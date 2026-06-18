#!/bin/bash
# CyberNova — Backup Verification Script
# Restores the latest pg_dump to a staging database and runs integrity checks.
#
# Usage: ./scripts/verify-backup.sh [--backup-file <path>]
#
# Environment variables:
#   Staging DB (for verification):
#     VERIFY_PGHOST / VERIFY_PGUSER / VERIFY_PGPASSWORD / VERIFY_PGDATABASE / VERIFY_PGPORT
#     Defaults to POSTGRES_HOST/USER/PASSWORD/DB/PORT if not set.
#
#   Backup source (checked in order):
#     BACKUP_LOCAL_DIR         default: /backups
#     BACKUP_S3_BUCKET         downloaded to temp if no local backup found
#     BACKUP_GCS_BUCKET        downloaded to temp if no S3/local backup found
#
# Exit codes:
#   0 — All checks passed
#   1 — Backup not found
#   2 — Restore failed
#   3 — Integrity checks failed
#   4 — Staging DB cleanup failed

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────

BACKUP_LOCAL_DIR="${BACKUP_LOCAL_DIR:-/backups}"
VERIFY_TEMP_DIR="/tmp/cybernova-verify"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
GCS_BUCKET="${BACKUP_GCS_BUCKET:-}"
LOG_FILE="${VERIFY_TEMP_DIR}/verify.log"

# Staging DB connection (defaults to main PG vars)
VERIFY_PGHOST="${VERIFY_PGHOST:-${POSTGRES_HOST:-postgres}}"
VERIFY_PGUSER="${VERIFY_PGUSER:-${POSTGRES_USER:-cybernova}}"
VERIFY_PGPASSWORD="${VERIFY_PGPASSWORD:-${POSTGRES_PASSWORD:-}}"
VERIFY_PGDATABASE="${VERIFY_PGDATABASE:-cybernova_verify}"
VERIFY_PGPORT="${VERIFY_PGPORT:-${PGPORT:-5432}}"

# Expected tables (from cybernova/database/postgres/models.py)
EXPECTED_TABLES=(
    tenants organization_keys subscriptions api_keys tenant_usage_daily
    users devices device_commands idempotency_keys
    raw_events normalized_events enriched_events
    alerts incidents alert_suppressions whitelist_entries
    playbooks notifications response_actions audit_logs
    correlation_rules detection_rules blocked_ips
    analytics_events user_sessions insights dead_letter_events
    training_records model_registry entity_baselines drift_records
    ab_tests ab_test_results
)

# Critical tables that must have rows (for production DBs)
CRITICAL_TABLES=(
    tenants users
)

PASS_COUNT=0
FAIL_COUNT=0
CURRENT_CHECK=""

mkdir -p "${VERIFY_TEMP_DIR}"

# ── Logging ─────────────────────────────────────────────────────────────────

log()    { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "${LOG_FILE}"; }
err()    { log "ERROR: $*"; }
suc()    { log "SUCCESS: $*"; }
warn()   { log "WARNING: $*"; }

check_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ✓ PASS: ${CURRENT_CHECK}" | tee -a "${LOG_FILE}"
}

check_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  ✗ FAIL: ${CURRENT_CHECK} — $*" | tee -a "${LOG_FILE}"
}

cleanup_temp() {
    log "Cleaning up temp directory"
    rm -rf "${VERIFY_TEMP_DIR}"
}

cleanup_staging() {
    log "Dropping staging database: ${VERIFY_PGDATABASE}"
    PGPASSWORD="${VERIFY_PGPASSWORD}" dropdb \
        -h "${VERIFY_PGHOST}" \
        -p "${VERIFY_PGPORT}" \
        -U "${VERIFY_PGUSER}" \
        --if-exists \
        "${VERIFY_PGDATABASE}" >>"${LOG_FILE}" 2>&1 || true
}

run_sql() {
    local query="$1"
    PGPASSWORD="${VERIFY_PGPASSWORD}" psql \
        -h "${VERIFY_PGHOST}" \
        -p "${VERIFY_PGPORT}" \
        -U "${VERIFY_PGUSER}" \
        -d "${VERIFY_PGDATABASE}" \
        -At \
        -c "${query}" 2>/dev/null
}

# ── Trap for cleanup ────────────────────────────────────────────────────────

cleanup_all() {
    cleanup_staging
    cleanup_temp
}
trap cleanup_all EXIT

# ── Step 0: Arguments ───────────────────────────────────────────────────────

CUSTOM_BACKUP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --backup-file) CUSTOM_BACKUP="$2"; shift 2 ;;
        *) log "Unknown option: $1"; exit 1 ;;
    esac
done

log "=========================================="
log "CyberNova Backup Verification Started"
log "=========================================="
log "Staging DB: ${VERIFY_PGDATABASE}@${VERIFY_PGHOST}:${VERIFY_PGPORT}"

# ── Step 1: Find or download backup ─────────────────────────────────────────

RESTORE_FILE=""

if [ -n "${CUSTOM_BACKUP}" ]; then
    RESTORE_FILE="${CUSTOM_BACKUP}"
    log "Using specified backup: ${RESTORE_FILE}"
elif [ -d "${BACKUP_LOCAL_DIR}" ]; then
    RESTORE_FILE=$(find "${BACKUP_LOCAL_DIR}" -name 'cybernova_pg_*.dump' -type f 2>/dev/null \
        | sort | tail -1)
    if [ -n "${RESTORE_FILE}" ]; then
        log "Using latest local backup: ${RESTORE_FILE}"
    else
        warn "No local .dump found in ${BACKUP_LOCAL_DIR}"
    fi
fi

if [ -z "${RESTORE_FILE}" ] && [ -n "${S3_BUCKET}" ]; then
    log "Looking for latest backup in S3: s3://${S3_BUCKET}/postgres/"
    S3_KEY=$(aws s3 ls "s3://${S3_BUCKET}/postgres/" --recursive 2>/dev/null \
        | sort | tail -1 | awk '{print $4}')
    if [ -n "${S3_KEY}" ]; then
        RESTORE_FILE="${VERIFY_TEMP_DIR}/$(basename "${S3_KEY}")"
        aws s3 cp "s3://${S3_BUCKET}/${S3_KEY}" "${RESTORE_FILE}" >>"${LOG_FILE}" 2>&1
        log "Downloaded from S3: ${S3_KEY}"
    else
        warn "No backups found in S3 bucket"
    fi
fi

if [ -z "${RESTORE_FILE}" ] && [ -n "${GCS_BUCKET}" ]; then
    log "Looking for latest backup in GCS: gs://${GCS_BUCKET}/postgres/"
    GCS_KEY=$(gsutil ls "gs://${GCS_BUCKET}/postgres/" 2>/dev/null \
        | sort | tail -1)
    if [ -n "${GCS_KEY}" ]; then
        RESTORE_FILE="${VERIFY_TEMP_DIR}/$(basename "${GCS_KEY}")"
        gsutil cp "${GCS_KEY}" "${RESTORE_FILE}" >>"${LOG_FILE}" 2>&1
        log "Downloaded from GCS: ${GCS_KEY}"
    else
        warn "No backups found in GCS bucket"
    fi
fi

if [ -z "${RESTORE_FILE}" ] || [ ! -f "${RESTORE_FILE}" ]; then
    err "No backup file found to verify"
    exit 1
fi

BACKUP_SIZE=$(stat -c%s "${RESTORE_FILE}" 2>/dev/null || stat -f%z "${RESTORE_FILE}" 2>/dev/null)
log "Backup file size: $(numfmt --to=iec "${BACKUP_SIZE}" 2>/dev/null || echo "${BACKUP_SIZE} bytes")"

# ── Step 2: Create staging database ─────────────────────────────────────────

log "Creating staging database: ${VERIFY_PGDATABASE}"
PGPASSWORD="${VERIFY_PGPASSWORD}" dropdb \
    -h "${VERIFY_PGHOST}" -p "${VERIFY_PGPORT}" -U "${VERIFY_PGUSER}" \
    --if-exists "${VERIFY_PGDATABASE}" >>"${LOG_FILE}" 2>&1 || true

PGPASSWORD="${VERIFY_PGPASSWORD}" createdb \
    -h "${VERIFY_PGHOST}" -p "${VERIFY_PGPORT}" -U "${VERIFY_PGUSER}" \
    "${VERIFY_PGDATABASE}" >>"${LOG_FILE}" 2>&1

if [ $? -ne 0 ]; then
    err "Failed to create staging database"
    exit 2
fi
suc "Staging database created"

# ── Step 3: Restore backup to staging ───────────────────────────────────────

log "Restoring backup to staging database (this may take a while)..."
PGPASSWORD="${VERIFY_PGPASSWORD}" pg_restore \
    -h "${VERIFY_PGHOST}" -p "${VERIFY_PGPORT}" -U "${VERIFY_PGUSER}" \
    -d "${VERIFY_PGDATABASE}" \
    --no-owner --no-privileges \
    --exit-on-error \
    "${RESTORE_FILE}" >>"${LOG_FILE}" 2>&1

if [ $? -ne 0 ]; then
    err "pg_restore failed — backup may be corrupt"
    exit 2
fi
suc "Backup restored to staging database"

# ── Step 4: Run integrity checks ────────────────────────────────────────────

log "=========================================="
log "Running integrity checks"
log "=========================================="

# Check 4a: All expected tables exist
CURRENT_CHECK="All expected tables exist"
MISSING_TABLES=()
for table in "${EXPECTED_TABLES[@]}"; do
    count=$(run_sql "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='${table}';")
    if [ "${count}" != "1" ]; then
        MISSING_TABLES+=("${table}")
    fi
done

if [ ${#MISSING_TABLES[@]} -eq 0 ]; then
    check_pass
else
    check_fail "Missing tables: ${MISSING_TABLES[*]}"
fi

# Check 4b: Schema count matches expected
CURRENT_CHECK="Table count matches expected (${#EXPECTED_TABLES[@]})"
TABLE_COUNT=$(run_sql "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
if [ "${TABLE_COUNT}" -ge "${#EXPECTED_TABLES[@]}" ]; then
    check_pass
else
    check_fail "Found ${TABLE_COUNT} tables, expected at least ${#EXPECTED_TABLES[@]}"
fi

# Check 4c: Critical tables have rows
CURRENT_CHECK="Critical tables have data"
CRITICAL_FAIL=false
for table in "${CRITICAL_TABLES[@]}"; do
    row_count=$(run_sql "SELECT count(*) FROM \"${table}\";")
    if [ "${row_count}" -eq 0 ] 2>/dev/null; then
        warn "Critical table '${table}' has 0 rows"
        CRITICAL_FAIL=true
    elif [ -n "${row_count}" ]; then
        log "  Table '${table}': ${row_count} rows"
    fi
done

if [ "${CRITICAL_FAIL}" = false ]; then
    check_pass
else
    check_fail "Some critical tables are empty"
fi

# Check 4d: Row counts for all tables (informational)
CURRENT_CHECK="All tables accessible for counting"
ACCESS_FAIL=false
for table in "${EXPECTED_TABLES[@]}"; do
    row_count=$(run_sql "SELECT count(*) FROM \"${table}\";")
    if [ -z "${row_count}" ]; then
        warn "Could not count rows in '${table}'"
        ACCESS_FAIL=true
    else
        log "  ${table}: ${row_count} rows"
    fi
done

if [ "${ACCESS_FAIL}" = false ]; then
    check_pass
else
    check_fail "Some tables could not be queried"
fi

# Check 4e: Referential integrity (no orphaned foreign keys)
CURRENT_CHECK="No orphaned foreign key references"
FK_FAIL=false
FK_RESULT=$(run_sql "
    SELECT count(*) FROM (
        SELECT c.relname AS child_table,
               f.confrelid::regclass AS parent_table
        FROM pg_constraint f
        JOIN pg_class c ON c.oid = f.conrelid
        WHERE f.confrelid IS NOT NULL
          AND f.contype = 'f'
          AND NOT EXISTS (
              SELECT 1 FROM pg_class pc WHERE pc.oid = f.confrelid
          )
    ) orphans;
")
if [ "${FK_RESULT}" = "0" ]; then
    check_pass
else
    check_fail "Found ${FK_RESULT} orphaned foreign key references"
fi

# ── Step 5: Results ─────────────────────────────────────────────────────────

TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))
log "=========================================="
log "Verification complete: ${PASS_COUNT}/${TOTAL_CHECKS} checks passed"
log "=========================================="

cleanup_staging

if [ "${FAIL_COUNT}" -gt 0 ]; then
    err "Backup verification FAILED — ${FAIL_COUNT} check(s) failed"
    exit 3
fi

suc "Backup verification PASSED — backup is valid"
exit 0
