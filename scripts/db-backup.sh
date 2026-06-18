#!/bin/bash
# CyberNova — Automated PostgreSQL Backup to S3/GCS
# Usage: ./scripts/db-backup.sh [--s3-only|--gcs-only]
#
# Environment variables:
#   PGHOST / PGUSER / PGPASSWORD / PGDATABASE / PGPORT
#   BACKUP_S3_BUCKET          e.g. "cybernova-backups"
#   BACKUP_S3_REGION          default: us-east-1
#   BACKUP_GCS_BUCKET         e.g. "cybernova-backups-gcs"
#   BACKUP_RETENTION_DAYS     default: 30
#   BACKUP_LOCAL_DIR          default: /tmp/cybernova-backups
#
# Exit codes:
#   0  — Success (all configured destinations)
#   1  — pg_dump failed
#   2  — S3 upload failed
#   3  — GCS upload failed

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────

BACKUP_LOCAL_DIR="${BACKUP_LOCAL_DIR:-/tmp/cybernova-backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
S3_REGION="${BACKUP_S3_REGION:-us-east-1}"
GCS_BUCKET="${BACKUP_GCS_BUCKET:-}"
PGHOST="${PGHOST:-postgres}"
PGUSER="${PGUSER:-cybernova}"
PGDATABASE="${PGDATABASE:-cybernova}"
PGPORT="${PGPORT:-5432}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_FILE="cybernova_pg_${TIMESTAMP}.dump"
BACKUP_PATH="${BACKUP_LOCAL_DIR}/${BACKUP_FILE}"
LOG_FILE="${BACKUP_LOCAL_DIR}/db-backup.log"

mkdir -p "${BACKUP_LOCAL_DIR}"

log()  { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "${LOG_FILE}"; }
err()  { log "ERROR: $*"; }
suc()  { log "SUCCESS: $*"; }
warn() { log "WARNING: $*"; }

cleanup() {
    if [ -f "${BACKUP_PATH}" ]; then
        rm -f "${BACKUP_PATH}"
        log "Cleaned up local backup: ${BACKUP_PATH}"
    fi
}
trap cleanup EXIT

# ── pg_dump ─────────────────────────────────────────────────────────────────

log "Starting PostgreSQL backup to ${BACKUP_PATH}"

PGPASSWORD="${PGPASSWORD:-}" pg_dump \
    -h "${PGHOST}" \
    -p "${PGPORT}" \
    -U "${PGUSER}" \
    -d "${PGDATABASE}" \
    -Fc \
    -f "${BACKUP_PATH}" \
    -v 2>>"${LOG_FILE}"

if [ ! -f "${BACKUP_PATH}" ]; then
    err "pg_dump did not produce a backup file"
    exit 1
fi

BACKUP_SIZE=$(stat -c%s "${BACKUP_PATH}" 2>/dev/null || stat -f%z "${BACKUP_PATH}" 2>/dev/null)
suc "pg_dump complete: ${BACKUP_FILE} ($(numfmt --to=iec "${BACKUP_SIZE}" 2>/dev/null || echo "${BACKUP_SIZE} bytes"))"

# ── Retention helper ────────────────────────────────────────────────────────

run_retention() {
    local bucket="$1"  # s3://bucket or gs://bucket
    local prefix="$2"  # optional subfolder
    local days="$3"

    if [[ "${bucket}" == s3://* ]]; then
        log "Cleaning S3 backups older than ${days}d in ${bucket}/${prefix}"
        aws s3 ls "${bucket}/${prefix}" --recursive 2>/dev/null \
            | while read -r date_str time_str size path; do
                if [ -n "${date_str}" ] && [ -n "${path}" ]; then
                    obj_date="${date_str}T${time_str}Z"
                    obj_ts=$(date -d "${obj_date}" +%s 2>/dev/null || echo 0)
                    cutoff_ts=$(date -d "-${days} days" +%s)
                    if [ "${obj_ts}" -gt 0 ] && [ "${obj_ts}" -lt "${cutoff_ts}" ]; then
                        aws s3 rm "${bucket}/${path}" >>"${LOG_FILE}" 2>&1
                        log "Deleted old S3 backup: ${path}"
                    fi
                fi
            done
    elif [[ "${bucket}" == gs://* ]]; then
        log "Cleaning GCS backups older than ${days}d in ${bucket}/${prefix}"
        gsutil ls "${bucket}/${prefix}**" 2>/dev/null \
            | while read -r path; do
                if [ -n "${path}" ]; then
                    created=$(gsutil stat "${path}" 2>/dev/null \
                        | grep -i "Creation time" \
                        | sed 's/.*Creation time: *//;s/\(....\)-\(..\)-\(..\)T.*/\1\2\3/')
                    if [ -n "${created}" ] && [ "${created}" -lt "$(date -d "-${days} days" +%Y%m%d)" ]; then
                        gsutil rm "${path}" >>"${LOG_FILE}" 2>&1
                        log "Deleted old GCS backup: ${path}"
                    fi
                fi
            done
    fi
}

# ── S3 upload ────────────────────────────────────────────────────────────────

S3_OK=true
if [ -n "${S3_BUCKET}" ]; then
    S3_PATH="s3://${S3_BUCKET}/postgres/${BACKUP_FILE}"
    log "Uploading to S3: ${S3_PATH}"

    if aws s3 cp "${BACKUP_PATH}" "${S3_PATH}" \
        --region "${S3_REGION}" \
        >>"${LOG_FILE}" 2>&1; then
        suc "S3 upload complete: ${S3_PATH}"
    else
        err "S3 upload failed"
        S3_OK=false
    fi

    run_retention "s3://${S3_BUCKET}" "postgres/" "${RETENTION_DAYS}"
else
    warn "BACKUP_S3_BUCKET not set — skipping S3 upload"
fi

# ── GCS upload ───────────────────────────────────────────────────────────────

GCS_OK=true
if [ -n "${GCS_BUCKET}" ]; then
    GCS_PATH="gs://${GCS_BUCKET}/postgres/${BACKUP_FILE}"
    log "Uploading to GCS: ${GCS_PATH}"

    if gsutil cp "${BACKUP_PATH}" "${GCS_PATH}" >>"${LOG_FILE}" 2>&1; then
        suc "GCS upload complete: ${GCS_PATH}"
    else
        err "GCS upload failed"
        GCS_OK=false
    fi

    run_retention "gs://${GCS_BUCKET}" "postgres/" "${RETENTION_DAYS}"
else
    warn "BACKUP_GCS_BUCKET not set — skipping GCS upload"
fi

# ── Result ──────────────────────────────────────────────────────────────────

if [ "${S3_OK}" = false ]; then
    exit 2
elif [ "${GCS_OK}" = false ]; then
    exit 3
fi

suc "Backup cycle complete (retention: ${RETENTION_DAYS}d)"
exit 0
