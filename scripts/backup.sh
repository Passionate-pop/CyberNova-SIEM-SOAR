#!/bin/bash
# CyberNova — Backup Script
# Runs daily via cron or Docker healthcheck
# Backups PostgreSQL and Redis AOF to persistent volume

set -e

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}
HOST=${POSTGRES_HOST:-postgres}
USER=${POSTGRES_USER:-cybernova}
LOG_FILE="/var/log/cybernova_backup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$(date)] $1"
}

log_success() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}✓ $1${NC}" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$(date)] ✓ $1"
}

log_warning() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}⚠ $1${NC}" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$(date)] ⚠ $1"
}

mkdir -p "${BACKUP_DIR}"
mkdir -p "$(dirname "$LOG_FILE" 2>/dev/null || echo /tmp)"

log "=========================================="
log "CyberNova Backup Started"
log "=========================================="

# PostgreSQL backup (using custom format for point-in-time recovery)
log "Backing up PostgreSQL..."
PGPASSWORD=$(cat /run/secrets/postgres_password 2>/dev/null || echo "${POSTGRES_PASSWORD:-}") \
pg_dump -h "${HOST}" -U "${USER}" -d cybernova -Fc \
  > "${BACKUP_DIR}/cybernova_pg_${DATE}.dump" 2>/dev/null || \
pg_dump -h "${HOST}" -U "${USER}" -d cybernova \
  | gzip > "${BACKUP_DIR}/cybernova_pg_${DATE}.sql.gz"

if [ -f "${BACKUP_DIR}/cybernova_pg_${DATE}.dump" ]; then
    SIZE=$(du -h "${BACKUP_DIR}/cybernova_pg_${DATE}.dump" | cut -f1)
    log_success "PostgreSQL backup: cybernova_pg_${DATE}.dump ($SIZE)"
elif [ -f "${BACKUP_DIR}/cybernova_pg_${DATE}.sql.gz" ]; then
    SIZE=$(du -h "${BACKUP_DIR}/cybernova_pg_${DATE}.sql.gz" | cut -f1)
    log_success "PostgreSQL backup: cybernova_pg_${DATE}.sql.gz ($SIZE)"
fi

# Redis RDB backup
log "Backing up Redis..."
REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_PASS=${REDIS_PASSWORD:-}

if [ -f /data/dump.rdb ]; then
    cp /data/dump.rdb "${BACKUP_DIR}/cybernova_redis_${DATE}.rdb"
    SIZE=$(du -h "${BACKUP_DIR}/cybernova_redis_${DATE}.rdb" | cut -f1)
    log_success "Redis backup: cybernova_redis_${DATE}.rdb ($SIZE)"
elif command -v redis-cli &> /dev/null; then
    if [ -n "$REDIS_PASS" ]; then
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASS" BGSAVE 2>/dev/null || true
    else
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" BGSAVE 2>/dev/null || true
    fi
    sleep 2
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SAVE 2>/dev/null || true
fi

# Config backup
if [ -f "/app/.env" ]; then
    cp /app/.env "${BACKUP_DIR}/cybernova_config_${DATE}.env"
    log_success "Config backup: cybernova_config_${DATE}.env"
fi

# Cleanup old backups
log "Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "cybernova_*" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

# Count remaining backups
BACKUP_COUNT=$(find "${BACKUP_DIR}" -name "cybernova_*" -type f | wc -l)
log "Total backups: ${BACKUP_COUNT}"

# Generate manifest
cat > "${BACKUP_DIR}/manifest.txt" << EOF
CyberNova Backup Manifest
========================
Generated: $(date)
Backup Name: ${DATE}
Total Backups: ${BACKUP_COUNT}
Retention Days: ${RETENTION_DAYS}
EOF

log "=========================================="
log_success "Backup Completed Successfully"
log "=========================================="
