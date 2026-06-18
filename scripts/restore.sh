#!/bin/bash
# CyberNova — Database Restore Script
# Usage: ./scripts/restore.sh <backup_file> [--redis]
# 
# Examples:
#   ./scripts/restore.sh /backups/cybernova_pg_20240115_020000.dump
#   ./scripts/restore.sh /backups/cybernova_pg_20240115_020000.dump --redis

set -e

BACKUP_FILE="$1"
REDIS_ONLY=false

if [ "$2" == "--redis" ]; then
    REDIS_ONLY=true
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_success() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}✗ $1${NC}"
}

log_warning() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}⚠ $1${NC}"
}

# Validate input
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file> [--redis]"
    echo ""
    echo "Options:"
    echo "  --redis     Restore Redis only"
    echo ""
    echo "Available backups:"
    ls -la /backups/cybernova_pg_*.dump /backups/cybernova_pg_*.sql.gz 2>/dev/null || echo "No backups found in /backups/"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    log_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

log "=========================================="
log "CyberNova Restore Started"
log "=========================================="

HOST=${POSTGRES_HOST:-postgres}
USER=${POSTGRES_USER:-cybernova}
DB_NAME=${POSTGRES_DB:-cybernova}

if [ "$REDIS_ONLY" == "false" ]; then
    # PostgreSQL Restore
    log "Restoring PostgreSQL from: $BACKUP_FILE"
    
    log_warning "Dropping existing database..."
    PGPASSWORD=${POSTGRES_PASSWORD:-} dropdb -h "$HOST" -U "$USER" "$DB_NAME" 2>/dev/null || true
    
    log "Creating database..."
    PGPASSWORD=${POSTGRES_PASSWORD:-} createdb -h "$HOST" -U "$USER" "$DB_NAME"
    
    if [[ "$BACKUP_FILE" == *.dump ]]; then
        log "Restoring from custom format dump..."
        PGPASSWORD=${POSTGRES_PASSWORD:-} pg_restore -h "$HOST" -U "$USER" -d "$DB_NAME" --clean --if-exists "$BACKUP_FILE"
    elif [[ "$BACKUP_FILE" == *.sql.gz ]]; then
        log "Restoring from SQL dump..."
        gunzip -c "$BACKUP_FILE" | PGPASSWORD=${POSTGRES_PASSWORD:-} psql -h "$HOST" -U "$USER" -d "$DB_NAME"
    else
        log "Restoring from plain SQL dump..."
        PGPASSWORD=${POSTGRES_PASSWORD:-} psql -h "$HOST" -U "$USER" -d "$DB_NAME" -f "$BACKUP_FILE"
    fi
    
    log_success "PostgreSQL restore completed"
fi

# Redis Restore
if [ -f "${BACKUP_FILE%.pg_*}.redis_"*.rdb ] || [ "$REDIS_ONLY" == "true" ]; then
    log "Restoring Redis..."
    
    REDIS_HOST=${REDIS_HOST:-redis}
    REDIS_PORT=${REDIS_PORT:-6379}
    REDIS_PASS=${REDIS_PASSWORD:-}
    
    REDIS_BACKUP=$(ls "${BACKUP_FILE%.pg_*}".redis_*.rdb 2>/dev/null | head -1)
    
    if [ -f "$REDIS_BACKUP" ]; then
        if [ -n "$REDIS_PASS" ]; then
            redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASS" SHUTDOWN NOSAVE 2>/dev/null || true
        else
            redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SHUTDOWN NOSAVE 2>/dev/null || true
        fi
        
        cp "$REDIS_BACKUP" /data/dump.rdb
        mkdir -p /data
        
        if command -v redis-server &> /dev/null; then
            redis-server --daemonize yes --dir /data --dbfilename dump.rdb
        fi
        
        log_success "Redis restore completed"
    fi
fi

log "=========================================="
log_success "Restore Completed Successfully"
log "=========================================="
log ""
log "Note: You may need to restart the CyberNova application"
log "to pick up the restored data."
