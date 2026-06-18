# ═════════════════════════════════════════════════════════════════════════════
# CyberNova — Operations Runbooks
# ═════════════════════════════════════════════════════════════════════════════
# Version: 2.0.0 | Last Updated: 2026-06-01
# Architecture: 10 Docker services, Docker secrets, multi-stage builds
# ═════════════════════════════════════════════════════════════════════════════

## Table of Contents
1. [Deployment](#deployment)
2. [Monitoring](#monitoring)
3. [Troubleshooting](#troubleshooting)
4. [Disaster Recovery](#disaster-recovery)
5. [Scaling](#scaling)
6. [Security Operations](#security-operations)

---

## Deployment

### Docker Compose Deployment

```bash
# Build and start all services
docker compose up -d --build

# Check service status (all should show "healthy")
docker compose ps

# View logs for specific service
docker compose logs -f backend
docker compose logs -f pipeline-worker
docker compose logs -f postgres
docker compose logs -f redis
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENVIRONMENT` | Yes | production | `production`, `staging`, `development` |
| `DEBUG` | Yes | false | MUST be `false` in production |
| `SECRET_KEY` | Yes | — | Secondary signing key (min 32 chars) |
| `ADMIN_PASSWORD` | Yes | — | Initial admin account password |
| `AGENT_PASSWORD` | Yes | — | Host agent authentication password |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `CORS_ORIGINS` | Yes | localhost | Comma-separated allowed origins |
| `REDIS_PASSWORD` | Via secrets | — | Redis authentication password |
| `GRAFANA_PASSWORD` | Yes | — | Grafana admin password |
| `SMTP_HOST` | No | — | SMTP server for email alerts |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | No | — | AbuseIPDB API key |
| `OTX_API_KEY` | No | — | AlienVault OTX API key |
| `UVICORN_WORKERS` | No | 1 | API worker count (1 recommended for lifecycle) |
| `DB_POOL_SIZE` | No | 0 (auto) | PostgreSQL connection pool size |
| `DB_MAX_OVERFLOW` | No | 0 (auto) | Extra connections under load |
| `REDIS_MAXMEMORY` | No | 512mb | Redis memory limit with eviction |

### Docker Secrets

Passwords are managed via Docker secrets (mounted as files at `/run/secrets/`):

| Secret | File | Used By |
|--------|------|---------|
| jwt_secret | secrets/jwt_secret.txt | Backend, Pipeline-worker |
| admin_password | secrets/admin_password.txt | Backend |
| agent_password | secrets/agent_password.txt | Backend (entrypoint) |
| postgres_password | secrets/postgres_password.txt | Backend, Pipeline-worker, Postgres |
| redis_password | secrets/redis_password.txt | Backend, Pipeline-worker, Redis |
| smtp_password | secrets/smtp_password.txt | Backend, Alertmanager |

### Entrypoint Behavior

The backend Dockerfile uses `ENTRYPOINT ["/app/docker-entrypoint.sh"]`:

1. Resolves Docker secrets (`*_FILE` → env vars)
2. Creates data directories
3. If `RUN_ALL_SERVICES=false` (production), skips background services
4. Execs the CMD (default: uvicorn)

In production, `RUN_ALL_SERVICES=false` is set for both backend and pipeline-worker to prevent duplicate service startup (main.py lifespan handles everything for backend).

### Health Checks

```bash
# Backend API health
curl http://localhost:8888/health

# Readiness probe (K8s-compatible)
curl http://localhost:8888/ready

# Detailed health (requires auth)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/health/detailed

# System info
curl http://localhost:8888/
```

---

## Monitoring

### Key Metrics Endpoints

```bash
# Dashboard summary
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/dashboard/summary

# Pipeline status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/pipeline/status

# SLA metrics (P99 latency, availability)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/monitoring/sla

# Circuit breaker status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/monitoring/circuit-breakers

# WAF statistics
curl http://localhost:8888/api/v1/security/waf/stats

# Prometheus metrics
curl http://localhost:8888/metrics
```

### Monitoring Stack Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Prometheus | http://localhost:9090 | None (restrict in prod) |
| Alertmanager | http://localhost:9093 | None (restrict in prod) |
| Grafana | http://localhost:3000 | admin / GRAFANA_PASSWORD |

### Log Locations

```bash
# Application logs
docker compose logs -f backend

# Worker logs
docker compose logs -f pipeline-worker

# Database logs
docker compose logs -f postgres

# All services
docker compose logs -f

# Last N lines
docker compose logs --tail=500 backend
```

### Prometheus Alert Rules

Pre-configured alert rules (in `monitoring/alerts.yml`):

| Alert | Severity | Condition |
|-------|----------|-----------|
| BackendDown | critical | Backend unreachable > 1m |
| PipelineStopped | critical | Pipeline not running > 1m |
| HighProcessingLatency | warning | P99 latency > 2s for 5m |
| CriticalProcessingLatency | critical | P99 latency > 10s for 2m |
| NoEventsIngested | warning | No events for 15m |
| HighAlertRate | warning | > 100 alerts/s for 5m |
| StreamConsumerLag | warning | Lag > 1000 for 2m |
| DeadLetterQueueGrowing | critical | DLQ > 10 for 5m |
| HighMemoryUsage | warning | > 1GB for 10m |
| HighCPUUsage | warning | > 80% for 10m |

---

## Troubleshooting

### Issue: Backend Won't Start

**Symptoms:** Container exits immediately, health check fails

**Diagnosis:**
```bash
docker compose logs backend --tail=100
```

**Common causes:**
1. **Missing secrets** — `secrets/*.txt` files don't exist
2. **SECRET_KEY default** — SECRET_KEY still has default value in production
3. **PostgreSQL not ready** — Backend depends on postgres healthcheck
4. **AGENT_PASSWORD missing** — Required for host agent

**Resolution:**
```bash
# Verify secrets exist
ls -la secrets/

# Regenerate any missing secrets
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret.txt
chmod 600 secrets/*.txt

# Restart
docker compose up -d backend
```

### Issue: Pipeline Not Processing Events

**Symptoms:** Events ingested but no alerts created, queue depths increasing

**Diagnosis:**
```bash
# Check pipeline status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/pipeline/status

# Check stream lag
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" \
  XINFO GROUPS cybernova:raw_events

# Check worker logs
docker compose logs -f pipeline-worker --tail=100
```

**Resolution:**
```bash
# Restart pipeline worker
docker compose restart pipeline-worker

# Or restart full stack
docker compose down && docker compose up -d
```

### Issue: High Memory Usage

**Diagnosis:**
```bash
# Check container stats
docker stats --no-stream

# Check Redis memory
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" INFO memory

# Check PostgreSQL connections
docker compose exec postgres psql -U cybernova -c "SELECT count(*) FROM pg_stat_activity;"
```

**Resolution:**
```bash
# Increase Redis memory limit in docker-compose.yml
# REDIS_MAXMEMORY=1gb

# Restart Redis (data will be evicted per policy)
docker compose restart redis
```

### Issue: Duplicate Service Startup

**Symptoms:** Multiple syslog listeners, multiple file watchers, multiple workers

**Diagnosis:**
```bash
# Check environment variables
docker compose exec backend env | grep -E 'RUN_ALL|START_'
# All should show "false" in production
```

**Resolution:**
Ensure `docker-compose.yml` has for backend:
```yaml
RUN_ALL_SERVICES: "false"
START_LOCAL_AGENT: "false"
START_WORKER_PROCESSOR: "false"
START_SYSLOG_LISTENER: "false"
START_FILE_WATCHER: "false"
```

### Issue: External API Failures (VirusTotal, etc.)

**Diagnosis:**
```bash
# Check circuit breakers
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/monitoring/circuit-breakers
```

**Resolution:** Circuit breakers auto-recover after timeout (60s default). Events continue processing with fallback values. Monitor until "closed" state.

### Issue: TLS/SSL Errors

```bash
# Verify certificate validity
openssl x509 -in nginx/ssl/cert.pem -noout -dates -subject

# Test nginx config
docker compose exec nginx nginx -t

# Check nginx error log
docker compose logs nginx 2>&1 | grep -i ssl
```

---

## Disaster Recovery

### Backup

```bash
# Automated backup (runs daily via cron)
./scripts/backup.sh

# Manual PostgreSQL backup
docker compose exec -T postgres pg_dump -U cybernova -Fc cybernova \
  > backups/cybernova_$(date +%Y%m%d_%H%M%S).dump

# Manual Redis backup
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" BGSAVE
sleep 2
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" SAVE

# List backups
ls -la backups/
```

### Restore

```bash
# Stop application services
docker compose stop backend pipeline-worker

# Restore PostgreSQL
docker compose exec -T postgres pg_restore -U cybernova -d cybernova \
  --clean --if-exists < backups/cybernova_YYYYMMDD_HHMMSS.dump

# Restart services
docker compose start backend pipeline-worker

# Verify
curl -sf http://localhost:8888/health
```

### Full Recovery Procedure

```bash
# 1. Stop everything
docker compose down

# 2. Restore secrets (from secure backup)
# cp /secure-backup/secrets/*.txt secrets/

# 3. Restore database
docker compose up -d postgres
sleep 10
docker compose exec -T postgres pg_restore -U cybernova -d cybernova \
  --clean < backups/cybernova_YYYYMMDD_HHMMSS.dump

# 4. Start all services
docker compose up -d

# 5. Verify all services
docker compose ps
curl -sf http://localhost:8888/health
```

---

## Scaling

### Horizontal Scaling

```yaml
# docker-compose.yml
services:
  backend:
    deploy:
      replicas: 3
  pipeline-worker:
    deploy:
      replicas: 2
```

### Resource Tuning

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 2G
        reservations:
          cpus: "0.5"
          memory: 512M
  postgres:
    command: >
      -c max_connections=200
      -c shared_buffers=512MB
      -c effective_cache_size=1536MB
```

### Database Connection Pooling

```bash
# Monitor pool usage
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/ready | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('DB pool:', json.dumps(d.get('pool_stats', {}), indent=2))
"
```

---

## Security Operations

### Audit Logs

```bash
# View all audit logs
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/audit/logs

# Security events only
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/audit/logs/security

# Audit statistics
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/audit/stats
```

### JWT Secret Rotation

```bash
# Generate new secret
NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Update secrets file
echo "$NEW_SECRET" > secrets/jwt_secret.txt
chmod 600 secrets/jwt_secret.txt

# Restart services (existing tokens will be invalidated)
docker compose restart backend pipeline-worker
```

### Agent Authentication

```bash
# Rotate agent password
NEW_AGENT_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
echo "$NEW_AGENT_PASS" > secrets/agent_password.txt
chmod 600 secrets/agent_password.txt

# Restart to pick up new secret
docker compose restart backend
```

### Firewall Management

```bash
# Check UFW status
sudo ufw status verbose

# Block suspicious IP
sudo ufw deny from 1.2.3.4

# Allow new port
sudo ufw allow 8443/tcp
```

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `docker compose up -d --build` | Full build & deploy |
| `docker compose down` | Stop all services |
| `docker compose ps` | Service status & health |
| `docker compose logs -f <svc>` | Live logs |
| `docker compose restart <svc>` | Restart one service |
| `docker compose exec <svc> sh` | Shell into container |
| `curl http://localhost:8888/health` | Health check |
| `curl http://localhost:8888/ready` | Readiness check |
| `./scripts/backup.sh` | Run backup |
| `./scripts/restore.sh <file>` | Restore from backup |

---

*Last Updated: 2026-06-01 | Architecture: 10 services | Secrets: Docker secrets | TLS: nginx*
