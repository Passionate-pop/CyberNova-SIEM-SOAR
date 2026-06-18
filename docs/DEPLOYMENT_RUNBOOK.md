# ═════════════════════════════════════════════════════════════════════════════
# CyberNova — Deployment Runbook
# ═════════════════════════════════════════════════════════════════════════════
# Version: 2.0.0 | Last Updated: 2026-06-01
# Architecture: 10 Docker services, Docker secrets, multi-stage builds
# ═════════════════════════════════════════════════════════════════════════════

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Deployment](#deployment)
4. [Configuration Reference](#configuration-reference)
5. [Operations](#operations)
6. [Troubleshooting](#troubleshooting)
7. [Disaster Recovery](#disaster-recovery)
8. [Scaling](#scaling)

---

## Architecture Overview

```
                         ┌──────────────┐
                         │    Client     │
                         └──────┬───────┘
                                │
                    ┌───────────┴───────────┐
                    │     nginx (443/8888)   │  TLS termination + reverse proxy
                    │     Security headers   │  HSTS, CSP, X-Frame-Options
                    └────┬──────────────┬───┘
                         │              │
              ┌──────────┴──┐    ┌──────┴──────────┐
              │  frontend   │    │    backend       │  FastAPI + uvicorn
              │  (port 80)  │    │   (port 8000)    │  lifespan manages all services
              └─────────────┘    └──┬────┬────┬────┘
                                    │    │    │
                         ┌──────────┘    │    └──────────┐
                         ▼               ▼               ▼
                    ┌─────────┐   ┌──────────┐    ┌──────────┐
                    │ postgres │   │  redis   │    │pipeline- │
                    │ (5432)  │   │ (6379)   │    │ worker   │
                    └─────────┘   └──────────┘    └──────────┘

    Monitoring Stack:
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  prometheus   │  │ alertmanager │  │   grafana    │
    │  (9090)      │  │  (9093)      │  │   (3000)     │
    └──────────────┘  └──────────────┘  └──────────────┘

    Optional:
    ┌──────────────┐
    │   suricata   │  Network IDS (uses backend networking)
    └──────────────┘
```

### Services (10 total)

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| postgres | postgres:16-alpine | internal | Primary database |
| redis | redis:7-alpine | internal | Cache, dedup, event bus |
| backend | cybernova:latest | 8000 (internal) | FastAPI application |
| frontend | cybernova-frontend | 80 (internal) | React SPA |
| nginx | nginx:alpine | 443, 8888 | TLS + reverse proxy |
| pipeline-worker | cybernova:latest | — | Event processing workers |
| prometheus | prom/prometheus:v2.53.0 | 9090 | Metrics collection |
| alertmanager | prom/alertmanager:v0.27.0 | 9093 | Alert routing |
| grafana | grafana/grafana:11.1.0 | 3000 | Dashboards |
| suricata | custom | — | Network IDS |

### Docker Secrets

All passwords are managed via Docker secrets (mounted as files):

| Secret | File | Purpose |
|--------|------|---------|
| jwt_secret | secrets/jwt_secret.txt | JWT token signing |
| admin_password | secrets/admin_password.txt | Initial admin credentials |
| agent_password | secrets/agent_password.txt | Host agent authentication |
| postgres_password | secrets/postgres_password.txt | Database password |
| redis_password | secrets/redis_password.txt | Redis authentication |
| smtp_password | secrets/smtp_password.txt | Email notification auth |

---

## Prerequisites

```bash
# Install Docker (Ubuntu/Debian)
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker

# Verify
docker --version    # 24.0+
docker compose version  # v2.20+
```

---

## Deployment

### Quick Deploy (< 5 minutes)

```bash
# 1. Clone
git clone https://github.com/your-org/cybernova.git
cd cybernova

# 2. Generate secrets
mkdir -p secrets
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret.txt
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/secret_key.txt
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/postgres_password.txt
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/redis_password.txt
python3 -c "import secrets; print(secrets.token_urlsafe(20))" > secrets/admin_password.txt
python3 -c "import secrets; print(secrets.token_urlsafe(20))" > secrets/agent_password.txt
echo "smtp_placeholder" > secrets/smtp_password.txt
chmod 600 secrets/*.txt

# 3. Create .env (see Configuration Reference below)
# .env is the single source of configuration
# See "Configuration Reference" below for required variables
nano .env

# 4. Generate SSL certs (self-signed for dev)
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem -out nginx/ssl/cert.pem \
  -subj "/CN=cybernova"
chmod 600 nginx/ssl/*.pem

# 5. Launch
docker compose up -d --build

# 6. Verify
docker compose ps
curl -sf http://localhost:8888/health
```

### First-Time Setup

```bash
# Create admin user (only on first run)
curl -X POST http://localhost:8888/api/v1/setup/admin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@your-domain.com","password":"YOUR_ADMIN_PASSWORD"}'
```

---

## Configuration Reference

### Required .env Variables

```bash
# ── Core ──────────────────────────────────────────────────────
ENVIRONMENT=production          # production | staging | development
DEBUG=false                     # MUST be false in production
LOG_LEVEL=INFO

# ── Secrets (use Docker secrets in production) ────────────────
SECRET_KEY=<64-char hex>        # Secondary signing key (webhooks)
ADMIN_PASSWORD=<strong>         # Initial admin password
AGENT_PASSWORD=<strong>         # Host agent authentication
GRAFANA_PASSWORD=<strong>       # Grafana admin password

# ── Database ──────────────────────────────────────────────────
DATABASE_URL=postgresql+psycopg://cybernova@postgres:5432/cybernova

# ── CORS ──────────────────────────────────────────────────────
CORS_ORIGINS=https://your-domain.com

# ── SMTP (optional — for email alerts) ───────────────────────
SMTP_HOST=smtp.provider.com
SMTP_PORT=587
SMTP_USER=alerts@your-domain.com
SMTP_PASSWORD=<smtp-password>
FROM_EMAIL=alerts@your-domain.com
ALERT_EMAIL_TO=security@your-domain.com

# ── Performance Tuning ────────────────────────────────────────
DB_POOL_SIZE=25                 # PostgreSQL connection pool
DB_MAX_OVERFLOW=15              # Extra connections under load
DB_POOL_TIMEOUT=30              # Seconds to wait for connection
UVICORN_WORKERS=1               # API workers (1 = main.py manages lifecycle)
REDIS_MAXMEMORY=512mb           # Redis eviction threshold
```

### Docker Compose Entrypoint Behavior

The backend Dockerfile uses `ENTRYPOINT ["/app/docker-entrypoint.sh"]` with a default `CMD`:

1. **Resolves Docker secrets** — reads `*_FILE` env vars and exports the values
2. **Creates data directories** — `/app/data`, `/data/rag_store`, `/data/cold_storage`
3. **Execs the CMD** — passes through to uvicorn or custom command

When a `command:` override is provided (e.g., pipeline-worker), the entrypoint skips background services and directly execs the CMD.

---

## Operations

### Viewing Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend
docker compose logs -f pipeline-worker
docker compose logs -f postgres

# Last 100 lines
docker compose logs --tail=100 backend
```

### Restarting

```bash
# Single service
docker compose restart backend

# Full stack
docker compose down && docker compose up -d

# Rebuild after code changes
docker compose up -d --build backend
```

### Database Operations

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U cybernova cybernova

# Check connections
docker compose exec postgres psql -U cybernova -c "SELECT count(*) FROM pg_stat_activity;"

# Run migrations (via Alembic)
docker compose exec backend python -m alembic upgrade head
```

### Redis Operations

```bash
# Connect to Redis
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)"

# Check memory usage
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" INFO memory

# Check stream lag
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" XINFO GROUPS cybernova:raw_events
```

---

## Troubleshooting

### Backend Won't Start

```bash
# Check logs
docker compose logs backend

# Common causes:
# 1. Missing secrets — ensure secrets/*.txt files exist
# 2. DATABASE_URL wrong — verify postgres is healthy
# 3. SECRET_KEY default in production — must be set in .env

# Verify secrets are readable
docker compose exec backend ls -la /run/secrets/
```

### Pipeline Lagging

```bash
# Check worker logs
docker compose logs -f pipeline-worker

# Check queue depths
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" \
  XLEN cybernova:raw_events

# Restart worker
docker compose restart pipeline-worker
```

### SSL/TLS Errors

```bash
# Verify certificates
openssl x509 -in nginx/ssl/cert.pem -text -noout

# Test nginx config
docker compose exec nginx nginx -t

# Check nginx error log
docker compose logs nginx 2>&1 | grep -i ssl
```

### Container Health Issues

```bash
# Check all health statuses
docker inspect --format='{{.Name}}: {{.State.Health.Status}}' $(docker compose ps -q)

# Force rebuild
docker compose down
docker compose build --no-cache backend
docker compose up -d
```

---

## Disaster Recovery

### Backup

```bash
# Run backup script
./scripts/backup.sh

# Manual PostgreSQL backup
docker compose exec -T postgres pg_dump -U cybernova -Fc cybernova \
  > backups/cybernova_$(date +%Y%m%d_%H%M%S).dump

# Manual Redis backup
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)" BGSAVE
```

### Restore

```bash
# Stop application
docker compose stop backend pipeline-worker

# Restore PostgreSQL
docker compose exec -T postgres pg_restore -U cybernova -d cybernova \
  --clean --if-exists < backups/cybernova_YYYYMMDD_HHMMSS.dump

# Restart
docker compose start backend pipeline-worker
```

---

## Scaling

### Backend (Horizontal)

```yaml
# docker-compose.yml
services:
  backend:
    deploy:
      replicas: 3
```

### Worker (Parallel Processing)

```yaml
services:
  pipeline-worker:
    deploy:
      replicas: 2
```

### Resource Limits

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
```

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `docker compose up -d --build` | Full build & deploy |
| `docker compose down` | Stop everything |
| `docker compose ps` | Service status |
| `docker compose logs -f <svc>` | Live logs |
| `docker compose restart <svc>` | Restart one service |
| `docker compose exec <svc> sh` | Shell into container |
| `curl http://localhost:8888/health` | Health check |
| `curl http://localhost:8888/ready` | Readiness check |
| `./scripts/backup.sh` | Run backup |

---

*Last Updated: 2026-06-01 | Architecture: 10 services | Secrets: Docker secrets | TLS: nginx*
