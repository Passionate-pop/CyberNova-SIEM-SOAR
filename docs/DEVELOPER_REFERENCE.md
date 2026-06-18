# ═════════════════════════════════════════════════════════════════════════════
# CyberNova — Developer Reference
# ═════════════════════════════════════════════════════════════════════════════
# Version: 2.0.0 | Last Updated: 2026-06-01
# Architecture: 10 Docker services, Docker secrets, multi-stage ENTRYPOINT
# ═════════════════════════════════════════════════════════════════════════════

## Quick Start

### Local Development

```bash
# 1. Start infrastructure
docker compose up -d postgres redis

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start backend (with hot reload)
cd cybernova && uvicorn main:app --reload --port 8000

# 4. Start host agent (optional)
python host_agent.py --backend http://localhost:8000
```

### Docker Development

```bash
# Full stack
docker compose up -d --build

# Backend only (with source mounted for live reload)
docker compose up -d postgres redis
docker compose run --rm backend python -m uvicorn cybernova.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Default Credentials

| Role | Username | Password | Permissions |
|------|----------|----------|-------------|
| Admin | admin | (from secrets/admin_password.txt) | Full access: read, write, delete, configure, SOAR |
| Analyst | analyst | analyst | read, write, SOAR |
| Viewer | viewer | viewer | read only |

**⚠️ Production:** Change all default passwords before deployment. Use `secrets/*.txt` files.

---

## Configuration

### Settings Architecture

CyberNova uses **Pydantic Settings** with a layered configuration system:

```
1. .env file (lowest priority)
2. Environment variables (override .env)
3. Docker secrets via *_FILE env vars (highest priority)
```

**Secret resolution priority** (in `settings.py`):
1. Direct env var (e.g., `JWT_SECRET=abc`)
2. File-based secret (e.g., `JWT_SECRET_FILE=/run/secrets/jwt_secret`)
3. Default value from Settings class

### Key Environment Variables

```bash
# ── Core ──────────────────────────────────────────────────────
ENVIRONMENT=production          # production | staging | development
DEBUG=false                     # MUST be false in production
LOG_LEVEL=INFO

# ── Security ─────────────────────────────────────────────────
SECRET_KEY=<64-char-hex>        # Secondary signing key (webhooks, tokens)
JWT_SECRET=<64-char-hex>        # Primary JWT signing key (via secrets)
ADMIN_PASSWORD=<strong>         # Initial admin password
AGENT_PASSWORD=<strong>         # Host agent authentication

# ── Database ─────────────────────────────────────────────────
DATABASE_URL=postgresql+psycopg://cybernova@postgres:5432/cybernova
DB_POOL_SIZE=25                 # Connection pool size (0 = auto)
DB_MAX_OVERFLOW=15              # Extra connections under load
DB_POOL_TIMEOUT=30              # Seconds to wait for connection

# ── Redis ────────────────────────────────────────────────────
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_MAXMEMORY=512mb
REDIS_MAXMEMORY_POLICY=allkeys-lru

# ── CORS ─────────────────────────────────────────────────────
CORS_ORIGINS=https://your-domain.com,https://www.your-domain.com

# ── SOAR ─────────────────────────────────────────────────────
SOAR_ENABLED=true
SOAR_AUTO_APPROVE_TIMEOUT=15    # Seconds before auto-block

# ── Monitoring ───────────────────────────────────────────────
OTEL_ENDPOINT=http://localhost:4318/v1/traces
OTEL_ENABLED=true

# ── Workers ──────────────────────────────────────────────────
UVICORN_WORKERS=1               # API workers (1 = main.py lifecycle)
RUN_ALL_SERVICES=false          # false in production (per-service control)
START_LOCAL_AGENT=false         # backend: managed by main.py lifespan
START_WORKER_PROCESSOR=false    # backend: pipeline-worker handles this
START_SYSLOG_LISTENER=false     # backend: managed by main.py lifespan
START_FILE_WATCHER=false        # backend: managed by main.py lifespan
```

### Docker Secrets

In production, passwords are managed via Docker secrets:

| Secret | File | Python Setting | Bash Variable |
|--------|------|---------------|---------------|
| jwt_secret | secrets/jwt_secret.txt | `secret_key` | `JWT_SECRET` |
| admin_password | secrets/admin_password.txt | `admin_password` | `ADMIN_PASSWORD` |
| agent_password | secrets/agent_password.txt | `agent_password` | `AGENT_PASSWORD` |
| postgres_password | secrets/postgres_password.txt | `postgres_password` | `POSTGRES_PASSWORD` |
| redis_password | secrets/redis_password.txt | `redis_password` | `REDIS_PASSWORD` |
| smtp_password | secrets/smtp_password.txt | `smtp_password` | `SMTP_PASSWORD` |

The entrypoint resolves `*_FILE` env vars to actual values. Python `settings.py` does the same via `_load_file_secrets()`.

---

## API Endpoints

### Authentication
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/auth/login` | POST | No | JWT login |
| `/api/v1/auth/refresh` | POST | Yes | Refresh token |
| `/api/v1/setup/admin` | POST | No | Create initial admin |

### Dashboard & Monitoring
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Liveness probe |
| `/ready` | GET | No | Readiness probe (K8s) |
| `/health/detailed` | GET | Admin | Full telemetry |
| `/api/v1/dashboard/summary` | GET | read | Dashboard summary |
| `/api/v1/pipeline/status` | GET | read | Pipeline status |
| `/api/v1/monitoring/sla` | GET | read | SLA metrics |
| `/api/v1/monitoring/circuit-breakers` | GET | read | Circuit breaker status |
| `/metrics` | GET | No | Prometheus metrics |

### Event Ingestion
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/ingest/event` | POST | write | Ingest event |
| `/api/v1/ingest/agent` | POST | Agent JWT | Agent event ingestion |
| `/api/v1/ingest/batch` | POST | write | Batch ingestion |

### Detection & Response
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/detection/rules` | GET | read | Detection rules |
| `/api/v1/detection/alerts` | GET | read | Alert list |
| `/api/v1/response/actions` | GET | read | SOAR actions |
| `/api/v1/response/soar/trigger` | POST | soar | Trigger SOAR |

### Device Management
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/devices` | GET | read | List devices |
| `/api/v1/devices/register` | POST | write | Register device |
| `/api/v1/devices/{id}/isolate` | POST | admin | Isolate device |
| `/api/v1/devices/{id}/restore` | POST | admin | Restore device |

### Agent Management
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/agent/auth` | POST | Agent JWT | Agent authentication |
| `/api/v1/agent/heartbeat` | POST | Agent JWT | Agent heartbeat |
| `/api/v1/agent/commands` | GET | Agent JWT | Pending commands |
| `/api/v1/agent/download` | GET | No | Download agent installer |

### Administration
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/audit/logs` | GET | read | Audit trail |
| `/api/v1/admin/users` | GET | admin | User management |
| `/api/v1/org/keys` | GET | read | Organization keys |
| `/api/v1/analytics/*` | GET | read | Analytics endpoints |

---

## Pipeline Architecture

### Event Flow

```
Ingestion → Normalization → Enrichment → Detection → Correlation → Alert → SOAR → AI
```

### Pipeline Stages (in main.py lifespan)

| Phase | Startup | Description |
|-------|---------|-------------|
| 1 | Database | PostgreSQL + Redis connections |
| 2 | HA | Leader election for multi-instance |
| 3 | Pipeline | Unified pipeline initialization |
| 4 | Integrations | Third-party connectors |
| 5 | Ingestion | Syslog receiver, file watcher |
| 6 | WebSocket | Real-time dashboard updates |
| 7 | ML | Anomaly detection model training |
| 8 | Agent | Host agent manager, threat feeds |
| 9 | Data | Retention, device processor, DLQ |
| 10 | Seeding | Default policies and data |
| 11 | Background | HA health, backup, key rotation |
| 12 | On-Call | Alerting, runbooks |

---

## Testing

### Run Tests

```bash
# All tests
python -m pytest tests/ -v --tb=short

# Unit tests only
python -m pytest tests/unit/ -v --tb=short

# Integration tests
python -m pytest tests/integration/ -v --tb=short

# E2E tests
python -m pytest tests/e2e/ -v --tb=short

# Security tests
python -m pytest tests/security/ -v --tb=short

# Load tests
python tests/load/run.py --profile 10k-eps
```

### Security Audit

```bash
# Bandit SAST
bandit -r cybernova/ -f json -o bandit_report.json

# Dependency audit
pip-audit
```

---

## Host Agent

### Installation (Windows)

```powershell
# One-liner install
irm http://localhost:8000/agent.ps1 | iex
```

### Installation (Linux)

```bash
# Download and install
curl -sL http://localhost:8000/agent.sh | sudo bash
```

### Agent Event Types

| Event Type | Source | Default Severity |
|-----------|--------|-------------------|
| external_connection_threshold | network_monitor | high |
| malicious_process | process_monitor | critical |
| malicious_script | powershell_monitor | critical |
| suspicious_file | file_monitor | high |
| new_download | download_monitor | high |
| startup_item | registry_monitor | high |
| agent_heartbeat | agent_heartbeat | info |
| failed_login | windows_eventlog | medium |
| user_created | windows_eventlog | high |

---

## Risk Scoring

### Score Calculation

| Severity | Base Score |
|----------|-----------|
| info | 0 |
| low | 10 |
| medium | 30 |
| high | 60 |
| critical | 90 |

### Confirmation Thresholds

| Risk Score | Result |
|------------|--------|
| >= 120 | confirmed = TRUE |
| >= 80 | severity = high |
| >= 40 | severity = medium |

### Time Decay
- Rate: 5% every 10 minutes
- Function: `apply_risk_decay(conn, decay_minutes=10)`

---

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| 401 on valid token | JWT_SECRET mismatch | Ensure same secret across all services |
| 502 Bad Gateway | Backend unhealthy | `docker compose logs backend` |
| Duplicate services | RUN_ALL_SERVICES=true | Set `false` in docker-compose.yml |
| Agent auth fails | AGENT_PASSWORD mismatch | Re-generate `secrets/agent_password.txt` |
| Pipeline lagging | Worker overloaded | Scale pipeline-worker replicas |
| Database connection pool exhaustion | Pool too small | Increase `DB_POOL_SIZE` |

### Useful Commands

```bash
# Shell into backend
docker compose exec backend sh

# Database shell
docker compose exec postgres psql -U cybernova cybernova

# Redis CLI
docker compose exec redis redis-cli -a "$(cat secrets/redis_password.txt)"

# Check process list inside container
docker compose exec backend ps aux

# View container resource usage
docker stats --no-stream
```

---

*For deployment instructions, see [DEPLOYMENT_CHECKLIST.md](../DEPLOYMENT_CHECKLIST.md)*
*For operations runbooks, see [RUNBOOKS.md](RUNBOOKS.md)*
*Last Updated: 2026-06-01*
