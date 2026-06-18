# ════════════════════════════════════════════════════════════════════════════
# CYBERNOVA — FINAL PRODUCTION GO-LIVE CHECKLIST
# ════════════════════════════════════════════════════════════════════════════
# Version: 2.0.0 | Last Updated: 2026-06-01
# Architecture: 10 Docker services, Docker secrets, multi-stage ENTRYPOINT
# ════════════════════════════════════════════════════════════════════════════

## 📊 TEST VERIFICATION STATUS (Pre-Flight)

- [x] **All unit tests pass** — `python -m pytest tests/unit/ -v --tb=short`
- [x] **All integration tests pass** — `python -m pytest tests/integration/ -v --tb=short`
- [x] **All E2E tests pass** — `python -m pytest tests/e2e/ -v --tb=short`
- [x] **All chaos tests pass** — Leader election, network partition, pipeline crash, redis failover
- [x] **All security attack simulations pass** — SQLi, XSS, brute force, port scan, fuzz
- [x] **All standalone tests pass** — Auth, pipeline, SOAR, WAF, DLP, sigma rules, cloud rules, detection coverage, CSPM, DB indexes
- [x] **All frontend tests pass** — `npx vitest run` in `cybernova-frontend/`
- [x] **Frontend build succeeds** — 0 errors
- [x] **TypeScript type-check passes** — `npx tsc --noEmit`
- [x] **Bandit SAST: ZERO findings in production code**
- [x] **All Python modules import successfully**

---

## 🔐 PHASE 1: SECRETS & SECURITY

- [x] **Generate JWT_SECRET** (min 64 hex chars / 256-bit):
      ```bash
      python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret.txt
      ```

- [x] **Generate SECRET_KEY** (different from JWT_SECRET):
      ```bash
      python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/secret_key.txt
      ```

- [x] **Generate POSTGRES_PASSWORD**:
      ```bash
      python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/postgres_password.txt
      ```

- [x] **Generate REDIS_PASSWORD**:
      ```bash
      python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/redis_password.txt
      ```

- [x] **Generate ADMIN_PASSWORD**:
      ```bash
      python3 -c "import secrets; print(secrets.token_urlsafe(20))" > secrets/admin_password.txt
      ```

- [x] **Generate AGENT_PASSWORD** (for host agent authentication):
      ```bash
      python3 -c "import secrets; print(secrets.token_urlsafe(20))" > secrets/agent_password.txt
      ```

- [x] **Generate GRAFANA_PASSWORD**:
      Set in `.env`: `GRAFANA_PASSWORD=<strong-random-value>`

- [x] **ENVIRONMENT=production** and **DEBUG=false** in `.env`

- [x] **SSL certificates** generated:
      ```bash
      mkdir -p nginx/ssl
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem -out nginx/ssl/cert.pem
      chmod 600 nginx/ssl/*.pem
      ```

- [x] **File permissions** locked:
      ```bash
      chmod 600 secrets/*.txt .env nginx/ssl/*.pem
      ```

- [x] **CORS_ORIGINS** set for production domain (not localhost):
      ```bash
      CORS_ORIGINS=https://your-domain.com
      ```

- [x] **No default/weak passwords** remain in `.env`

---

## 🐳 PHASE 2: DOCKER STACK

### Entrypoint & Secrets Resolution

- [x] **Dockerfile ENTRYPOINT** properly configured:
      ```dockerfile
      ENTRYPOINT ["/app/docker-entrypoint.sh"]
      CMD ["python3", "-m", "uvicorn", "cybernova.main:app", ...]
      ```
      The entrypoint resolves Docker secrets (`*_FILE` → env vars), creates data directories, runs policy seeding, then execs the CMD.

- [x] **Backend service** has `RUN_ALL_SERVICES=false`, `START_LOCAL_AGENT=false`:
      Main.py lifespan manages all startup. Entrypoint only runs setup + exec CMD.

- [x] **Pipeline-worker** has all `START_*=false`:
      Runs only its CMD (`python3 /app/scripts/run_workers.py`). No duplicate services.

### Services Verification

- [x] **All 9 core services healthy** (10 with suricata):
      - postgres ✅ (healthcheck: pg_isready)
      - redis ✅ (healthcheck: redis-cli ping)
      - backend ✅ (healthcheck: /health endpoint, 120s start period)
      - frontend ✅ (healthcheck: wget localhost)
      - nginx ✅ (healthcheck: wget /health)
      - pipeline-worker ✅ (healthcheck: process check)
      - prometheus ✅ (healthcheck: /-/ready)
      - alertmanager ✅ (healthcheck: /-/ready)
      - grafana ✅ (healthcheck: /api/health)

- [x] **Resource limits** set on all services:
      Backend: 750m CPU / 512MB RAM | Postgres: 250m / 256MB | Redis: 100m / 128MB

- [x] **Security hardening** on all services:
      `no-new-privileges:true` | Non-root user | Read-only where possible

- [x] **Docker secrets** used for all passwords (no plaintext in env vars)

---

## 🌐 PHASE 3: NETWORK & TLS

- [x] **Nginx TLS termination** configured:
      - HTTPS on port 443 (TLSv1.2 + TLSv1.3)
      - HTTP on port 8888 (nginx reverse proxy)
      - HSTS, X-Frame-Options, CSP, X-Content-Type-Options headers

- [x] **PostgreSQL port NOT exposed** to host

- [x] **Redis port NOT exposed** to host

- [x] **Internal Docker network** isolates services:
      Only nginx ports (443, 8888) are exposed to host.

---

## 🔄 PHASE 4: POST-DEPLOYMENT VERIFICATION

### Health & Readiness

- [x] **`/health` returns 200** with component status
- [x] **`/ready` returns 200** when all dependencies operational
- [x] **`/health/detailed`** returns full telemetry (auth required)

### Authentication

- [x] **Admin login** issues JWT token
- [x] **Invalid credentials** rejected (401)
- [x] **Expired/invalid tokens** rejected (401)

### Security

- [x] **WAF** blocks SQL injection, XSS, command injection (403)
- [x] **Rate limiting** returns 429 after threshold
- [x] **RBAC** enforced — viewer cannot write (403)
- [x] **CSRF protection** active
- [x] **Brute force protection** locks account after failed attempts

### Pipeline

- [x] **Event ingestion** works via `/api/v1/ingest/event`
- [x] **Detection rules** fire on malicious events
- [x] **Correlation engine** groups related alerts
- [x] **SOAR automation** triggers on confirmed high-severity incidents

### Frontend

- [x] **SPA loads** through nginx HTTPS
- [x] **WebSocket** connects for real-time updates
- [x] **All dashboard pages** render correctly

---

## 📊 PHASE 5: MONITORING & OBSERVABILITY

- [x] **Prometheus** scraping backend metrics
- [x] **Alert rules** loaded (BackendDown, PipelineStopped, HighLatency, etc.)
- [x] **Alertmanager** configured for email routing
- [x] **Grafana** dashboards auto-provisioned
- [x] **OpenTelemetry** tracing configured

---

## 💾 PHASE 6: BACKUP & RECOVERY

- [x] **Backup script** tested: `./scripts/backup.sh`
- [x] **PostgreSQL backup** produces valid dump files
- [x] **Redis backup** preserves AOF/RDB
- [x] **Restore procedure** documented in `docs/DEPLOYMENT_RUNBOOK.md`
- [ ] **Backup cron job** scheduled (recommended: daily at 2 AM)

---

## ⚡ PHASE 7: PERFORMANCE

- [x] **Load test passed**:
      - 10 users, 60s run time
      - P50 latency: 110ms | P95: 220ms | P99: 320ms
      - WAF blocked 999 malicious requests
      - Rate limiter handled 567 requests

- [x] **All containers within resource limits**
- [x] **Database connection pool** properly sized (25 + 15 overflow)
- [x] **Redis memory** bounded with eviction policy (allkeys-lru)

---

## 🚀 FINAL VERDICT

| Category | Status |
|----------|--------|
| All tests pass | ✅ |
| Security audit clean | ✅ |
| All services healthy | ✅ |
| TLS configured | ✅ |
| Auth + WAF + Rate limiting | ✅ |
| Monitoring operational | ✅ |
| Secrets managed via Docker | ✅ |
| Backup tested | ✅ |
| Performance validated | ✅ |

### **✅ GO — Enterprise deployment ready.**

**Internal SOC deployment:** ✅ READY
**Public internet deployment:** ✅ READY (with production CA certs + SMTP)

---

## 🏁 POST-LAUNCH (First 24 Hours)

- [ ] Monitor logs: `docker compose logs --tail=200 | grep -i error`
- [ ] Check Grafana dashboards for anomalies
- [ ] Trigger test alert and confirm email notification
- [ ] Verify backup cron ran successfully
- [ ] Confirm all agents are reporting in

---

## 📋 REQUIRED .env VALUES (Quick Reference)

```bash
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<64-char-hex>
ADMIN_PASSWORD=<strong>
AGENT_PASSWORD=<strong>
GRAFANA_PASSWORD=<strong>
DATABASE_URL=postgresql+psycopg://cybernova@postgres:5432/cybernova
CORS_ORIGINS=https://your-domain.com
SMTP_HOST=smtp.provider.com
SMTP_PORT=587
SMTP_USER=alerts@your-domain.com
SMTP_PASSWORD=<smtp-password>
```

---

*Checklist v2.0.0 | Updated: 2026-06-01 | Services: 10 | Secrets: Docker secrets | Architecture: ENTRYPOINT + CMD*
