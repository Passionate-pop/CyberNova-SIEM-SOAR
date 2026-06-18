# ═════════════════════════════════════════════════════════════════════════════
# CyberNova — Enterprise Deployment Checklist
# ═════════════════════════════════════════════════════════════════════════════
# Version: 2.0.0 | Last Updated: 2026-06-01
# Services: postgres, redis, backend, frontend, nginx, pipeline-worker,
#           prometheus, alertmanager, grafana, suricata (optional)
# ═════════════════════════════════════════════════════════════════════════════

## ── PHASE 0: SERVER REQUIREMENTS ───────────────────────────────────────────

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB | 50+ GB SSD |
| Docker | 24.0+ | Latest stable |
| Docker Compose | v2.20+ | Latest stable |
| Access | Root or sudo | Dedicated deploy user |

### Open Ports
```
80    — HTTP (redirects to HTTPS)
443   — HTTPS (primary entry point)
8888  — HTTP fallback (nginx)
9090  — Prometheus (internal only)
9093  — Alertmanager (internal only)
3000  — Grafana (internal only)
22    — SSH
```

---

## ── PHASE 1: SECRETS & ENVIRONMENT ─────────────────────────────────────────

### 1.1 Generate Cryptographic Secrets

```bash
# Create secrets directory (excluded from git)
mkdir -p secrets && chmod 700 secrets

# JWT signing key (64 hex chars = 256-bit HMAC-SHA256)
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret.txt

# SECRET_KEY (secondary signing key for webhooks — must differ from JWT_SECRET)
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/secret_key.txt

# PostgreSQL password
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/postgres_password.txt

# Redis password
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/redis_password.txt

# Admin password (min 12 chars, mixed case + digits + symbols)
python3 -c "import secrets, string; alphabet=string.ascii_letters+string.digits+'!@#$%&*'; print(''.join(secrets.choice(alphabet) for _ in range(20)))" > secrets/admin_password.txt

# Agent authentication password
python3 -c "import secrets, string; alphabet=string.ascii_letters+string.digits+'!@#$%&*'; print(''.join(secrets.choice(alphabet) for _ in range(20)))" > secrets/agent_password.txt

# SMTP password (set to placeholder if not using email alerts)
echo "smtp_placeholder" > secrets/smtp_password.txt

# Lock down permissions
chmod 600 secrets/*.txt
```

### 1.2 Create Production .env

```bash
cat > .env << 'EOF'
# ── Environment ────────────────────────────────────────────────
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# ── Security (use values generated above) ──────────────────────
SECRET_KEY=<paste from secrets/secret_key.txt>
ADMIN_PASSWORD=<paste from secrets/admin_password.txt>
AGENT_PASSWORD=<paste from secrets/agent_password.txt>
GRAFANA_PASSWORD=<generate a strong password>

# ── Database ───────────────────────────────────────────────────
DATABASE_URL=postgresql+psycopg://cybernova@postgres:5432/cybernova

# ── CORS (comma-separated list of allowed origins) ─────────────
CORS_ORIGINS=https://your-domain.com,https://www.your-domain.com

# ── SMTP (configure for email alerts) ──────────────────────────
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USER=alerts@your-domain.com
SMTP_PASSWORD=<your-smtp-password>
FROM_EMAIL=alerts@your-domain.com
ALERT_EMAIL_TO=security-team@your-domain.com

# ── Threat Intelligence (optional) ────────────────────────────
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=

# ── Performance ────────────────────────────────────────────────
DB_POOL_SIZE=25
DB_MAX_OVERFLOW=15
DB_POOL_TIMEOUT=30
UVICORN_WORKERS=1
REDIS_MAXMEMORY=512mb
EOF

chmod 600 .env
```

### 1.3 Generate SSL Certificates

```bash
# Option A: Self-signed (internal SOC / development)
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/CN=cybernova/O=CyberNova/C=US"
chmod 600 nginx/ssl/*.pem

# Option B: Let's Encrypt (production — requires domain DNS)
# sudo apt install certbot python3-certbot-nginx -y
# sudo certbot certonly --standalone -d your-domain.com
# Copy certs to nginx/ssl/cert.pem and nginx/ssl/key.pem
```

---

## ── PHASE 2: DEPLOY ────────────────────────────────────────────────────────

### 2.1 Upload & Build

```bash
# From local machine
scp -r . user@server:/opt/cybernova

# On server
cd /opt/cybernova
docker compose up -d --build
```

### 2.2 Verify All 10 Services

```bash
docker compose ps
# Expected: postgres, redis, backend, frontend, nginx,
#           pipeline-worker, prometheus, alertmanager, grafana healthy
#           suricata (optional, may be unhealthy without host networking)
```

### 2.3 Health Checks

```bash
# Backend API
curl -sf http://localhost:8888/health | python3 -m json.tool

# Readiness (should return 200 when all dependencies are up)
curl -sf http://localhost:8888/ready | python3 -m json.tool

# HTTPS (after SSL configured)
curl -skf https://localhost/health | python3 -m json.tool

# Prometheus
curl -sf http://localhost:9090/-/ready

# Grafana
curl -sf http://localhost:3000/api/health
```

### 2.4 First-Time Admin Setup

```bash
# Create the initial admin user (only needed on first run)
curl -X POST http://localhost:8888/api/v1/setup/admin \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@your-domain.com",
    "password": "<ADMIN_PASSWORD from .env>"
  }'
```

---

## ── PHASE 3: POST-DEPLOYMENT VERIFICATION ──────────────────────────────────

### 3.1 Authentication

```bash
# Login
TOKEN=$(curl -sf -X POST http://localhost:8888/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Verify token works
curl -sf -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/pipeline/status | python3 -m json.tool
```

### 3.2 WAF & Rate Limiting

```bash
# WAF should block SQL injection
curl -s -o /dev/null -w "%{http_code}" "http://localhost:8888/api/v1/auth/login' OR 1=1--"
# Expected: 403

# Rate limiting should return 429 after threshold
for i in $(seq 1 110); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/health)
  [ "$code" = "429" ] && echo "Rate limit hit at request $i" && break
done
```

### 3.3 Event Ingestion Pipeline

```bash
# Register a test device
ORG_KEY=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/org/keys | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['org_key'])")

curl -sf -X POST http://localhost:8888/api/v1/devices/register \
  -H "Content-Type: application/json" \
  -d "{\"org_key\":\"$ORG_KEY\",\"hostname\":\"test-server\",\"ip_address\":\"10.0.0.1\",\"os_type\":\"linux\"}"

# Ingest a test event
curl -sf -X POST http://localhost:8888/api/v1/ingest/event \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "event_type": "failed_login",
    "severity": "high",
    "source_ip": "192.168.1.100",
    "hostname": "test-server",
    "message": "Test event for pipeline verification"
  }'
```

### 3.4 RBAC Verification

```bash
# Login as viewer (should have read-only)
VIEWER_TOKEN=$(curl -sf -X POST http://localhost:8888/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"viewer","password":"viewer123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Should return 403 (no write access)
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8888/api/v1/admin/devices/test/isolate \
  -H "Authorization: Bearer $VIEWER_TOKEN" \
  -H "Content-Type: application/json" -d '{}'
# Expected: 403
```

---

## ── PHASE 4: MONITORING SETUP ──────────────────────────────────────────────

### 4.1 Prometheus Targets

```bash
# Verify targets are being scraped
curl -sf http://localhost:9090/api/v1/targets | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['data']['activeTargets']:
    print(f\"  {t['labels']['job']}: {t['health']}\")
"
```

### 4.2 Alertmanager

```bash
# Verify alertmanager is ready
curl -sf http://localhost:9093/-/ready

# Check loaded config
curl -sf http://localhost:9093/api/v2/status | python3 -m json.tool
```

### 4.3 Grafana

```bash
# Access: http://localhost:3000
# Login: admin / GRAFANA_PASSWORD from .env
# Dashboards are auto-provisioned from monitoring/grafana/dashboards/
```

### 4.4 Cron Health Check

```bash
# Add to crontab for continuous monitoring
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -sf http://localhost:8888/health > /dev/null 2>&1 || docker compose -f /opt/cybernova/docker-compose.yml restart backend") | crontab -
```

---

## ── PHASE 5: BACKUP & DISASTER RECOVERY ────────────────────────────────────

### 5.1 Automated Backups

```bash
# Run backup script
./scripts/backup.sh

# Verify backups exist
ls -la backups/

# Schedule daily backups (cron)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/cybernova/scripts/backup.sh >> /var/log/cybernova_backup.log 2>&1") | crontab -
```

### 5.2 Restore Procedure

```bash
# Stop application services
docker compose stop backend pipeline-worker

# Restore PostgreSQL
docker compose exec -T postgres pg_restore -U cybernova -d cybernova \
  < backups/cybernova_pg_YYYYMMDD_HHMMSS.dump

# Restart services
docker compose start backend pipeline-worker
```

---

## ── PHASE 6: SECURITY HARDENING ────────────────────────────────────────────

### 6.1 Host Firewall

```bash
# Enable UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP redirect
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### 6.2 Fail2ban

```bash
sudo apt install fail2ban -y
# Configure fail2ban for SSH and nginx as needed
```

### 6.3 Verify Secrets Not in Git

```bash
# Ensure .gitignore includes:
# .env
# secrets/
# nginx/ssl/*.pem

git status --porcelain | grep -E '\.env|secrets/|ssl/'
# Should return nothing
```

---

## ── PHASE 7: KUBERNETES (OPTIONAL) ─────────────────────────────────────────

For Kubernetes deployment, use the Helm chart:

```bash
# Install
helm install cybernova ./helm/cybernova \
  --set config.environment=production \
  --set postgresql.auth.password=<STRONG_PASSWORD> \
  --set redis.auth.password=<STRONG_PASSWORD> \
  --set grafana.adminPassword=<STRONG_PASSWORD> \
  --set config.corsOrigins=https://your-domain.com

# Verify
kubectl get pods -n cybernova
kubectl get svc -n cybernova
```

### Helm Chart Features
- **HPA**: Auto-scales 3–10 replicas based on CPU/memory
- **PDB**: Minimum 2 replicas available (backend), 1 (worker)
- **Security**: Non-root (UID 1000), read-only root FS, dropped capabilities
- **Anti-Affinity**: Spreads pods across nodes
- **Secrets**: K8s Secrets with Docker secret fallback

---

## ── QUICK REFERENCE ────────────────────────────────────────────────────────

| Command | Description |
|---------|-------------|
| `docker compose up -d --build` | Build & start all services |
| `docker compose down` | Stop all services |
| `docker compose ps` | Service status & health |
| `docker compose logs -f backend` | Backend logs |
| `docker compose logs -f pipeline-worker` | Worker logs |
| `docker compose restart backend` | Restart backend only |
| `docker compose exec postgres psql -U cybernova cybernova` | DB shell |
| `docker compose exec redis redis-cli` | Redis CLI |
| `curl http://localhost:8888/health` | Health check |
| `curl http://localhost:8888/ready` | Readiness check |
| `./scripts/backup.sh` | Run backup |

---

## ── TROUBLESHOOTING ────────────────────────────────────────────────────────

| Issue | Diagnosis | Fix |
|-------|-----------|-----|
| Backend won't start | `docker compose logs backend` | Check secrets exist, DATABASE_URL correct |
| 502 Bad Gateway | Nginx can't reach backend | `docker compose ps backend` — ensure healthy |
| Duplicate services | Check START_ env vars | Ensure `RUN_ALL_SERVICES=false` in docker-compose |
| Agent auth fails | AGENT_PASSWORD mismatch | Re-generate in secrets/agent_password.txt |
| TLS errors | Check cert files | `openssl x509 -in nginx/ssl/cert.pem -text -noout` |
| Pipeline lagging | Check worker logs | `docker compose logs -f pipeline-worker` |
| Grafana 503 | Check GF_SECURITY_ADMIN_PASSWORD | Must be set in .env |

---

**Date Completed: __________**
**Server IP: __________**
**Domain: __________**
**Admin Email: __________**
**Deployed By: __________**
