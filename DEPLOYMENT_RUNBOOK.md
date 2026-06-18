# CyberNova Production Deployment Runbook

## Prerequisites

- Docker 24+ and Docker Compose v2.20+
- Domain name with DNS pointing to deployment server
- SSL certificate (letsencrypt or commercial CA)
- SMTP server for email notifications

## Step 1: Clone & Configure

```bash
git clone <repo-url> cybernova
cd cybernova

# Create production environment
cp .env.production.example .env
# EDIT .env with your production values!
```

### Required .env Values

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | 64+ char random hex for JWT signing |
| `SECRET_KEY` | Different 64+ char random hex (NOT same as JWT_SECRET) |
| `ADMIN_PASSWORD` | Strong admin password (min 12 chars) |
| `AGENT_PASSWORD` | Agent authentication password |
| `POSTGRES_PASSWORD` | Database password |
| `REDIS_PASSWORD` | Redis password |
| `CORS_ORIGINS` | Comma-separated allowed origins |

Generate secure keys:
```bash
python -c "import secrets; print('JWT_SECRET=' + secrets.token_hex(32))"
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```

## Step 2: Deploy

```bash
# Build and start all services
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check all services are healthy
watch docker compose ps
```

## Step 3: Initial Setup

```bash
# Wait for backend to be ready (60s)
curl -s http://localhost:8000/health

# Create admin user (first-time setup)
curl -X POST http://localhost:8000/api/v1/setup/admin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@your-domain.com","password":"<ADMIN_PASSWORD>","company_name":"Your Company"}'
```

## Step 4: Verify Deployment

```bash
# Run the full verification
python scripts/attack_sim.py

# Run the pipeline demo
python scripts/full_pipeline_demo.py

# Check monitoring
open http://localhost:9090  # Prometheus
open http://localhost:3001  # Grafana (admin / <GRAFANA_PASSWORD>)
```

## Step 5: Configure SSL (Production)

Replace nginx auto-generated self-signed certs:
```bash
# Copy your certs
cp /path/to/fullchain.pem nginx/ssl/cert.pem
cp /path/to/privkey.pem nginx/ssl/key.pem

# Restart nginx
docker compose restart nginx
```

## Maintenance

### Backup
```bash
# Manual backup
curl -X POST http://localhost:8000/api/v1/backup/db -H "Authorization: Bearer <token>"

# List backups
curl http://localhost:8000/api/v1/backup/list -H "Authorization: Bearer <token>"
```

### Restore
```bash
curl -X POST "http://localhost:8000/api/v1/backup/restore?backup_file=data/backups/cybernova_db_20240101_120000.dump" \
  -H "Authorization: Bearer <token>"
```

### Logs
```bash
docker compose logs -f backend
docker compose logs -f pipeline-worker
```

### Update
```bash
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Backend won't start | `docker compose logs backend` — look for DB connection errors |
| Frontend shows blank page | Check nginx logs: `docker compose logs nginx` |
| No alerts in dashboard | Run `python scripts/full_pipeline_demo.py` |
| Grafana shows no data | Check Prometheus: `http://localhost:9090/targets` |
| Email not sending | Check MailHog: `http://localhost:8025` (dev) or SMTP config |

## Security Checklist

- [ ] All default passwords changed in .env
- [ ] PostgreSQL port not exposed (handled by docker-compose.prod.yml)
- [ ] Redis port not exposed (handled by docker-compose.prod.yml)
- [ ] SSL certificates installed and auto-renewal configured
- [ ] CORS_ORIGINS set to specific domain(s), not wildcard
- [ ] Rate limiting enabled
- [ ] WAF enabled (default)
- [ ] Audit logging enabled (default)
- [ ] Backups configured
- [ ] Monitoring alerts configured in alertmanager.yml
