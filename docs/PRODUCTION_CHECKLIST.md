# ═════════════════════════════════════════════════════════════════════════════
# CyberNova — Production Pre-Deployment Verification Checklist
# ═════════════════════════════════════════════════════════════════════════════
# Run this BEFORE going to production. Every item must be checked.
# Version: 2.0.0 | Last Updated: 2026-06-01
# ═════════════════════════════════════════════════════════════════════════════

## PHASE 1: SECRETS & CREDENTIALS ⚠️ CRITICAL

- [ ] 1.1 **All Docker secret files exist** and contain strong values:
      ```bash
      ls -la secrets/*.txt
      # Required: jwt_secret.txt, postgres_password.txt, redis_password.txt,
      #           admin_password.txt, agent_password.txt, smtp_password.txt
      ```

- [ ] 1.2 **JWT_SECRET** — 64 hex chars (256-bit HMAC-SHA256):
      ```bash
      wc -c secrets/jwt_secret.txt   # Should be 65+ (64 chars + newline)
      ```

- [ ] 1.3 **SECRET_KEY** differs from JWT_SECRET and is 32+ chars:
      ```bash
      [ "$(cat secrets/jwt_secret.txt)" != "$(cat secrets/secret_key.txt)" ] && echo "OK" || echo "FAIL"
      ```

- [ ] 1.4 **No default/weak passwords** in .env:
      ```bash
      grep -iE 'change_me|default|admin123|password1' .env && echo "FAIL" || echo "OK"
      ```

- [ ] 1.5 **File permissions locked down**:
      ```bash
      chmod 600 secrets/*.txt .env nginx/ssl/*.pem 2>/dev/null
      ls -la secrets/ .env nginx/ssl/
      # All should show -rw------- (600)
      ```

- [ ] 1.6 **ENVIRONMENT=production** and **DEBUG=false** in .env:
      ```bash
      grep -E '^(ENVIRONMENT|DEBUG)=' .env
      ```

- [ ] 1.7 **GRAFANA_PASSWORD** set in .env (required, will crash without it):
      ```bash
      grep -q 'GRAFANA_PASSWORD' .env && echo "OK" || echo "FAIL — grafana won't start"
      ```

---

## PHASE 2: NETWORK & TLS

- [ ] 2.1 **SSL certificates** exist and are valid:
      ```bash
      openssl x509 -in nginx/ssl/cert.pem -noout -dates
      # Not After should be > 30 days from now
      ```

- [ ] 2.2 **PostgreSQL port (5432) NOT exposed** to host:
      ```bash
      docker compose ps | grep 5432 && echo "FAIL" || echo "OK — not exposed"
      ```

- [ ] 2.3 **Redis port (6379) NOT exposed** to host:
      ```bash
      docker compose ps | grep 6379 && echo "FAIL" || echo "OK — not exposed"
      ```

- [ ] 2.4 **CORS_ORIGINS** set to production domain(s) in .env:
      ```bash
      grep 'CORS_ORIGINS' .env
      # Should NOT contain localhost in production
      ```

- [ ] 2.5 **UFW firewall** configured:
      ```bash
      sudo ufw status | grep -E '80|443|22'
      ```

---

## PHASE 3: SERVICES & HEALTH

- [ ] 3.1 **All 9 core services healthy** (10 with suricata):
      ```bash
      docker compose ps
      # All should show "healthy" or "Up"
      ```

- [ ] 3.2 **Backend /health returns 200**:
      ```bash
      curl -sf http://localhost:8888/health | python3 -m json.tool
      ```

- [ ] 3.3 **Backend /ready returns 200** (all deps operational):
      ```bash
      curl -sf http://localhost:8888/ready | python3 -m json.tool
      ```

- [ ] 3.4 **No critical errors in logs**:
      ```bash
      docker compose logs --tail=500 2>&1 | grep -iE 'CRITICAL|FATAL|Traceback' | head -20
      ```

- [ ] 3.5 **Database migrations applied**:
      ```bash
      docker compose exec postgres psql -U cybernova cybernova \
        -c "SELECT version FROM alembic_version;" 2>/dev/null || echo "No alembic — schema managed by lifespan"
      ```

---

## PHASE 4: AUTHENTICATION & AUTHORIZATION

- [ ] 4.1 **Admin login works**:
      ```bash
      TOKEN=$(curl -sf -X POST http://localhost:8888/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
      [ -n "$TOKEN" ] && echo "OK" || echo "FAIL"
      ```

- [ ] 4.2 **Invalid credentials rejected** (401):
      ```bash
      curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8888/api/v1/auth/login \
        -H "Content-Type: application/json" -d '{"username":"admin","password":"wrong"}'
      # Expected: 401
      ```

- [ ] 4.3 **WAF blocks malicious requests** (403):
      ```bash
      curl -s -o /dev/null -w "%{http_code}" "http://localhost:8888/api/v1/auth/login' OR 1=1--"
      # Expected: 403
      ```

- [ ] 4.4 **Rate limiting works** (429 after threshold):
      ```bash
      for i in $(seq 1 110); do
        code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/health)
        [ "$code" = "429" ] && echo "Rate limit OK at request $i" && break
      done
      ```

- [ ] 4.5 **RBAC enforced** — viewer can't write:
      ```bash
      VIEWER_TOKEN=$(curl -sf -X POST http://localhost:8888/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username":"viewer","password":"viewer123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
      curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8888/api/v1/admin/devices/test/isolate \
        -H "Authorization: Bearer $VIEWER_TOKEN" -d '{}'
      # Expected: 403
      ```

---

## PHASE 5: MONITORING & ALERTING

- [ ] 5.1 **Prometheus targets up**:
      ```bash
      curl -sf http://localhost:9090/api/v1/targets | python3 -c "
      import sys,json; d=json.load(sys.stdin)
      [print(f\"  {t['labels']['job']}: {t['health']}\") for t in d['data']['activeTargets']]
      "
      ```

- [ ] 5.2 **Alert rules loaded**:
      ```bash
      curl -sf http://localhost:9090/api/v1/rules | python3 -c "
      import sys,json; d=json.load(sys.stdin)
      print(f\"  {len(d['data']['groups'])} groups loaded\")
      "
      ```

- [ ] 5.3 **Grafana accessible**:
      ```bash
      curl -sf http://localhost:3000/api/health
      ```

- [ ] 5.4 **SMTP configured** for Alertmanager (if using email):
      ```bash
      grep 'SMTP_HOST' .env | grep -v '^#' | grep -v '=$' && echo "OK" || echo "WARN — email alerts won't send"
      ```

---

## PHASE 6: BACKUP & RECOVERY

- [ ] 6.1 **Backup script works**:
      ```bash
      ./scripts/backup.sh
      ls -la backups/ | tail -3
      ```

- [ ] 6.2 **Cron job scheduled**:
      ```bash
      crontab -l 2>/dev/null | grep backup || echo "WARN — no backup cron"
      ```

- [ ] 6.3 **Restore tested** (at least once):
      ```bash
      echo "Documented restore procedure exists: docs/DEPLOYMENT_RUNBOOK.md"
      ```

---

## PHASE 7: FINAL GO/NO-GO

| Check | Status |
|-------|--------|
| All secrets generated and locked down | [ ] |
| TLS configured with valid certs | [ ] |
| All 9+ services healthy | [ ] |
| Auth + WAF + Rate limiting verified | [ ] |
| Monitoring stack operational | [ ] |
| Backup tested | [ ] |
| Firewall configured | [ ] |
| No default passwords | [ ] |
| CORS set for production domain | [ ] |

**GO / NO-GO:** __________

**Deployed by:** __________
**Date:** __________
**Server:** __________

---

*Last Updated: 2026-06-01 | Architecture: 10 services | Secrets: Docker secrets | TLS: nginx*
