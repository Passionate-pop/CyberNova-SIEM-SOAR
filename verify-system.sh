#!/bin/bash
echo "============================================"
echo " CyberNova System Verification"
echo "============================================"
echo ""

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" = "ok" ]; then
        echo "  ✅ $label"
        PASS=$((PASS+1))
    elif [ "$result" = "warn" ]; then
        echo "  ⚠️  $label"
        WARN=$((WARN+1))
    else
        echo "  ❌ $label"
        FAIL=$((FAIL+1))
    fi
}

# 1. File structure
echo "[1/7] File Structure"
[ -f .env ] && check ".env exists" ok || check ".env missing" fail
[ -d secrets ] && check "secrets/ directory exists" ok || check "secrets/ missing" fail
[ -f secrets/jwt_secret.txt ] && check "JWT secret exists" ok || check "JWT secret missing" fail
[ -f secrets/postgres_password.txt ] && check "Postgres secret exists" ok || check "Postgres secret missing" fail
[ -f nginx/ssl/cert.pem ] && check "SSL cert exists" ok || check "SSL cert missing" fail
[ -f monitoring/grafana/datasources/prometheus.yml ] && check "Grafana datasource exists" ok || check "Grafana datasource missing" fail
[ -f docker-compose.yml ] && check "docker-compose.yml exists" ok || check "docker-compose.yml missing" fail
[ -f Dockerfile ] && check "Root Dockerfile exists" ok || check "Root Dockerfile missing" fail
[ -f cybernova-frontend/Dockerfile ] && check "Frontend Dockerfile exists" ok || check "Frontend Dockerfile missing" fail

# 2. Frontend build
echo ""
echo "[2/7] Frontend Build"
[ -d cybernova-frontend/dist ] && check "Frontend dist/ exists" ok || check "Frontend not built" fail
[ -f cybernova-frontend/dist/index.html ] && check "dist/index.html exists" ok || check "dist/index.html missing" fail

# 3. Backend Python imports
echo ""
echo "[3/7] Backend Python Imports"
python scripts/check_imports.py > /dev/null 2>&1
[ $? -eq 0 ] && check "All 80 backend modules import OK" ok || check "Some backend imports failed" fail

# 4. Backend Python files count
echo ""
echo "[4/7] Codebase Stats"
PY_COUNT=$(find cybernova -name '*.py' | wc -l | tr -d ' ')
echo "  📊 Backend Python files: $PY_COUNT"
TS_COUNT=$(find cybernova-frontend/src -name '*.tsx' -o -name '*.ts' | wc -l | tr -d ' ')
echo "  📊 Frontend TypeScript files: $TS_COUNT"
INIT_COUNT=$(find cybernova -name '__init__.py' | wc -l | tr -d ' ')
echo "  📊 Python packages (init files): $INIT_COUNT"

# 5. Docker
echo ""
echo "[5/7] Docker"
docker --version > /dev/null 2>&1 && check "Docker available" ok || check "Docker not found" fail
docker compose version > /dev/null 2>&1 && check "Docker Compose available" ok || check "Docker Compose not found" fail

# 6. Key configuration files
echo ""
echo "[6/7] Configuration"
[ -f nginx/nginx-unified.conf ] && check "Nginx unified config exists" ok || check "Nginx config missing" fail
[ -f monitoring/prometheus.yml ] && check "Prometheus config exists" ok || check "Prometheus config missing" fail
[ -f monitoring/alertmanager.yml ] && check "Alertmanager config exists" ok || check "Alertmanager config missing" fail
[ -f cybernova-frontend/nginx.conf ] && check "Frontend nginx config exists" ok || check "Frontend nginx config missing" fail

# 7. Backend routes
echo ""
echo "[7/7] API Routes"
ROUTER_COUNT=$(find cybernova -name '*.py' -path '*/routes/*' -o -name '*router*.py' -path '*/api/*' | wc -l | tr -d ' ')
echo "  📊 Router files: $ROUTER_COUNT"

# Summary
echo ""
echo "============================================"
echo " Results: $PASS passed | $FAIL failed | $WARN warnings"
echo "============================================"

if [ $FAIL -eq 0 ]; then
    echo ""
    echo "✅ System is READY for Docker deployment!"
    echo "   Run: ./dev-start.sh"
else
    echo ""
    echo "❌ Fix the $FAIL failed checks before deploying."
fi
echo ""
