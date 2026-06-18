#!/bin/bash
set -e

echo "============================================"
echo " CyberNova Development Startup"
echo "============================================"

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Error: docker not found"; exit 1; }
command -v docker compose >/dev/null 2>&1 || { echo "Error: docker compose not found"; exit 1; }

# Create required directories
mkdir -p secrets monitoring/grafana/datasources monitoring/grafana/dashboards nginx/ssl data/rag_store data/cold_storage

# Generate secrets if missing
if [ ! -f secrets/jwt_secret.txt ]; then
    echo "[setup] Generating dev secrets..."
    echo -n "dev-jwt-secret-key-change-in-production-at-least-64-chars-long!!!" > secrets/jwt_secret.txt
    echo -n "admin123!" > secrets/admin_password.txt
    echo -n "agent123!" > secrets/agent_password.txt
    echo -n "postgres-pass-123" > secrets/postgres_password.txt
    echo -n "redis-pass-123" > secrets/redis_password.txt
    echo -n "" > secrets/smtp_password.txt
fi

# Generate SSL certs if missing
if [ ! -f nginx/ssl/cert.pem ]; then
    echo "[setup] Generating dev SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem -out nginx/ssl/cert.pem \
        -subj "/CN=localhost/O=CyberNova/C=US" 2>/dev/null
fi

# Copy grafana datasource if missing
if [ ! -f monitoring/grafana/datasources/prometheus.yml ]; then
    mkdir -p monitoring/grafana/datasources
    cat > monitoring/grafana/datasources/prometheus.yml << 'YAMLEOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
YAMLEOF
fi

# Ensure .env exists
if [ ! -f .env ]; then
    echo "[setup] Creating .env from .env.example..."
    cp .env.example .env
fi

echo ""
echo "Starting CyberNova stack..."
echo ""

# Start core services first (db + redis)
echo "[1/3] Starting PostgreSQL and Redis..."
docker compose up -d postgres redis
echo "Waiting for database to be healthy..."
sleep 5

# Wait for postgres to be healthy
for i in $(seq 1 30); do
    if docker compose exec -T postgres pg_isready -U cybernova -q 2>/dev/null; then
        echo "  PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "  WARNING: PostgreSQL not ready after 30s, continuing anyway"
    fi
    sleep 1
done

# Start backend
echo "[2/3] Starting backend..."
docker compose up -d backend
echo "Waiting for backend to be healthy..."

for i in $(seq 1 60); do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "  Backend is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "  WARNING: Backend not ready after 60s"
    fi
    sleep 2
done

# Start frontend + nginx + monitoring
echo "[3/3] Starting frontend, nginx, and monitoring..."
docker compose up -d frontend nginx prometheus grafana alertmanager

echo ""
echo "============================================"
echo " CyberNova is starting up!"
echo "============================================"
echo ""
echo "  App (SPA):     http://localhost:8888"
echo "  App (SPA):     http://localhost:8888"
echo "  Direct:        http://localhost:8080"
echo "  API Docs:      http://localhost:8000/docs"
echo "  Health:        http://localhost:8000/health"
echo "  Grafana:       http://localhost:3001"
echo "  Prometheus:    http://localhost:9090"
echo ""
echo "  Default admin: admin / admin123!"
echo ""
echo "  First-time setup:"
echo "    1. Open http://localhost:8888"
echo "    2. Click 'Individual' or 'Organization'"
echo "    3. Register your admin account"
echo ""
echo "  To check logs: docker compose logs -f backend"
echo "  To stop: docker compose down"
echo "============================================"
