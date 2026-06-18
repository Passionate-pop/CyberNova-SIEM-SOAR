# CyberNova Development Startup (PowerShell)
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " CyberNova Development Startup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Check prerequisites
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Error: docker not found" -ForegroundColor Red
    exit 1
}

# Create required directories
@('secrets', 'monitoring/grafana/datasources', 'monitoring/grafana/dashboards', 'nginx/ssl', 'data/rag_store', 'data/cold_storage') | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# Generate secrets if missing
if (-not (Test-Path 'secrets/jwt_secret.txt')) {
    Write-Host "[setup] Generating dev secrets..."
    Set-Content -Path 'secrets/jwt_secret.txt' -Value 'dev-jwt-secret-key-change-in-production-at-least-64-chars-long!!!' -NoNewline
    Set-Content -Path 'secrets/admin_password.txt' -Value 'admin123!' -NoNewline
    Set-Content -Path 'secrets/agent_password.txt' -Value 'agent123!' -NoNewline
    Set-Content -Path 'secrets/postgres_password.txt' -Value 'postgres-pass-123' -NoNewline
    Set-Content -Path 'secrets/redis_password.txt' -Value 'redis-pass-123' -NoNewline
    Set-Content -Path 'secrets/smtp_password.txt' -Value '' -NoNewline
}

# Generate SSL certs if missing
if (-not (Test-Path 'nginx/ssl/cert.pem')) {
    Write-Host "[setup] Generating dev SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx/ssl/key.pem -out nginx/ssl/cert.pem -subj "/CN=localhost/O=CyberNova/C=US" 2>$null
}

# Ensure .env exists
if (-not (Test-Path '.env')) {
    Write-Host "[setup] Creating .env from .env.example..."
    Copy-Item .env.example .env
}

# Ensure Grafana datasource
if (-not (Test-Path 'monitoring/grafana/datasources/prometheus.yml')) {
    @'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
'@ | Set-Content 'monitoring/grafana/datasources/prometheus.yml'
}

Write-Host ""
Write-Host "Starting CyberNova stack..."
Write-Host ""

# Start core services
Write-Host "[1/3] Starting PostgreSQL and Redis..." -ForegroundColor Yellow
docker compose up -d postgres redis
Start-Sleep -Seconds 5

Write-Host "Waiting for database..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        docker compose exec -T postgres pg_isready -U cybernova -q 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  PostgreSQL is ready"
            $ready = $true
            break
        }
    } catch {}
    Start-Sleep -Seconds 1
}
if (-not $ready) { Write-Host "  WARNING: PostgreSQL not ready, continuing anyway" -ForegroundColor Yellow }

# Start backend
Write-Host "[2/3] Starting backend..." -ForegroundColor Yellow
docker compose up -d backend
Write-Host "Waiting for backend..."
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($resp.StatusCode -eq 200) {
            Write-Host "  Backend is ready"
            $ready = $true
            break
        }
    } catch {}
    Start-Sleep -Seconds 2
}
if (-not $ready) { Write-Host "  WARNING: Backend not ready after 120s" -ForegroundColor Yellow }

# Start frontend + nginx + monitoring
Write-Host "[3/3] Starting frontend, nginx, and monitoring..." -ForegroundColor Yellow
docker compose up -d frontend nginx prometheus grafana alertmanager

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host " CyberNova is starting up!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  App (SPA):     http://localhost:8888" -ForegroundColor Green
Write-Host "  Direct:        http://localhost:8080" -ForegroundColor Green
Write-Host "  API Docs:      http://localhost:8000/docs"
Write-Host "  Health:        http://localhost:8000/health"
Write-Host "  Grafana:       http://localhost:3001"
Write-Host "  Prometheus:    http://localhost:9090"
Write-Host ""
Write-Host "  Default admin: admin / admin123!"
Write-Host ""
Write-Host "  First-time setup:"
Write-Host "    1. Open http://localhost:8888"
Write-Host "    2. Click 'Individual' or 'Organization'"
Write-Host "    3. Register your admin account"
Write-Host ""
Write-Host "  To check logs: docker compose logs -f backend"
Write-Host "  To stop: docker compose down"
Write-Host "============================================"
