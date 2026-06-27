<#
.SYNOPSIS
    CyberNova — One-Command Start (Windows PowerShell)
.DESCRIPTION
    Starts the full CyberNova stack via Docker Compose.
    Usage:
      .\start-cybernova.ps1          # Start everything
      .\start-cybernova.ps1 -Stop    # Stop everything
      .\start-cybernova.ps1 -Status  # Check status
#>

param(
    [switch]$Stop,
    [switch]$Status,
    [switch]$Dev
)

$ErrorActionPreference = "Stop"
$CYAN = "Cyan"
$GREEN = "Green"
$RED = "Red"

function Write-Info  { Write-Host "[INFO]  $args" -ForegroundColor $CYAN }
function Write-Ok    { Write-Host "[OK]    $args" -ForegroundColor $GREEN }
function Write-Err   { Write-Host "[ERR]   $args" -ForegroundColor $RED }

# ── Check .env ─────────────────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Write-Err ".env file not found! Run: cp .env.production.example .env"
    exit 1
}
Write-Ok ".env file found"

# ── Stop ───────────────────────────────────────────────────────────────────
if ($Stop) {
    Write-Info "Stopping all services..."
    docker compose down --remove-orphans
    Get-Process -Name "python" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Ok "All services stopped"
    exit 0
}

# ── Status ─────────────────────────────────────────────────────────────────
if ($Status) {
    docker ps --format "table {{.Names}}`t{{.Status}}"
    exit 0
}

# ── Start ──────────────────────────────────────────────────────────────────
Write-Info "Starting CyberNova with Docker Compose..."
docker compose up -d postgres redis backend frontend mailhog

Write-Info "Waiting for services to become healthy..."
Start-Sleep -Seconds 10

# Show status
docker ps --format "table {{.Names}}`t{{.Status}}"

# Check backend health
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 10 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Ok "Backend health check passed"
    }
} catch {
    Write-Err "Backend health check failed — run: docker logs cybernova-backend"
}

Write-Host ""
Write-Info "===================== CyberNova is RUNNING ====================="
Write-Host ""
Write-Host "  Marketing Site:     http://localhost:8888"
Write-Host "  Frontend SPA:       http://localhost:8888/app/"
Write-Host "  Backend API:        http://localhost:8000"
Write-Host "  Health Check:       http://localhost:8000/health"
Write-Host "  MailHog (Email):    http://localhost:8025"
Write-Host ""
Write-Info "Stop with: .\start-cybernova.ps1 -Stop"
