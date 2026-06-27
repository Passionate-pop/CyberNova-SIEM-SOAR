#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# CyberNova — One-Command Start (Linux/Mac/WSL)
# ═════════════════════════════════════════════════════════════════════════════
# Usage:
#   ./start-cybernova.sh          # Start everything via Docker
#   ./start-cybernova.sh --dev    # Start backend locally + Docker deps
#   ./start-cybernova.sh --stop   # Stop everything
# ═════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
err()   { echo -e "${RED}[ERR]${NC}   $1"; }

# ── Check .env exists ──────────────────────────────────────────────────────
check_env() {
    if [ ! -f ".env" ]; then
        err ".env file not found!"
        err "Create .env with the required secrets (see .env for reference)."
        exit 1
    fi
    ok ".env file found"
}

# ── Start via Docker Compose ───────────────────────────────────────────────
start_docker() {
    info "Starting CyberNova with Docker Compose..."
    docker compose up -d postgres redis backend frontend mailhog
    info "Waiting for services to become healthy (this may take up to 60s)..."
    sleep 5

    # Wait for backend healthcheck
    local max_wait=60 elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' cybernova-backend 2>/dev/null || echo "starting")
        if [ "$status" = "healthy" ]; then
            ok "Backend is healthy"
            break
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    if [ $elapsed -ge $max_wait ]; then
        err "Backend healthcheck timed out — check docker logs cybernova-backend"
        exit 1
    fi

    echo ""
    info "===================== CyberNova is RUNNING ====================="
    echo ""
    printf "  ${CYAN}%-30s${NC} %s\n" "Service" "URL"
    printf "  ${CYAN}%-30s${NC} %s\n" "-------" "---"
    printf "  %-30s %s\n" "Marketing Site"     "http://localhost:8888"
    printf "  %-30s %s\n" "Frontend SPA"       "http://localhost:8888/app/"
    printf "  %-30s %s\n" "Backend API"        "http://localhost:8000"
    printf "  %-30s %s\n" "Health Check"       "http://localhost:8000/health"
    printf "  %-30s %s\n" "PostgreSQL"         "localhost:5432"
    printf "  %-30s %s\n" "Redis"              "localhost:6379"
    printf "  %-30s %s\n" "MailHog (Email)"    "http://localhost:8025"
    echo ""

    # Quick API test
    local api_ok
    api_ok=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/health 2>/dev/null || echo "000")
    if [ "$api_ok" = "200" ]; then
        ok "API health check passed"
    else
        err "API not responding (HTTP $api_ok)"
    fi
}

# ── Dev mode: run backend locally + Docker deps ────────────────────────────
start_dev() {
    info "Starting CyberNova dev mode..."
    info "Starting postgres + redis via Docker..."
    docker compose up -d postgres redis mailhog
    sleep 3

    info "Starting backend locally..."
    cd "$SCRIPT_DIR"
    python -m uvicorn cybernova.main:app --host 0.0.0.0 --port 8000 --reload &
    BACKEND_PID=$!
    echo "$BACKEND_PID" > /tmp/cybernova-backend.pid

    info "Starting frontend dev server..."
    cd "$SCRIPT_DIR/cybernova-frontend"
    npm run dev &
    FRONTEND_PID=$!
    echo "$FRONTEND_PID" > /tmp/cybernova-frontend.pid

    cd "$SCRIPT_DIR"
    echo ""
    info "===================== CyberNova (DEV) ====================="
    printf "  %-30s %s\n" "Backend API"     "http://localhost:8000"
    printf "  %-30s %s\n" "Frontend Dev"    "http://localhost:5173"
    printf "  %-30s %s\n" "MailHog"         "http://localhost:8025"
    echo ""
    info "Stop with: $0 --stop"
}

# ── Stop everything ────────────────────────────────────────────────────────
stop_all() {
    info "Stopping Docker services..."
    docker compose down --remove-orphans 2>/dev/null || true

    # Kill local dev processes
    if [ -f /tmp/cybernova-backend.pid ]; then
        kill "$(cat /tmp/cybernova-backend.pid)" 2>/dev/null || true
        rm -f /tmp/cybernova-backend.pid
    fi
    if [ -f /tmp/cybernova-frontend.pid ]; then
        kill "$(cat /tmp/cybernova-frontend.pid)" 2>/dev/null || true
        rm -f /tmp/cybernova-frontend.pid
    fi
    ok "All services stopped"
}

# ── Main ───────────────────────────────────────────────────────────────────
case "${1:-}" in
    --dev)
        check_env
        start_dev
        ;;
    --stop)
        stop_all
        ;;
    --help|-h)
        echo "Usage: $0 [--dev|--stop|--help]"
        echo "  (no args)   Start production stack via Docker"
        echo "  --dev       Start deps in Docker + backend/frontend locally"
        echo "  --stop      Stop all services"
        ;;
    *)
        check_env
        start_docker
        ;;
esac
