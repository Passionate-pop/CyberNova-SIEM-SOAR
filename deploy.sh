#!/bin/bash

# ═════════════════════════════════════════════════════════════════════════════
# CyberNova SIEM - One-Command Deployment Script
# ═════════════════════════════════════════════════════════════════════════════
# Usage: ./deploy.sh [options]
#   Options:
#     --skip-build    Skip Docker build (use existing images)
#     --with-ui       Include frontend
#     --production    Enable production mode (TLS, etc.)
#     --help          Show this help
# ═════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
BACKUP_DIR="./backups"

# Parse arguments
SKIP_BUILD=false
WITH_UI=false
PRODUCTION=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --with-ui)
            WITH_UI=true
            shift
            ;;
        --production)
            PRODUCTION=true
            shift
            ;;
        --help|-h)
            echo "CyberNova Deployment Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-build    Skip Docker build"
            echo "  --with-ui       Include frontend"
            echo "  --production    Production mode"
            echo "  --help          Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║          CyberNova SIEM - Deployment Script               ║"
echo "║                    v1.0.0                                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
echo -e "${YELLOW}[1/7] Checking prerequisites...${NC}"
command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker is required but not installed. Aborting.${NC}" >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker Compose is required. Aborting.${NC}" >&2; exit 1; }

# Check .env file
echo -e "${YELLOW}[2/7] Checking configuration...${NC}"
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}No .env file found. Please create $ENV_FILE with required production variables.${NC}"
    echo -e "${YELLOW}See DEPLOYMENT_CHECKLIST.md for the required .env template.${NC}"
    exit 1
fi

# Validate critical settings
echo -e "${YELLOW}[3/7] Validating configuration...${NC}"
if grep -q "change_me\|default" "$ENV_FILE" 2>/dev/null; then
    echo -e "${RED}⚠️  WARNING: $ENV_FILE contains default/change_me values!${NC}"
    echo -e "${RED}    Please update all sensitive values before deploying to production.${NC}"
fi

# Create required directories
echo -e "${YELLOW}[4/7] Creating directories...${NC}"
mkdir -p $BACKUP_DIR
mkdir -p logs

# Stop existing containers
echo -e "${YELLOW}[5/7] Stopping existing containers...${NC}"
docker-compose down 2>/dev/null || true

# Build and start
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${YELLOW}[6/7] Building and starting services...${NC}"
    
    if [ "$WITH_UI" = true ]; then
        echo -e "${BLUE}  → Building with frontend...${NC}"
        docker-compose --profile full up -d --build
    else
        echo -e "${BLUE}  → Backend only...${NC}"
        docker-compose up -d --build
    fi
else
    echo -e "${YELLOW}[6/7] Starting services (skipping build)...${NC}"
    docker-compose up -d
fi

# Wait for services to be healthy
echo -e "${YELLOW}[7/7] Waiting for services to be healthy...${NC}"

# Check PostgreSQL
echo -n "  → PostgreSQL: "
for i in {1..30}; do
    if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
        echo -e "${GREEN}Ready${NC}"
        break
    fi
    sleep 2
done

# Check Redis
echo -n "  → Redis: "
for i in {1..15}; do
    if docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
        echo -e "${GREEN}Ready${NC}"
        break
    fi
    sleep 1
done

# Check API
echo -n "  → API: "
for i in {1..30}; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}Ready${NC}"
        break
    fi
    sleep 2
done

# Initialize database
echo -e "${YELLOW}  → Initializing database schema...${NC}"
docker-compose exec -T postgres psql -U postgres -d cybernova -f /docker-entrypoint-initdb.d/incidents.sql 2>/dev/null || \
docker exec cybernova-postgres psql -U postgres -d cybernova -c "SELECT 1" >/dev/null 2>&1 || \
    echo -e "${YELLOW}     Database schema may already exist or needs manual init${NC}"

# Get API URL
if [ "$PRODUCTION" = true ]; then
    API_URL="https://your-domain.com"
else
    API_URL="http://localhost:8000"
fi

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✓ Deployment Complete!                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLUE}API:${NC}        $API_URL"
echo -e "  ${BLUE}Health:${NC}    $API_URL/health"
echo -e "  ${BLUE}Docs:${NC}      $API_URL/docs"
echo ""
echo -e "  ${YELLOW}Default Credentials:${NC}"
echo -e "    Admin:   admin / (check AGENT_USERNAME/AGENT_PASSWORD in .env)"
echo -e "    Analyst: analyst / analyst"
echo -e "    Viewer:  viewer / viewer"
echo ""
echo -e "${RED}⚠️  SECURITY REMINDERS:${NC}"
echo "  1. Change all default passwords in .env"
echo "  2. Use TLS/HTTPS in production (expose port 443 only)"
echo "  3. Block direct access to PostgreSQL (5432) and Redis (6379) ports"
echo "  4. Set a secure JWT_SECRET"
echo ""
echo -e "${YELLOW}View logs:${NC}  docker-compose logs -f"
echo -e "${YELLOW}Stop:${NC}      docker-compose down"
echo ""
