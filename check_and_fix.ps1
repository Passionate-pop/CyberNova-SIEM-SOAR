# Check and Restart CyberNova
$ErrorActionPreference = "Continue"

Write-Host "=== Checking CyberNova Status ===" -ForegroundColor Cyan

# Check if docker is running
Write-Host "Checking Docker..." -ForegroundColor Yellow

# Try to check containers
try {
    $containers = docker ps --format "{{.Names}} {{.Status}}" 2>$null
    if ($containers -match "cybernova") {
        Write-Host "CyberNova containers running:" -ForegroundColor Green
        $containers | Where-Object { $_ -match "cybernova" }
    } else {
        Write-Host "CyberNova NOT running - starting..." -ForegroundColor Red
        docker compose up -d
        Start-Sleep 10
    }
} catch {
    Write-Host "Docker error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Testing CyberNova API..." -ForegroundColor Yellow

# Test API
try {
    $test = Invoke-RestMethod -Uri "http://localhost:8000/" -TimeoutSec 5 -ErrorAction Stop
    Write-Host "[OK] CyberNova is running: $($test.name) v$($test.version)" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] CyberNova API not responding" -ForegroundColor Red
    Write-Host "        Try: docker compose up -d" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Testing authentication..." -ForegroundColor Yellow

# Test login
try {
    $user = $env:CYBERNOVA_USER
    $pass = $env:CYBERNOVA_PASSWORD
    if (-not $user -or -not $pass) {
        Write-Host "[WARN] CYBERNOVA_USER / CYBERNOVA_PASSWORD not set, trying .env fallback..." -ForegroundColor Yellow
        $user = "admin"
        $pass = "admin"
    }
    $login = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -Body (@{username=$user; password=$pass} | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
    Write-Host "[OK] Login successful" -ForegroundColor Green
    Write-Host "     Token: $($login.access_token.Substring(0,20))..." -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Login failed: $_" -ForegroundColor Red
    
    # Check if user exists, if not create one
    Write-Host ""
    Write-Host "Trying to create admin user..." -ForegroundColor Yellow
    
    # Check for any user creation endpoint or just restart with seed
    docker compose exec -T app python -c "
import asyncio
from cybernova.database.postgres.session import get_db_session
from cybernova.database.postgres.models import User
from cybernova.core.utils.helpers import new_id, utcnow
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

async def create_admin():
    async for db in get_db_session():
        # Check if admin exists
        from sqlalchemy import select
        result = await db.execute(select(User).where(User.username == 'admin'))
        existing = result.scalar_one_or_none()
        
        if existing:
            print('Admin user already exists')
            return
            
        # Create admin
        import os
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
        admin = User(
            id=new_id(),
            username='admin',
            email='admin@cybernova.local',
            password_hash=pwd_context.hash(admin_password),
            is_active=True,
            is_superuser=True,
            tenant_id='default',
            created_at=utcnow()
        )
        db.add(admin)
        await db.commit()
        print('Admin user created with password: admin')

asyncio.run(create_admin())
" 2>&1 | Select-Object -Last 5
}

Write-Host ""
Write-Host "=== Ready ===" -ForegroundColor Green
Write-Host "Now run: python host_agent.py --backend http://localhost:8000 --username `$env:CYBERNOVA_USER --password `$env:CYBERNOVA_PASSWORD" -ForegroundColor Cyan