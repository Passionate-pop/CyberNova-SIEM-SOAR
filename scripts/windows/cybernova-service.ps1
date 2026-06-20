# ============================================================================
# CyberNova Background Service Manager
# Runs all CyberNova services (Docker stack + agent) invisibly.
# Designed to be launched by Task Scheduler at system startup.
# No terminal window. No user interaction. Just works.
# ============================================================================
#Requires -RunAsAdministrator

param(
    [string]$InstallDir = "$env:ProgramFiles\CyberNova",
    [switch]$Stop,
    [switch]$Status
)

$ErrorActionPreference = "Continue"
$LogFile = Join-Path $InstallDir "logs\service.log"
$PidFile = Join-Path $InstallDir "logs\agent.pid"

# --- Logging ---------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    try {
        if (-not (Test-Path (Split-Path $LogFile))) {
            New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force | Out-Null
        }
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    } catch { }
}

# --- Stop mode -------------------------------------------------------------
if ($Stop) {
    Write-Log "Stopping CyberNova services..."

    # Stop host agent
    if (Test-Path $PidFile) {
        $pid = Get-Content $PidFile -ErrorAction SilentlyContinue
        if ($pid) {
            try {
                $proc = Get-Process -Id ([int]$pid) -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id ([int]$pid) -Force -ErrorAction SilentlyContinue
                    Write-Log "Stopped host agent (PID $pid)"
                }
            } catch { }
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }

    # Stop all processes named host_agent or cybernova_agent
    Get-Process -Name "python*" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($_.CommandLine -match "host_agent|cybernova_agent") {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped agent process PID $($_.Id)"
            }
        } catch { }
    }

    # Stop Docker Compose stack
    Push-Location $InstallDir
    docker compose down 2>$null
    Pop-Location

    Write-Log "CyberNova services stopped."
    exit 0
}

# --- Status mode -----------------------------------------------------------
if ($Status) {
    Write-Log "Checking CyberNova status..."

    # Check Docker
    $dockerRunning = docker info 2>$null | Out-Null; $LASTEXITCODE -eq 0

    # Check containers
    $containers = docker ps --format "{{.Names}}:{{.Status}}" 2>$null
    $backendOk = $containers -match "cybernova-backend.*Up"
    $postgresOk = $containers -match "cybernova-postgres.*Up"
    $redisOk = $containers -match "cybernova-redis.*Up"
    $frontendOk = $containers -match "cybernova-frontend.*Up"

    Write-Host "CyberNova Status:" -ForegroundColor Cyan
    Write-Host "  Docker:        $(if ($dockerRunning) {'Running'} else {'STOPPED'})" -ForegroundColor $(if ($dockerRunning) {'Green'} else {'Red'})
    Write-Host "  PostgreSQL:    $(if ($postgresOk) {'Running'} else {'STOPPED'})" -ForegroundColor $(if ($postgresOk) {'Green'} else {'Red'})
    Write-Host "  Redis:         $(if ($redisOk) {'Running'} else {'STOPPED'})" -ForegroundColor $(if ($redisOk) {'Green'} else {'Red'})
    Write-Host "  Backend API:   $(if ($backendOk) {'Running'} else {'STOPPED'})" -ForegroundColor $(if ($backendOk) {'Green'} else {'Red'})
    Write-Host "  Frontend:      $(if ($frontendOk) {'Running'} else {'STOPPED'})" -ForegroundColor $(if ($frontendOk) {'Green'} else {'Red'})

    # Check API health
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 3 -ErrorAction Stop
        Write-Host "  API Health:    OK" -ForegroundColor Green
    } catch {
        Write-Host "  API Health:    UNREACHABLE" -ForegroundColor Red
    }

    exit 0
}

# --- Main service loop -----------------------------------------------------
Write-Log "============================================"
Write-Log "CyberNova Background Service Starting"
Write-Log "============================================"
Write-Log "Install dir: $InstallDir"

# Verify install directory exists
if (-not (Test-Path $InstallDir)) {
    Write-Log "Install directory not found: $InstallDir" "ERROR"
    exit 1
}

# --- Phase 1: Start Docker Desktop -----------------------------------------
Write-Log "Phase 1: Ensuring Docker is running..."

# Check if Docker is available
$dockerAvailable = $false
try {
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $dockerAvailable = $true }
} catch { }

if (-not $dockerAvailable) {
    Write-Log "Docker not running, starting Docker Desktop..."

    $dockerExe = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path $dockerExe)) {
        $dockerExe = "$env:ProgramFiles(x86)\Docker\Docker\Docker Desktop.exe"
    }

    if (Test-Path $dockerExe) {
        Start-Process -FilePath $dockerExe -WindowStyle Hidden
        Write-Log "Docker Desktop launched, waiting up to 120s..."

        # Wait for Docker to become available (up to 120s)
        for ($i = 0; $i -lt 120; $i++) {
            Start-Sleep -Seconds 2
            try {
                docker info 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Docker is ready (waited ${i}x2 seconds)"
                    $dockerAvailable = $true
                    break
                }
            } catch { }
        }
    } else {
        Write-Log "Docker Desktop not found at $dockerExe" "ERROR"
        Write-Log "Please install Docker Desktop from https://docker.com/products/docker-desktop" "ERROR"
        exit 1
    }
}

if (-not $dockerAvailable) {
    Write-Log "Docker failed to start after 120s" "ERROR"
    exit 1
}

# --- Phase 2: Start Docker Compose stack -----------------------------------
Write-Log "Phase 2: Starting CyberNova Docker stack..."

Push-Location $InstallDir

# Ensure secrets directory exists
$secretsDir = Join-Path $InstallDir "secrets"
if (-not (Test-Path $secretsDir)) {
    New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
}

# Generate default secrets if missing
$secretFiles = @(
    @{ Name = "jwt_secret.txt"; Value = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")) },
    @{ Name = "admin_password.txt"; Value = "Admin2026!" },
    @{ Name = "agent_password.txt"; Value = "AgentSecure2026!" },
    @{ Name = "postgres_password.txt"; Value = "postgres-pass-123" },
    @{ Name = "redis_password.txt"; Value = "redis-pass-123" },
    @{ Name = "smtp_password.txt"; Value = "" }
)

foreach ($secret in $secretFiles) {
    $path = Join-Path $secretsDir $secret.Name
    if (-not (Test-Path $path)) {
        Set-Content -Path $path -Value $secret.Value -NoNewline
        Write-Log "Generated secret: $($secret.Name)"
    }
}

# Generate .env if missing
$envFile = Join-Path $InstallDir ".env"
if (-not (Test-Path $envFile)) {
    $jwtSecret = Get-Content (Join-Path $secretsDir "jwt_secret.txt") -Raw
    @"
JWT_SECRET=$jwtSecret
SECRET_KEY=$jwtSecret
ADMIN_PASSWORD=Admin2026!
AGENT_PASSWORD=AgentSecure2026!
ENVIRONMENT=production
LOG_LEVEL=INFO
CORS_ORIGINS=http://localhost,http://localhost:8888,http://localhost:8080
"@ | Set-Content -Path $envFile
    Write-Log "Generated .env file"
}

# Start the stack
Write-Log "Running: docker compose up -d --build"
docker compose up -d --build 2>&1 | ForEach-Object { Write-Log "  $_" }

Pop-Location

# Wait for backend health
Write-Log "Waiting for backend API to become healthy..."
$backendReady = $false
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            Write-Log "Backend API is healthy (waited ${i}x2 seconds)"
            $backendReady = $true
            break
        }
    } catch { }
}

if (-not $backendReady) {
    Write-Log "Backend API not healthy after 180s — continuing anyway (may still be starting)" "WARN"
}

# --- Phase 3: Start Host Agent ---------------------------------------------
Write-Log "Phase 3: Starting host agent..."

$agentScript = Join-Path $InstallDir "host_agent.py"
if (Test-Path $agentScript) {
    # Find Python
    $python = $null
    foreach ($p in @("python", "python3", "py")) {
        try {
            $ver = & $p --version 2>&1
            if ($ver -match "Python 3") { $python = $p; break }
        } catch { }
    }

    if ($python) {
        # Create logs directory for agent
        $agentLogDir = Join-Path $InstallDir "logs"
        if (-not (Test-Path $agentLogDir)) {
            New-Item -ItemType Directory -Path $agentLogDir -Force | Out-Null
        }

        # Start agent hidden (no terminal window)
        $agentLog = Join-Path $agentLogDir "agent.log"
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $python
        $startInfo.Arguments = "`"$agentScript`" --backend http://localhost:8000 --username admin --password Admin2026!"
        $startInfo.WorkingDirectory = $InstallDir
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $proc = [System.Diagnostics.Process]::Start($startInfo)

        # Write PID for cleanup
        Set-Content -Path $PidFile -Value $proc.Id
        Write-Log "Host agent started (PID $($proc.Id))"

        # Redirect stdout/stderr to log file in background
        $outputTask = {
            param($proc, $logFile)
            while (-not $proc.HasExited) {
                $line = $proc.StandardOutput.ReadLine()
                if ($line) {
                    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Add-Content -Path $logFile -Value "[$ts] $line" -ErrorAction SilentlyContinue
                }
            }
        }
        $null = Start-Job -ScriptBlock $outputTask -ArgumentList $proc, $agentLog
    } else {
        Write-Log "Python not found — host agent will not start" "WARN"
        Write-Log "Install Python 3.8+ from https://python.org" "WARN"
    }
} else {
    Write-Log "host_agent.py not found at $agentScript" "WARN"
}

# --- Phase 4: Health monitor loop ------------------------------------------
Write-Log "============================================"
Write-Log "CyberNova is running in background"
Write-Log "Dashboard: http://localhost:8888"
Write-Log "API:       http://localhost:8000"
Write-Log "============================================"

# Periodic health check — restart containers if they die
$checkInterval = 60  # seconds
$restartCount = 0
$maxRestarts = 10

while ($true) {
    Start-Sleep -Seconds $checkInterval

    try {
        # Check if backend container is alive
        $backendContainer = docker inspect cybernova-backend --format '{{.State.Running}}' 2>$null
        if ($backendContainer -ne "true") {
            $restartCount++
            Write-Log "Backend container is down! Restarting... (attempt $restartCount/$maxRestarts)" "WARN"

            if ($restartCount -le $maxRestarts) {
                Push-Location $InstallDir
                docker compose up -d 2>&1 | ForEach-Object { Write-Log "  $_" }
                Pop-Location
            } else {
                Write-Log "Max restarts ($maxRestarts) reached. Service needs manual intervention." "ERROR"
                # Reset counter after 30 minutes
                Start-Sleep -Seconds 1800
                $restartCount = 0
            }
        } else {
            # Reset restart counter if things are healthy
            if ($restartCount -gt 0) {
                Write-Log "Services recovered. Resetting restart counter."
                $restartCount = 0
            }
        }
    } catch {
        Write-Log "Health check error: $_" "WARN"
    }
}
