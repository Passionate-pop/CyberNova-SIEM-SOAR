# ============================================================================
# CyberNova — Full Windows Installer
# Installs CyberNova like a real application:
#   - Program Files installation
#   - Desktop shortcut
#   - Start Menu entry
#   - Background service (starts on boot, runs 24/7)
#   - No terminal window required
# ============================================================================
#Requires -RunAsAdministrator

param(
    [string]$SourceDir = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$InstallDir = "$env:ProgramFiles\CyberNova",
    [switch]$NoDesktopIcon,
    [switch]$SkipDocker,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Colors & helpers ------------------------------------------------------
function Write-Step  { param([string]$Msg) Write-Host "  [$script:stepNum/$script:totalSteps] $Msg" -ForegroundColor Cyan; $script:stepNum++ }
function Write-OK    { param([string]$Msg) Write-Host "       OK  $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "    WARN  $Msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$Msg) Write-Host "   ERROR  $Msg" -ForegroundColor Red }

# ============================================================================
# Banner
# ============================================================================
Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                                                      ║" -ForegroundColor Cyan
Write-Host "  ║     ██████╗██╗   ██╗██████╗ ███████╗██████╗         ║" -ForegroundColor Cyan
Write-Host "  ║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗        ║" -ForegroundColor Cyan
Write-Host "  ║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝        ║" -ForegroundColor Cyan
Write-Host "  ║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗        ║" -ForegroundColor Cyan
Write-Host "  ║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║        ║" -ForegroundColor Cyan
Write-Host "  ║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝        ║" -ForegroundColor Cyan
Write-Host "  ║                                                      ║" -ForegroundColor Cyan
Write-Host "  ║        Security Platform — Full Installer            ║" -ForegroundColor Cyan
Write-Host "  ║                                                      ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$script:stepNum = 1
$script:totalSteps = 10

# ============================================================================
# Step 1: Verify running as Administrator
# ============================================================================
Write-Step "Checking administrator privileges..."
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Fail "This installer must be run as Administrator!"
    Write-Host ""
    Write-Host "  Right-click this file -> Run as administrator" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}
Write-OK "Running as Administrator"

# ============================================================================
# Step 2: Check prerequisites
# ============================================================================
Write-Step "Checking prerequisites..."

# Check Docker
$dockerInstalled = $false
try {
    $dockerVer = docker --version 2>$null
    if ($dockerVer -match "Docker") { $dockerInstalled = $true }
} catch { }

if (-not $dockerInstalled) {
    Write-Fail "Docker Desktop is NOT installed!"
    Write-Host ""
    Write-Host "  CyberNova requires Docker Desktop to run its services." -ForegroundColor Yellow
    Write-Host "  Download: https://docker.com/products/docker-desktop" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  After installing Docker Desktop, run this installer again." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}
Write-OK "Docker Desktop found: $dockerVer"

# Check Python
$pythonCmd = $null
foreach ($p in @("python", "python3", "py")) {
    try {
        $ver = & $p --version 2>&1
        if ($ver -match "Python 3\.([89]|1[0-9])") { $pythonCmd = $p; break }
    } catch { }
}

if ($pythonCmd) {
    Write-OK "Python found: $(&$pythonCmd --version 2>&1)"
} else {
    Write-Warn "Python 3.8+ not found — host agent will not run (dashboard & API still work)"
}

# ============================================================================
# Step 3: Stop existing services
# ============================================================================
Write-Step "Stopping any existing CyberNova services..."

# Stop existing background service task
$taskName = "CyberNova-Service"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-OK "Removed old scheduled task"
}

# Stop Docker compose if running in old install location
$oldLocations = @(
    "$env:USERPROFILE\CyberNova",
    "$env:USERPROFILE\Documents\CyberNova",
    (Split-Path -Parent $PSScriptRoot)
)
foreach ($loc in $oldLocations) {
    if (Test-Path "$loc\docker-compose.yml") {
        Push-Location $loc
        docker compose down 2>$null
        Pop-Location
    }
}
Write-OK "Previous services stopped"

# ============================================================================
# Step 4: Install files
# ============================================================================
Write-Step "Installing CyberNova to $InstallDir..."

if (Test-Path $InstallDir) {
    if ($Force) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Warn "Removed existing installation"
    } else {
        Write-Fail "Installation already exists at $InstallDir"
        Write-Host "  Use -Force to overwrite, or run uninstall.ps1 first" -ForegroundColor Yellow
        Write-Host ""
        pause
        exit 1
    }
}

# Create install directory structure
$dirs = @(
    $InstallDir,
    "$InstallDir\logs",
    "$InstallDir\secrets",
    "$InstallDir\cybernova",
    "$InstallDir\scripts",
    "$InstallDir\data"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

# Copy essential files
$sourceRoot = $SourceDir  # Project root (passed from CyberNova-Setup.bat or resolved default)

# Docker files
Copy-Item "$sourceRoot\docker-compose.yml" "$InstallDir\" -Force
Copy-Item "$sourceRoot\Dockerfile" "$InstallDir\" -Force
if (Test-Path "$sourceRoot\.env") { Copy-Item "$sourceRoot\.env" "$InstallDir\" -Force }
if (Test-Path "$sourceRoot\.env.production.example") { Copy-Item "$sourceRoot\.env.production.example" "$InstallDir\" -Force }

# Python backend
Copy-Item "$sourceRoot\cybernova" "$InstallDir\cybernova\" -Recurse -Force

# Scripts
Copy-Item "$sourceRoot\scripts" "$InstallDir\scripts\" -Recurse -Force

# Host agent + system tray
Copy-Item "$sourceRoot\host_agent.py" "$InstallDir\" -Force
Copy-Item "$sourceRoot\start_agent.py" "$InstallDir\" -Force
Copy-Item "$sourceRoot\cybernova_agent.py" "$InstallDir\" -Force
Copy-Item "$sourceRoot\cybernova_tray.py" "$InstallDir\" -Force

# Requirements
if (Test-Path "$sourceRoot\requirements.txt") {
    Copy-Item "$sourceRoot\requirements.txt" "$InstallDir\" -Force
}

# Frontend (pre-built)
if (Test-Path "$sourceRoot\cybernova-frontend") {
    Copy-Item "$sourceRoot\cybernova-frontend" "$InstallDir\cybernova-frontend\" -Recurse -Force
}

# Nginx config
if (Test-Path "$sourceRoot\nginx") {
    Copy-Item "$sourceRoot\nginx" "$InstallDir\nginx\" -Recurse -Force
}

# Web page (marketing site)
if (Test-Path "$sourceRoot\web-page") {
    Copy-Item "$sourceRoot\web-page" "$InstallDir\web-page\" -Recurse -Force
}

# Suricata
if (Test-Path "$sourceRoot\suricata") {
    Copy-Item "$sourceRoot\suricata" "$InstallDir\suricata\" -Recurse -Force
}

# Monitoring configs
if (Test-Path "$sourceRoot\monitoring") {
    Copy-Item "$sourceRoot\monitoring" "$InstallDir\monitoring\" -Recurse -Force
}

# Service manager scripts
Copy-Item "$PSScriptRoot\cybernova-service.ps1" "$InstallDir\scripts\windows\" -Force
Copy-Item "$PSScriptRoot\install.ps1" "$InstallDir\scripts\windows\" -Force
Copy-Item "$PSScriptRoot\uninstall.ps1" "$InstallDir\scripts\windows\" -Force

# Secrets directory (preserve existing)
if (Test-Path "$sourceRoot\secrets") {
    Copy-Item "$sourceRoot\secrets\*" "$InstallDir\secrets\" -Force -ErrorAction SilentlyContinue
}

Write-OK "Files installed ($InstallDir)"

# ============================================================================
# Step 5: Install Python dependencies
# ============================================================================
if ($pythonCmd) {
    Write-Step "Installing Python dependencies..."
    $reqFile = Join-Path $InstallDir "requirements.txt"
    if (Test-Path $reqFile) {
        & $pythonCmd -m pip install -r $reqFile --quiet 2>&1 | Out-Null
        # Install system tray dependencies
        & $pythonCmd -m pip install pystray Pillow --quiet 2>&1 | Out-Null
        Write-OK "Python packages + tray icon dependencies installed"
    } else {
        Write-Warn "requirements.txt not found — skipping pip install"
    }
} else {
    Write-Step "Skipping Python dependencies (Python not found)"
}

# ============================================================================
# Step 6: Generate CyberNova Icon
# ============================================================================
Write-Step "Generating CyberNova icon..."

$iconPath = "$InstallDir\cybernova.ico"
$iconScript = Join-Path $PSScriptRoot "generate_icon.py"

# Use the real CyberNova logo from the frontend
$logoSource = Join-Path $sourceRoot "cybernova-frontend\public\logo.png"
if (-not (Test-Path $logoSource)) {
    $logoSource = Join-Path $sourceRoot "web-page\public\logo.png"
}

if ($pythonCmd -and (Test-Path $iconScript) -and (Test-Path $logoSource)) {
    try {
        & $pythonCmd $iconScript $logoSource $iconPath 2>&1 | Out-Null
        if (Test-Path $iconPath) {
            Write-OK "CyberNova icon created from logo.png"
        } else {
            Write-Warn "Icon conversion failed — using fallback icon"
        }
    } catch {
        Write-Warn "Icon conversion failed — using fallback icon"
    }
} elseif (Test-Path $logoSource) {
    # Copy logo.png directly as the icon source
    Copy-Item $logoSource "$InstallDir\logo.png" -Force
    Write-OK "Logo copied (icon conversion needs Python)"
} else {
    Write-Warn "logo.png not found — using fallback icon"
}

# ============================================================================
# Step 7: Create Desktop Shortcut
# ============================================================================
Write-Step "Creating desktop shortcut..."

$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "CyberNova.lnk"

# Create shortcut using WScript.Shell
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "http://localhost:8080"
$shortcut.Description = "CyberNova Security Dashboard"
$shortcut.WorkingDirectory = $InstallDir

# Use the CyberNova icon (generated in Step 6, or fallback)
if (Test-Path $iconPath) {
    $shortcut.IconLocation = "$iconPath,0"
} else {
    $shortcut.IconLocation = "shell32.dll,47"
}

$shortcut.Save()
Write-OK "Desktop shortcut created"

# ============================================================================
# Step 8: Create Start Menu entry
# ============================================================================
Write-Step "Creating Start Menu entry..."

$startMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "CyberNova"
if (-not (Test-Path $startMenuDir)) {
    New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null
}

# Dashboard shortcut
$smShortcut = $shell.CreateShortcut((Join-Path $startMenuDir "CyberNova Dashboard.lnk"))
$smShortcut.TargetPath = "http://localhost:8080"
$smShortcut.Description = "Open CyberNova Dashboard"
if (Test-Path $iconPath) { $smShortcut.IconLocation = "$iconPath,0" } else { $smShortcut.IconLocation = "shell32.dll,47" }
$smShortcut.Save()

# Status shortcut
$smStatus = $shell.CreateShortcut((Join-Path $startMenuDir "CyberNova Status.lnk"))
$smStatus.TargetPath = "powershell.exe"
$smStatus.Arguments = "-ExecutionPolicy Bypass -File `"$InstallDir\scripts\windows\cybernova-service.ps1`" -Status"
$smStatus.Description = "Check CyberNova service status"
$smStatus.IconLocation = "shell32.dll,47"
$smStatus.Save()

# Stop shortcut
$smStop = $shell.CreateShortcut((Join-Path $startMenuDir "CyberNova Stop.lnk"))
$smStop.TargetPath = "powershell.exe"
$smStop.Arguments = "-ExecutionPolicy Bypass -File `"$InstallDir\scripts\windows\cybernova-service.ps1`" -Stop"
$smStop.Description = "Stop CyberNova services"
$smStop.IconLocation = "shell32.dll,47"
$smStop.Save()

# Uninstall shortcut
$smUninstall = $shell.CreateShortcut((Join-Path $startMenuDir "Uninstall CyberNova.lnk"))
$smUninstall.TargetPath = "powershell.exe"
$smUninstall.Arguments = "-ExecutionPolicy Bypass -File `"$InstallDir\scripts\windows\uninstall.ps1`""
$smUninstall.Description = "Uninstall CyberNova"
$smUninstall.IconLocation = "shell32.dll,31"
$smUninstall.Save()

Write-OK "Start Menu created (Dashboard, Status, Stop, Uninstall)"

# ============================================================================
# Step 9: Register Background Service (Task Scheduler)
# ============================================================================
Write-Step "Registering background service (auto-start on boot)..."

$serviceScript = Join-Path $InstallDir "scripts\windows\cybernova-service.ps1"

# Remove old task if exists
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Create the action: run the service manager hidden
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$serviceScript`"" `
    -WorkingDirectory $InstallDir

# Principal: SYSTEM account with highest privileges
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

# Register the task
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger @(
        New-ScheduledTaskTrigger -AtStartup
        New-ScheduledTaskTrigger -AtLogOn
    ) `
    -Principal $principal `
    -Settings $settings `
    -Description "CyberNova Security Platform — runs all services in background 24/7" `
    -Force

# Start it immediately
Start-ScheduledTask -TaskName $taskName
Write-OK "Background service registered and started"
Write-OK "CyberNova will auto-start on every boot"

# --- Register Tray Icon for User Session (starts on logon, HIDDEN) ---
if ($pythonCmd) {
    $trayTaskName = "CyberNova-Tray"
    $trayScript = Join-Path $InstallDir "cybernova_tray.py"
    
    # Use pythonw.exe (windowless) instead of python.exe to avoid terminal popup
    $pythonwCmd = $pythonCmd
    try {
        $realPath = (Get-Command $pythonCmd).Source
        $dir = Split-Path $realPath -Parent
        $pywPath = Join-Path $dir "pythonw.exe"
        if (Test-Path $pywPath) {
            $pythonwCmd = "`"$pywPath`""
            Write-OK "Using pythonw.exe for hidden tray icon"
        }
    } catch { }
    
    if (Test-Path $trayScript) {
        Unregister-ScheduledTask -TaskName $trayTaskName -Confirm:$false -ErrorAction SilentlyContinue

        $trayAction = New-ScheduledTaskAction `
            -Execute $pythonwCmd `
            -Argument "`"$trayScript`"" `
            -WorkingDirectory $InstallDir

        $trayPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Limited

        $traySettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -StartWhenAvailable `
            -MultipleInstances IgnoreNew

        Register-ScheduledTask `
            -TaskName $trayTaskName `
            -Action $trayAction `
            -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME) `
            -Principal $trayPrincipal `
            -Settings $traySettings `
            -Description "CyberNova system tray icon — shows in notification area on logon" `
            -Force

        Start-ScheduledTask -TaskName $trayTaskName
        Write-OK "System tray icon registered (auto-starts on logon, hidden)"
    }
}

# ============================================================================
# Step 10: Auto-Register Device with Backend
# ============================================================================
Write-Step "Registering this device with CyberNova backend..."

# Wait for backend to be ready
$backendReady = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $health = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($health.StatusCode -eq 200) {
            $backendReady = $true
            break
        }
    } catch { }
    Start-Sleep -Seconds 2
}

if (-not $backendReady) {
    Write-Warn "Backend not ready yet — device will register automatically when agent starts"
} else {
    Write-OK "Backend is healthy"
    
    # Login to get JWT token
    try {
        $loginBody = @{ username = "admin"; password = "Admin2026!" } | ConvertTo-Json
        $loginResp = Invoke-RestMethod `
            -Uri "http://localhost:8000/api/v1/auth/login" `
            -Method Post `
            -Body $loginBody `
            -ContentType "application/json" `
            -TimeoutSec 10
        
        $token = $loginResp.access_token
        Write-OK "Authenticated with backend"
        
        # Register this device via telemetry (auto-registers by hostname)
        $hostname = $env:COMPUTERNAME
        $telemetryBody = @{
            system = @{
                hostname = $hostname
                os_type = "windows"
                os_version = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Version
                agent_version = "3.0.0"
            }
            heartbeat_interval = 30
            sequence_number = 1
            timestamp = (Get-Date).ToString("o")
        } | ConvertTo-Json -Depth 5
        
        $telemetryResp = Invoke-RestMethod `
            -Uri "http://localhost:8000/api/v1/agent/telemetry" `
            -Method Post `
            -Body $telemetryBody `
            -ContentType "application/json" `
            -Headers @{ Authorization = "Bearer $token" } `
            -TimeoutSec 10
        
        if ($telemetryResp.device_registered) {
            Write-OK "Device registered: $hostname (ID: $($telemetryResp.device_id))"
            
            # If we got a device token, save it for the agent
            if ($telemetryResp.device_token) {
                $configPath = Join-Path $InstallDir "agent_config.json"
                $config = @{
                    api_url = "http://localhost:8000"
                    device_id = $telemetryResp.device_id
                    token = $telemetryResp.device_token
                    registered_at = (Get-Date).ToString("o")
                }
                $config | ConvertTo-Json | Set-Content -Path $configPath -Force
                Write-OK "Device token saved to agent_config.json"
            }
        } else {
            Write-OK "Device already registered: $hostname"
        }
    } catch {
        Write-Warn "Device registration failed: $($_.Exception.Message)"
        Write-Warn "Agent will register automatically when it starts and sends its first heartbeat"
    }
}

# Clean up any duplicate Run key from old persist_agent.ps1
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runKeyName = "CyberNovaHostDefender"
Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue
Write-OK "Cleaned up duplicate Run key (only scheduled task will start on boot)"

# ============================================================================
# Done!
# ============================================================================
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║           CYBERNOVA INSTALLED SUCCESSFULLY!         ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Installation: $InstallDir" -ForegroundColor White
Write-Host ""
Write-Host "  What's installed:" -ForegroundColor White
Write-Host "     Desktop icon      -> Click to open dashboard" -ForegroundColor Gray
Write-Host "     Start Menu        -> CyberNova folder with Dashboard, Status, Stop, Uninstall" -ForegroundColor Gray
Write-Host "     Background service -> Starts on boot, runs 24/7, no terminal needed" -ForegroundColor Gray
Write-Host "     Health monitor    -> Auto-restarts if anything crashes" -ForegroundColor Gray
Write-Host ""
Write-Host "  Services starting (this may take 30-60 seconds):" -ForegroundColor White
Write-Host "     Dashboard:  http://localhost:8080" -ForegroundColor Cyan
Write-Host "     API:        http://localhost:8000" -ForegroundColor Cyan
Write-Host "     Grafana:    http://localhost:3001" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Default login:  admin / Admin2026!" -ForegroundColor Yellow
Write-Host ""
Write-Host "  To uninstall:  Run uninstall.ps1 or use Start Menu" -ForegroundColor Gray
Write-Host ""

# Open dashboard after a short delay
Start-Sleep -Seconds 10
Start-Process "http://localhost:8080"



Write-Host ""
Write-Host "  Press any key to close this installer..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
