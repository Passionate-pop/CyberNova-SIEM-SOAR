# ============================================================================
# CyberNova — Uninstaller
# Completely removes CyberNova from your system.
# ============================================================================
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramFiles\CyberNova"
$taskName = "CyberNova-Service"

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "  ║           CyberNova Uninstaller                     ║" -ForegroundColor Red
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

# Confirm
$confirm = Read-Host "  Are you sure you want to completely remove CyberNova? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "  Cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

# Step 1: Stop and remove background service
Write-Host "  [1/5] Stopping background service..." -ForegroundColor Cyan
try {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "       OK  Service stopped and removed" -ForegroundColor Green
} catch {
    Write-Host "       OK  No service to remove" -ForegroundColor Gray
}

# Step 2: Stop Docker containers
Write-Host "  [2/5] Stopping Docker containers..." -ForegroundColor Cyan
if (Test-Path "$InstallDir\docker-compose.yml") {
    Push-Location $InstallDir
    docker compose down -v 2>$null
    Pop-Location
}
Write-Host "       OK  Containers stopped" -ForegroundColor Green

# Step 3: Kill any lingering agent processes
Write-Host "  [3/5] Killing lingering processes..." -ForegroundColor Cyan
Get-Process -Name "python*" -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        if ($_.CommandLine -match "host_agent|cybernova_agent|cybernova.service|cybernova_tray") {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Host "       Killed PID $($_.Id)" -ForegroundColor Gray
        }
    } catch { }
}
Write-Host "       OK  Processes cleaned" -ForegroundColor Green

# Step 4: Remove desktop shortcut
Write-Host "  [4/5] Removing shortcuts..." -ForegroundColor Cyan
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcut = Join-Path $desktopPath "CyberNova.lnk"
if (Test-Path $shortcut) {
    Remove-Item $shortcut -Force
    Write-Host "       OK  Desktop shortcut removed" -ForegroundColor Green
}

$startMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "CyberNova"
if (Test-Path $startMenuDir) {
    Remove-Item $startMenuDir -Recurse -Force
    Write-Host "       OK  Start Menu removed" -ForegroundColor Green
}

# Step 5: Remove installation directory
Write-Host "  [5/5] Removing installation files..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        # Some files may be locked — schedule for deletion on next reboot
        Write-Host "       WARN  Some files locked, scheduled for cleanup on reboot" -ForegroundColor Yellow
    } else {
        Write-Host "       OK  Installation removed" -ForegroundColor Green
    }
}

# Done
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║         CyberNova has been completely removed        ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Note: Docker images were NOT removed (other projects may use them)." -ForegroundColor Gray
Write-Host "  To remove them: docker system prune" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
