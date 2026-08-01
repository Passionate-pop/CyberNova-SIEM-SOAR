# restart_agent.ps1 - Update config and restart the CyberNova agent
$CONFIG_FILE = "C:\Program Files\CyberNova\agent_config.json"

# Update config with credentials
$cfg = @{
    api_url = "http://localhost:8080"
    username = "admin_boss"
    password = "Admin2026!"
    installed_at = (Get-Date).ToString("o")
    agent_version = "3.0.0"
}
$cfg | ConvertTo-Json | Set-Content -Path $CONFIG_FILE -Force
Write-Host "Config updated:" -ForegroundColor Green
Get-Content $CONFIG_FILE -Encoding UTF8

# Stop old agent
Write-Host "`nStopping old agent..." -ForegroundColor Yellow
Stop-ScheduledTask -TaskName "CyberNova-HostDefender" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Kill any lingering python processes from old agent
Get-Process python* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Start new agent
Write-Host "Starting agent..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName "CyberNova-HostDefender" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 8

# Check if running
$task = Get-ScheduledTask -TaskName "CyberNova-HostDefender" -ErrorAction SilentlyContinue
Write-Host "`nTask state: $($task.State)" -ForegroundColor Cyan

$procs = Get-Process python* -ErrorAction SilentlyContinue
if ($procs) {
    Write-Host "Agent running! PIDs:" -ForegroundColor Green
    $procs | Select-Object Id, ProcessName, StartTime | Format-Table
} else {
    Write-Host "WARNING: No Python process found!" -ForegroundColor Red
}

# Check logs
Write-Host "`n--- Agent Logs ---" -ForegroundColor Cyan
$logFile = "C:\Program Files\CyberNova\logs\agent.log"
if (Test-Path $logFile) {
    Get-Content $logFile -Tail 15 -Encoding UTF8
} else {
    Write-Host "No log file found" -ForegroundColor Yellow
}
