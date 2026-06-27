param(
    [string]$BackendUrl = "http://localhost:8000",
    [string]$Username = "admin",
    [string]$Password = "CMklXpm1LKHXGB7M"
)

$ErrorActionPreference = "Stop"
Write-Host "CyberNova Host Agent Deployment" -ForegroundColor Cyan

# 1. Verify backend
Write-Host "[1] Backend..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BackendUrl/health" -Method Get -TimeoutSec 10
    Write-Host "  PASS - Backend healthy" -ForegroundColor Green
} catch { Write-Host "  FAIL - $_" -ForegroundColor Red; exit 1 }

# 2. Login
Write-Host "[2] Login..." -ForegroundColor Yellow
try {
    $login = Invoke-RestMethod -Uri "$BackendUrl/api/v1/auth/login" -Method Post -ContentType "application/json" -Body (@{username=$Username;password=$Password} | ConvertTo-Json)
    Write-Host "  PASS - Login OK" -ForegroundColor Green
} catch { Write-Host "  FAIL - $_" -ForegroundColor Red; exit 1 }

# 3. Stop existing agent process
Write-Host "[3] Stopping any existing agent..." -ForegroundColor Yellow
Get-WmiObject Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match "host_agent" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
Write-Host "  PASS - Old agent stopped" -ForegroundColor Green

# 4. Start the host agent directly
Write-Host "[4] Starting host agent..." -ForegroundColor Yellow
$agentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentScript = Join-Path $agentDir "host_agent.py"

if (-not (Test-Path $agentScript)) {
    Write-Host "  FAIL - host_agent.py not found at $agentScript" -ForegroundColor Red
    exit 1
}

$env:AGENT_USERNAME = $Username
$env:AGENT_PASSWORD = $Password
$env:PYTHONUNBUFFERED = "1"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "python.exe"
$psi.Arguments = """$agentScript"" --backend ""$BackendUrl"" --username ""$Username"" --password ""$Password"""
$psi.WorkingDirectory = $agentDir
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$process = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Seconds 3

# Check if process is still running
$running = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "  PASS - Agent started (PID: $($process.Id))" -ForegroundColor Green
} else {
    $stderr = $process.StandardError.ReadToEnd()
    Write-Host "  FAIL - Agent exited: $stderr" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "DONE - Agent is running and monitoring:" -ForegroundColor Green
Write-Host "  PID: $($process.Id)" -ForegroundColor White
Write-Host "  Backend: $BackendUrl" -ForegroundColor White
Write-Host "  Server: $env:COMPUTERNAME" -ForegroundColor White
Write-Host ""
Write-Host "Events are being sent every 30 seconds." -ForegroundColor Cyan
Write-Host "Stop agent: Get-Process python | Where-Object {`$_.CommandLine -match 'host_agent'} | Stop-Process" -ForegroundColor Gray
