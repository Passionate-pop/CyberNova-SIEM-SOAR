# CyberNova Minifilter Driver — Installation Script
# Requires: Admin privileges, cybernova.sys + cybernova.inf in same directory

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$driverPath = Join-Path $scriptDir "cybernova.sys"
$infPath = Join-Path $scriptDir "cybernova.inf"
$serviceName = "CybernovaAV"

# Validate admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges required. Run as Administrator."
    exit 1
}

# Validate files
if (-not (Test-Path $driverPath) -or -not (Test-Path $infPath)) {
    Write-Error "cybernova.sys and cybernova.inf must be in the same directory as this script."
    exit 1
}

Write-Host "CyberNova Driver Installer v1.0" -ForegroundColor Cyan

# Stop and remove existing if present
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing CyberNova service..." -ForegroundColor Yellow
    sc.exe stop $serviceName 2>$null
    sc.exe delete $serviceName 2>$null
    Start-Sleep -Seconds 2
}

# Install via sc
Write-Host "Installing driver..." -ForegroundColor Cyan
$result = sc.exe create $serviceName type= kernel binPath= $driverPath start= demand DisplayName= "CyberNova Antivirus"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install service: $result"
    exit 1
}

# Start driver
Write-Host "Starting driver..." -ForegroundColor Cyan
sc.exe start $serviceName
if ($LASTEXITCODE -ne 2 -and $LASTEXITCODE -ne 0) {
    # Status 2 indicates the service is already started
    Write-Host "Driver started (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
}

# Verify
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "CyberNova minifilter driver is RUNNING" -ForegroundColor Green
} else {
    Write-Error "Driver not running. Status: $($svc.Status)"
    exit 1
}

# Optional: Register as boot-start driver
$choice = Read-Host "Register driver to start on boot? (y/N)"
if ($choice -eq "y") {
    sc.exe config $serviceName start= boot
    Write-Host "Driver configured to start on boot" -ForegroundColor Green
}

Write-Host "Installation complete." -ForegroundColor Green
