from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

log = logging.getLogger("cybernova.agent_download")
router = APIRouter(tags=["Agent Download"])

AGENT_DIST_DIR = Path("dist/agent")
SUPPORTED_ARCHS = {"x86_64", "aarch64", "amd64", "arm64"}
ARCH_NORMALIZE = {"amd64": "x86_64", "arm64": "aarch64"}


def _resolve_arch(arch: str) -> str:
    return ARCH_NORMALIZE.get(arch, arch)


def _normalize_arch(arch: str) -> str:
    a = _resolve_arch(arch)
    if a not in SUPPORTED_ARCHS:
        raise HTTPException(status_code=400, detail=f"Unsupported arch: {arch}. Supported: {', '.join(sorted(SUPPORTED_ARCHS))}")
    return a


def _find_binaries(base_dir: Path) -> list[dict]:
    binaries = []
    if not base_dir.exists():
        return binaries
    for f in base_dir.iterdir():
        if not f.is_file() or f.name.startswith("."):
            continue
        if f.suffix in (".sha256", ".rb", ".rpm", ".deb", ".msi"):
            continue
        name = f.name
        if not name.startswith("cybernova-agent"):
            continue
        parts = name.replace("cybernova-agent-", "").rsplit(".", 1)
        stem = parts[0]
        f".{parts[1]}" if len(parts) > 1 else ""
        meta = stem.split("-")
        arch = None
        version = None
        for m in meta:
            if m in SUPPORTED_ARCHS or m in ARCH_NORMALIZE:
                arch = _resolve_arch(m)
            if m.startswith("v"):
                version = m[1:]
        if arch and version:
            sha_path = f.with_suffix(f.suffix + ".sha256")
            sha256 = sha_path.read_text().strip() if sha_path.exists() else ""
            binaries.append({
                "filename": f.name,
                "arch": arch,
                "version": version,
                "size_bytes": f.stat().st_size,
                "sha256": sha256,
                "download_url": f"/api/v1/agent/download/{arch}/{version}",
                "checksum_url": f"/api/v1/agent/checksum/{arch}/{version}",
            })
    return binaries


@router.get("/agent.ps1", response_class=PlainTextResponse, summary="Download Windows agent script")
async def get_windows_agent():
    return PlainTextResponse(WINDOWS_AGENT.strip())


@router.get("/agent.sh", response_class=PlainTextResponse, summary="Download Linux agent script")
async def get_linux_agent():
    return PlainTextResponse(LINUX_AGENT.strip())


@router.get("/downloads/agent", summary="Download EDR agent binary (legacy)")
async def download_agent_binary(
    platform: str = Query("linux", pattern="^(linux|windows)$"),
):
    binary_path = Path("agent/dist") / f"cybernova-edr-agent{'.exe' if platform == 'windows' else ''}"
    if binary_path.exists():
        return FileResponse(
            str(binary_path),
            media_type="application/octet-stream",
            filename=f"cybernova-edr-agent{'.exe' if platform == 'windows' else ''}",
        )
    return JSONResponse(
        status_code=404,
        content={"error": f"Binary not found for {platform}. Build with agent/pyinstaller_build.py first."},
    )


@router.get("/downloads/agent/version", summary="Get latest agent version (legacy)")
async def agent_version():
    return {
        "version": "1.0.0",
        "release_date": "2026-05-14",
        "download_url": "/agent/downloads/agent",
        "checksum_url": "/agent/downloads/agent/sha256",
        "changelog": "- Initial release\n- Process, network, system info collection\n- Heartbeat and health reporting\n- Configurable collection intervals",
    }


@router.get("/api/v1/agent/versions", summary="List all available agent binaries")
async def list_agent_versions(
    arch: Optional[str] = Query(None, description="Filter by architecture"),
    version: Optional[str] = Query(None, description="Filter by version"),
):
    binaries = _find_binaries(AGENT_DIST_DIR)
    if arch:
        try:
            a = _normalize_arch(arch)
            binaries = [b for b in binaries if b["arch"] == a]
        except HTTPException:
            pass
    if version:
        binaries = [b for b in binaries if b["version"] == version]
    return {"binaries": sorted(binaries, key=lambda b: b["version"], reverse=True)}


@router.get("/api/v1/agent/download/{arch}", summary="Download latest agent binary for architecture")
async def download_latest(arch: str):
    a = _normalize_arch(arch)
    binaries = _find_binaries(AGENT_DIST_DIR)
    matched = sorted(
        [b for b in binaries if b["arch"] == a],
        key=lambda b: b["version"],
        reverse=True,
    )
    if not matched:
        raise HTTPException(status_code=404, detail=f"No binaries found for arch: {arch}")
    latest = matched[0]
    return await _serve_binary(latest["filename"])


@router.get("/api/v1/agent/download/{arch}/{version}", summary="Download specific agent version")
async def download_version(arch: str, version: str):
    a = _normalize_arch(arch)
    binaries = _find_binaries(AGENT_DIST_DIR)
    matched = [b for b in binaries if b["arch"] == a and b["version"] == version]
    if not matched:
        raise HTTPException(status_code=404, detail=f"Binary not found: {arch} v{version}")
    return await _serve_binary(matched[0]["filename"])


@router.get("/api/v1/agent/checksum/{arch}/{version}", summary="Get SHA256 checksum for agent binary")
async def get_checksum(arch: str, version: str):
    a = _normalize_arch(arch)
    binaries = _find_binaries(AGENT_DIST_DIR)
    matched = [b for b in binaries if b["arch"] == a and b["version"] == version]
    if not matched:
        raise HTTPException(status_code=404, detail=f"Binary not found: {arch} v{version}")
    return {
        "filename": matched[0]["filename"],
        "arch": a,
        "version": version,
        "sha256": matched[0]["sha256"],
        "size_bytes": matched[0]["size_bytes"],
    }


async def _serve_binary(filename: str) -> FileResponse:
    path = AGENT_DIST_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Binary file not found on disk: {filename}")
    return FileResponse(
        str(path),
        media_type="application/octet-stream",
        filename=filename,
        headers={
            "X-Checksum-SHA256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "X-Content-Size": str(path.stat().st_size),
        },
    )


WINDOWS_AGENT = r"""# CyberNova Host Defender - Windows
# Install:  $env:CYBERNOVA_API_URL="http://SERVER:8888"; irm http://SERVER:8888/agent.ps1 | iex
# Manual:   powershell -ExecutionPolicy Bypass -File "C:\Program Files\CyberNova\hostdefender.ps1"

$API_URL = if ($env:CYBERNOVA_API_URL) { $env:CYBERNOVA_API_URL } else { "http://localhost:8888" }
$INSTALL_DIR = "$env:ProgramFiles\CyberNova"
$CONFIG_FILE = "$INSTALL_DIR\agent_config.json"
$AGENT_FILE = "$INSTALL_DIR\hostdefender.ps1"
$LOG_DIR = "$INSTALL_DIR\logs"
$LOG_FILE = "$LOG_DIR\agent.log"

# ==================================================
#  INSTALL MODE -- runs when piped via iex ($PSScriptRoot is empty)
# ==================================================
if ([string]::IsNullOrEmpty($PSScriptRoot)) {

    $ErrorActionPreference = "Stop"

    Write-Host "`n  =========================================="
    Write-Host "  CyberNova - Security Agent Installer"
    Write-Host "  ==========================================`n"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  [ERROR] This needs Administrator access!" -ForegroundColor Red
        Write-Host "  Right-click PowerShell -> Run as administrator`n" -ForegroundColor Yellow
        pause
        return
    }

    # Step 1: Create directory
    Write-Host "  [1/5] Creating install directory..." -ForegroundColor White
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
    Write-Host "        OK  $INSTALL_DIR" -ForegroundColor Green

    # Step 2: Download agent
    Write-Host "  [2/5] Saving agent..." -ForegroundColor White
    $dlHeaders = @{}
    if ($env:CYBERNOVA_API_KEY) { $dlHeaders["X-API-Key"] = $env:CYBERNOVA_API_KEY }
    Invoke-WebRequest -Uri "$API_URL/agent.ps1" -OutFile $AGENT_FILE -Headers $dlHeaders -TimeoutSec 30 -UseBasicParsing
    if (-not (Test-Path $AGENT_FILE)) {
        Write-Host "        FAILED: agent file not saved" -ForegroundColor Red
        return
    }
    Write-Host "        OK  $AGENT_FILE" -ForegroundColor Green

    # Step 3: Save config
    Write-Host "  [3/5] Saving configuration..." -ForegroundColor White
    $cfg = @{ api_url = $API_URL; installed_at = (Get-Date).ToString("o") }
    if ($env:CYBERNOVA_TOKEN) { $cfg["token"] = $env:CYBERNOVA_TOKEN }
    $cfg | ConvertTo-Json | Set-Content -Path $CONFIG_FILE -Force
    Write-Host "        OK" -ForegroundColor Green

    # Step 4: Desktop shortcut
    Write-Host "  [4/5] Creating desktop shortcut..." -ForegroundColor White
    try {
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\CyberNova Agent.lnk")
        $lnk.TargetPath = "powershell.exe"
        $lnk.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AGENT_FILE`""
        $lnk.Description = "CyberNova Security Agent"
        $lnk.IconLocation = "shell32.dll,47"
        $lnk.Save()
        Write-Host "        OK" -ForegroundColor Green
    } catch {
        Write-Host "        Warning: shortcut failed (non-critical)" -ForegroundColor Yellow
    }

    # Connectivity test
    Write-Host "`n  Testing connectivity..." -ForegroundColor White
    try {
        $r = Invoke-RestMethod -Uri "$API_URL/health" -TimeoutSec 10
        if ($r.status -eq "healthy") {
            Write-Host "        Backend: healthy" -ForegroundColor Green
        } else {
            Write-Host "        Backend: $($r.status)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "        WARNING: not reachable at $API_URL" -ForegroundColor Yellow
    }

    # Telemetry test — run BEFORE starting the scheduled task so device_token
    # is saved to config before the background agent starts.
    Write-Host "  Testing telemetry..." -ForegroundColor White
    try {
        $body = @{
            system = @{ hostname = $env:COMPUTERNAME; os_type = "windows"; agent_version = "2.0.0"; cpu_usage = 0; memory_usage = 0 }
            heartbeat_interval = 5
            sequence_number = 0
            timestamp = (Get-Date).ToString("o")
        } | ConvertTo-Json -Depth 5 -Compress
        $h = @{ "Content-Type" = "application/json" }
        if ($env:CYBERNOVA_TOKEN) { $h["Authorization"] = "Bearer " + $env:CYBERNOVA_TOKEN }
        $resp = Invoke-RestMethod -Uri "$API_URL/api/v1/agent/telemetry" -Method POST -Body $body -Headers $h -TimeoutSec 10
        Write-Host "        OK - device_id=$($resp.device_id) registered=$($resp.device_registered)" -ForegroundColor Green
        if ($resp.device_token) {
            Write-Host "        Saving device token to config..." -ForegroundColor Green
            try {
                $saved = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
                $saved.token = $resp.device_token
                $saved | ConvertTo-Json -Depth 5 | Set-Content -Path $CONFIG_FILE -Force
                Write-Host "        Device token saved" -ForegroundColor Green
            } catch {}
        }
    } catch {
        Write-Host "        WARNING: telemetry failed" -ForegroundColor Yellow
    }

    # Step 5: Register service — STARTED AFTER config has the device_token
    Write-Host "  [5/5] Registering auto-start service..." -ForegroundColor White
    $taskName = "CyberNova-HostDefender"
    $taskOk = $false
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AGENT_FILE`"" `
            -WorkingDirectory $INSTALL_DIR
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
            -StartWhenAvailable -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $taskName -Action $action `
            -Trigger @(
                New-ScheduledTaskTrigger -AtStartup
                New-ScheduledTaskTrigger -AtLogOn
            ) `
            -Principal $principal -Settings $settings `
            -Description "CyberNova Host Defender - 24/7 security monitoring" -Force
        Start-Sleep -Seconds 1
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 3
        $info = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($info -and $info.State -eq "Running") {
            $taskOk = $true
            Write-Host "        OK (scheduled task running)" -ForegroundColor Green
        } else {
            Write-Host "        Warning: task state=$($info.State)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "        Warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Fallback: start agent directly if scheduled task failed
    if (-not $taskOk) {
        Write-Host "        Starting agent in background..." -ForegroundColor Yellow
        try {
            $proc = Start-Process -FilePath "powershell.exe" `
                -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AGENT_FILE`"" `
                -WindowStyle Hidden -PassThru
            Start-Sleep -Seconds 3
            $proc.Refresh()
            if ($proc.HasExited) {
                Write-Host "        Warning: agent exited. Run manually: powershell -ExecutionPolicy Bypass -File `"$AGENT_FILE`"" -ForegroundColor Yellow
            } else {
                Write-Host "        OK (background PID=$($proc.Id))" -ForegroundColor Green
            }
        } catch {
            Write-Host "        Warning: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host "`n  ============================================"
    Write-Host "  CyberNova Agent installed!"
    Write-Host "  ============================================"
    Write-Host ""
    Write-Host "  Installed:  $INSTALL_DIR"
    Write-Host "  API:        $API_URL"
    Write-Host ""
    return

} else {

# ==================================================
#  MONITOR MODE -- background service
# ==================================================
$ErrorActionPreference = "SilentlyContinue"

# Read config
if (Test-Path $CONFIG_FILE) {
    try {
        $cfg = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
        if ($cfg.api_url) { $API_URL = $cfg.api_url }
    } catch {}
}

# Read token from env or config
$TOKEN = $env:CYBERNOVA_TOKEN
if (-not $TOKEN -and (Test-Path $CONFIG_FILE)) {
    try {
        $cfg = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
        if ($cfg.token) { $TOKEN = $cfg.token }
    } catch {}
}

$headers = @{ "Content-Type" = "application/json" }
if ($TOKEN) { $headers["Authorization"] = "Bearer " + $TOKEN }

$INTERVAL = 5

# Helper: log to file
function Write-Log([string]$msg) {
    try {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $LOG_FILE -Value "[$ts] $msg" -ErrorAction SilentlyContinue
    } catch {}
}

Write-Log "Starting - host=$env:COMPUTERNAME api=$API_URL"

# Gather system info (each wrapped to prevent crash)
$hn = try { $env:COMPUTERNAME } catch { "unknown" }
$osCap = try { (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption } catch { "Windows" }
$osVer = try { (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Version } catch { "" }
$myIp = try { (Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress } catch { "127.0.0.1" }
$myIps = try { @(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | ForEach-Object { $_.IPAddress }) } catch { @() }
$myMacs = try { @(Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.Status -eq "Up" } | ForEach-Object { $_.MacAddress }) } catch { @() }
$buildNum = try { (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).BuildNumber } catch { "" }

$hostInfo = @{
    hostname = $hn
    os_type = "windows"
    os_version = $osVer
    ip_addresses = $myIps
    mac_addresses = $myMacs
    kernel_version = $buildNum
    agent_version = "2.0.0"
}

$script:seq = 0
$script:knownUsb = @{}
$script:fimBaseline = @{}
$script:regBaseline = @{}
$script:seenFiles = @{}

function Send-Telemetry([hashtable]$extra) {
    $script:seq++
    $cpu = try { (Get-CimInstance Win32_Processor -EA SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average } catch { 0 }
    $mem = try { $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue; [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1) } catch { 0 }
    $hostInfo["cpu_usage"] = $cpu
    $hostInfo["memory_usage"] = $mem
    $body = @{
        system = $hostInfo
        heartbeat_interval = $INTERVAL
        sequence_number = $script:seq
        timestamp = (Get-Date).ToString("o")
    }
    if ($extra -and $extra.Count -gt 0) { $body += $extra }
    try {
        $json = $body | ConvertTo-Json -Depth 5 -Compress
        $resp = Invoke-RestMethod -Uri "$API_URL/api/v1/agent/telemetry" -Method POST -Body $json -Headers $headers -TimeoutSec 10
        Write-Log "Telemetry OK seq=$($script:seq) device=$($resp.device_id)"
        if ($resp.device_token) {
            $TOKEN = $resp.device_token
            $headers["Authorization"] = "Bearer " + $TOKEN
            try {
                $c = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
                $c.token = $resp.device_token
                $c | ConvertTo-Json | Set-Content -Path $CONFIG_FILE -Force
                Write-Log "Device token upgraded"
            } catch {}
        }
    } catch {
        Write-Log "Telemetry FAILED: $($_.Exception.Message)"
    }
}

function Send-SecurityEvent([string]$type, [string]$msg, [string]$sev, [hashtable]$extra) {
    $body = @{
        source = "agent"
        hostname = $hn
        event_type = $type
        message = $msg
        timestamp = (Get-Date).ToString("o")
        ip_address = $myIp
        os_type = "windows"
        severity = $sev
    }
    if ($extra) { $body += $extra }
    try {
        $json = $body | ConvertTo-Json -Depth 3 -Compress
        Invoke-RestMethod -Uri "$API_URL/api/v1/ingest/event" -Method POST -Body $json -Headers $headers -TimeoutSec 5
        Write-Log "Event sent: $type"
    } catch {
        Write-Log "Event FAILED: $type - $($_.Exception.Message)"
    }
}

function Check-Usb {
    $current = @{}
    try {
        Get-CimInstance -Class Win32_USBControllerDevice -EA SilentlyContinue | ForEach-Object {
            $dep = $_.Dependent -replace '.*="(.*?)".*', '$1'
            $current[$dep] = $true
        }
        Get-CimInstance -Class Win32_DiskDrive -EA SilentlyContinue | Where-Object { $_.InterfaceType -eq "USB" } | ForEach-Object {
            $current["DISK_$($_.DeviceID)"] = $true
        }
    } catch {}
    if ($script:knownUsb.Count -eq 0) { $script:knownUsb = $current; return }
    foreach ($k in $current.Keys) {
        if (-not $script:knownUsb.ContainsKey($k)) {
            Send-SecurityEvent "usb_connected" "USB connected: $k" "low" @{ device = $k }
        }
    }
    foreach ($k in $script:knownUsb.Keys) {
        if (-not $current.ContainsKey($k)) {
            Send-SecurityEvent "usb_removed" "USB removed: $k" "info" @{ device = $k }
        }
    }
    $script:knownUsb = $current
}

function Check-Registry {
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $current = @{}
    foreach ($p in $regPaths) {
        try {
            $items = Get-ItemProperty -Path $p -EA SilentlyContinue
            if ($items) {
                $current[$p] = ($items.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "|"
            }
        } catch {}
    }
    if ($script:regBaseline.Count -eq 0) { $script:regBaseline = $current; return }
    foreach ($k in $current.Keys) {
        if ($script:regBaseline[$k] -and $script:regBaseline[$k] -ne $current[$k]) {
            Send-SecurityEvent "registry_changed" "Registry modified: $k" "high" @{ registry_key = $k }
        }
    }
    $script:regBaseline = $current
}

function Check-Fim {
    $targets = @(
        "$env:WINDIR\System32\drivers\etc\hosts",
        "$env:WINDIR\System32\config\SAM",
        "$env:WINDIR\System32\config\SECURITY"
    )
    if ($script:fimBaseline.Count -eq 0) {
        foreach ($f in $targets) {
            if (Test-Path $f) {
                try {
                    $h = [System.IO.File]::OpenRead($f)
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    $hash = [BitConverter]::ToString($sha.ComputeHash($h)).Replace("-", "")
                    $h.Close()
                    $script:fimBaseline[$f] = $hash
                } catch {}
            }
        }
        return
    }
    foreach ($f in $targets) {
        if (-not (Test-Path $f)) { continue }
        try {
            $h = [System.IO.File]::OpenRead($f)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $cur = [BitConverter]::ToString($sha.ComputeHash($h)).Replace("-", "")
            $h.Close()
            if ($script:fimBaseline[$f] -and $script:fimBaseline[$f] -ne $cur) {
                Send-SecurityEvent "file_changed" "FIM: $f hash changed" "high" @{ file = $f }
                $script:fimBaseline[$f] = $cur
            }
        } catch {}
    }
}

Write-Log "Monitoring $hn ($myIp)"
Write-Host "CyberNova monitoring $hn ($myIp)" -ForegroundColor Green

$cycle = 0
while ($true) {
    $cycle++
    Check-Usb
    Check-Registry
    $extra = @{}
    if ($cycle % 2 -eq 0) {
        Check-Fim
        # Process list
        $procs = @()
        try {
            Get-Process -EA SilentlyContinue | Select-Object -First 100 | ForEach-Object {
                $procs += @{ pid = $_.Id; name = $_.ProcessName; memory_mb = [math]::Round($_.WorkingSet64 / 1MB, 1); event_type = "process_running" }
            }
        } catch {}
        $extra["processes"] = $procs
        # Network connections
        $conns = @()
        try {
            Get-NetTCPConnection -EA SilentlyContinue | Select-Object -First 100 | ForEach-Object {
                $conns += @{ local_ip = $_.LocalAddress; local_port = $_.LocalPort; remote_ip = $_.RemoteAddress; remote_port = $_.RemotePort; protocol = "tcp" }
            }
        } catch {}
        $extra["connections"] = $conns
    }
    Send-Telemetry $extra
    Start-Sleep -Seconds $INTERVAL
}

}
"""


LINUX_AGENT = '''#!/usr/bin/env python3
# CyberNova Host Defender v2 -- Linux
# Install:  CYBERNOVA_API_URL=http://SERVER:8000 curl -s http://SERVER:8000/agent.sh | python3
# Manual:   python3 /opt/cybernova/cyberhost.py
import hashlib, json, os, socket, sys, time, urllib.request, re, subprocess
from datetime import datetime, timezone
from pathlib import Path

API_URL = os.environ.get("CYBERNOVA_API_URL", "http://localhost:8000")
API_KEY = os.environ.get("CYBERNOVA_API_KEY", "")
INTERVAL = 5
HOSTNAME = socket.gethostname()
_SEQ = 0

INSTALL_DIR = "/opt/cybernova"
CONFIG_FILE = os.path.join(INSTALL_DIR, "agent_config.json")
AGENT_FILE = os.path.join(INSTALL_DIR, "cyberhost.py")

def log(msg):
    print("[CyberNova] %s" % msg)

# ==================================================
#  INSTALL MODE -- when piped via curl | python3
# ==================================================
def _is_install_mode():
    try:
        f = globals().get("__file__", "")
        return not f or not os.path.isfile(f) or "<stdin>" in str(f)
    except Exception:
        return True

if _is_install_mode():
    print()
    print("  ==========================================")
    print("  CyberNova -- Security Agent Installer")
    print("  ==========================================")
    print()

    # 1. Create install directory
    print("  [1/6] Creating install directory...")
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(os.path.join(INSTALL_DIR, "logs"), exist_ok=True)
    print("        OK  %s" % INSTALL_DIR)

    # 2. Save agent to disk
    print("  [2/6] Saving agent...")
    try:
        req_headers = {}
        if API_KEY:
            req_headers["X-API-Key"] = API_KEY
        req = urllib.request.Request("%s/agent.sh" % API_URL, headers=req_headers)
        resp = urllib.request.urlopen(req, timeout=30)
        agent_code = resp.read()
        with open(AGENT_FILE, "wb") as f:
            f.write(agent_code)
        os.chmod(AGENT_FILE, 0o755)
        print("        OK")
    except Exception as e:
        print("        Download failed: %s" % e)
        print("        Saving embedded agent...")
        _launcher = [
            "#!/usr/bin/env python3",
            "import os, sys, urllib.request",
            'API_URL = "%s"' % API_URL,
            'AGENT_FILE = "%s"' % AGENT_FILE,
            "if os.path.isfile(AGENT_FILE) and os.path.getsize(AGENT_FILE) > 1000:",
            "    exec(open(AGENT_FILE).read())",
            "else:",
            "    try:",
            '        req = urllib.request.Request("%s/agent.sh" % API_URL)',
            "        resp = urllib.request.urlopen(req, timeout=30)",
            "        with open(AGENT_FILE, 'wb') as f:",
            "            f.write(resp.read())",
            "        os.chmod(AGENT_FILE, 0o755)",
            "        exec(open(AGENT_FILE).read())",
            "    except Exception as e:",
            '        print("[CyberNova] Failed: %%s" %% e)',
            "        sys.exit(1)",
        ]
        with open(AGENT_FILE, "w") as f:
            f.write("\n".join(_launcher) + "\n")
        os.chmod(AGENT_FILE, 0o755)
        print("        OK (launcher saved)")

    # 3. Save configuration
    print("  [3/6] Saving configuration...")
    config = {"api_url": API_URL, "installed_at": datetime.now(timezone.utc).isoformat()}
    _token = os.environ.get("CYBERNOVA_TOKEN", "")
    if _token:
        config["token"] = _token
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    print("        OK")

    # 4. Create .desktop file
    print("  [4/6] Creating desktop shortcut...")
    desktop_dir = os.path.expanduser("~/Desktop")
    if not os.path.isdir(desktop_dir):
        desktop_dir = os.path.expanduser("~/.local/share/applications")
    desktop_file = os.path.join(desktop_dir, "cybernova-agent.desktop")
    try:
        _desktop = """[Desktop Entry]
Name=CyberNova Agent
Comment=CyberNova Security Agent
Exec=xdg-open %s
Icon=security-high
Terminal=false
Type=Application
Categories=Security;System;
""" % API_URL
        with open(desktop_file, "w") as f:
            f.write(_desktop)
        os.chmod(desktop_file, 0o755)
        print("        OK")
    except Exception as e:
        print("        Failed: %s" % e)

    # 5. Create systemd service
    print("  [5/6] Registering auto-start service...")
    _svc = """[Unit]
Description=CyberNova Host Defender
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=10
Environment=CYBERNOVA_API_URL=%s
Environment=CYBERNOVA_API_KEY=%s
Environment=CYBERNOVA_TOKEN=%s

[Install]
WantedBy=multi-user.target
""" % (sys.executable, AGENT_FILE, API_URL, API_KEY or "", os.environ.get("CYBERNOVA_TOKEN", ""))
    service_path = "/etc/systemd/system/cyberhost.service"
    try:
        with open(service_path, "w") as f:
            f.write(_svc)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "cyberhost"], capture_output=True)
        subprocess.run(["systemctl", "start", "cyberhost"], capture_output=True)
        import time as _v_t
        _v_t.sleep(2)
        _v_check = subprocess.run(["systemctl", "is-active", "cyberhost"], capture_output=True, text=True)
        if _v_check.stdout.strip() == "active":
            print("        OK -- service running")
        else:
            print("        WARNING: service may not be running. Run: systemctl status cyberhost")
    except PermissionError:
        try:
            subprocess.run(["sudo", "tee", service_path], input=_svc.encode(), capture_output=True)
            subprocess.run(["sudo", "systemctl", "daemon-reload"], capture_output=True)
            subprocess.run(["sudo", "systemctl", "enable", "cyberhost"], capture_output=True)
            subprocess.run(["sudo", "systemctl", "start", "cyberhost"], capture_output=True)
            print("        OK (with sudo)")
        except Exception as e:
            print("        Failed: %s" % e)
            print("        Agent saved to %s" % AGENT_FILE)
    except Exception as e:
        print("        Failed: %s" % e)
        print("        Agent saved to %s" % AGENT_FILE)

    # 6. Done
    print("  [6/6] Verifying...")
    try:
        req2 = urllib.request.Request("%s/health" % API_URL)
        urllib.request.urlopen(req2, timeout=5)
        print("        Backend: OK")
    except Exception:
        print("        Backend: not reachable (will retry)")

    print()
    print("  ============================================")
    print("  CyberNova installed and running!")
    print("  ============================================")
    print()
    print("  Installed:  %s" % INSTALL_DIR)
    print("  Desktop:    cybernova-agent.desktop")
    print("  Auto-start: Yes (runs 24/7 via systemd)")
    print("  API:        %s" % API_URL)
    print()
    sys.exit(0)

# ==================================================
#  MONITOR MODE -- background service
# ==================================================

# Read config if exists
import math
if os.path.isfile(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        if cfg.get("api_url"):
            API_URL = cfg["api_url"]
        # Restore token from config file (persists across reboots)
        if cfg.get("token") and not os.environ.get("CYBERNOVA_TOKEN", ""):
            os.environ["CYBERNOVA_TOKEN"] = cfg["token"]
    except Exception:
        pass

def send_batch(extra=None):
    global _SEQ
    _SEQ += 1
    payload = {"system": {"hostname": HOSTNAME, "os_type": "linux",
                "agent_version": "2.0.0", "cpu_usage": 0.0, "memory_usage": 0.0},
               "heartbeat_interval": INTERVAL, "sequence_number": _SEQ,
               "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    if extra: payload.update(extra)
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request("%s/api/v1/agent/telemetry" % API_URL, data=data,
            headers={"Content-Type": "application/json"})
        global CONFIG_FILE
        TOKEN = os.environ.get("CYBERNOVA_TOKEN", "")
        API_KEY = os.environ.get("CYBERNOVA_API_KEY", "")
        if TOKEN: req.add_header("Authorization", "Bearer %s" % TOKEN)
        elif API_KEY: req.add_header("X-API-Key", API_KEY)
        resp = urllib.request.urlopen(req, timeout=10)
        # Parse response for device_token -- upgrade from user JWT to device token
        try:
            body = json.loads(resp.read().decode("utf-8"))
            dt = body.get("device_token", "")
            if dt:
                log("Received device_token -- upgrading auth")
                # Save to config file and update env
                cfg = {}
                if os.path.isfile(CONFIG_FILE):
                    with open(CONFIG_FILE) as f:
                        cfg = json.load(f)
                cfg["token"] = dt
                cfg["api_url"] = API_URL
                with open(CONFIG_FILE, "w") as f:
                    json.dump(cfg, f, indent=2)
                os.environ["CYBERNOVA_TOKEN"] = dt
                log("Device token saved and activated")
        except Exception:
            pass
    except Exception as e:
        log("Batch send failed: %s" % e)

def send_event(event_type, message, severity="info", extra=None):
    event = {"source": "agent", "hostname": HOSTNAME, "event_type": event_type,
             "message": message[:500], "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
             "ip_address": socket.gethostbyname(socket.gethostname()),
             "os_type": "linux", "severity": severity}
    if extra: event.update(extra)
    try:
        data = json.dumps(event).encode("utf-8")
        req = urllib.request.Request("%s/api/v1/ingest/event" % API_URL, data=data,
            headers={"Content-Type": "application/json"})
        TOKEN = os.environ.get("CYBERNOVA_TOKEN", "")
        API_KEY = os.environ.get("CYBERNOVA_API_KEY", "")
        if TOKEN: req.add_header("Authorization", "Bearer %s" % TOKEN)
        elif API_KEY: req.add_header("X-API-Key", API_KEY)
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log("Send failed: %s" % e)

def get_processes():
    procs = []
    try:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit(): continue
            try:
                cmd = (p / "comm").read_text().strip()
                mem = int((p / "status").read_text().split("VmRSS:")[1].split()[0]) / 1024 if "VmRSS:" in (p / "status").read_text() else 0.0
                procs.append({"pid": int(p.name), "name": cmd, "memory_mb": round(mem, 1), "event_type": "process_running"})
            except OSError:
                continue
    except (OSError, PermissionError):
        log("Failed to list /proc entries")
    return procs[:200]

def get_connections():
    conns = []
    try:
        with open("/proc/net/tcp") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 4: continue
                local = parts[1].split(":")
                remote = parts[2].split(":")
                conns.append({"local_ip": ".".join(str(int(local[0][i:i+2], 16)) for i in range(0,8,2)),
                            "local_port": int(local[1], 16),
                            "remote_ip": ".".join(str(int(remote[0][i:i+2], 16)) for i in range(0,8,2)),
                            "remote_port": int(remote[1], 16), "protocol": "tcp"})
    except (OSError, FileNotFoundError):
        log("Failed to read /proc/net/tcp")
    return conns[:200]

_known_usb = set()

def scan_usb():
    devices = set()
    usb_path = Path("/sys/bus/usb/devices")
    if usb_path.exists():
        for entry in usb_path.iterdir():
            if entry.name.count("-") >= 1:
                vendor = (entry / "manufacturer").read_text().strip() if (entry / "manufacturer").exists() else ""
                product = (entry / "product").read_text().strip() if (entry / "product").exists() else ""
                if vendor or product: devices.add("%s:%s" % (vendor, product))
    by_id = Path("/dev/disk/by-id")
    if by_id.exists():
        for entry in by_id.iterdir():
            if "usb" in entry.name.lower(): devices.add("usb-storage:%s" % entry.name)
    return devices

def check_usb():
    global _known_usb
    current = scan_usb()
    if not _known_usb: _known_usb = current; return
    for dev in current - _known_usb:
        send_event("usb_connected", "USB connected: %s" % dev, "low", {"device": dev})
    for dev in _known_usb - current:
        send_event("usb_removed", "USB removed: %s" % dev, "info", {"device": dev})
    _known_usb = current

_keylog_names = ["keylogger", "logkeys", "pykeylogger", "hook", "getkey"]
def check_keyloggers():
    for p in Path("/proc").iterdir():
        if not p.name.isdigit(): continue
        try:
            cmd = (p / "comm").read_text().strip().lower()
            for sig in _keylog_names:
                if sig in cmd:
                    send_event("keylog_detected", "Keylogger: %s (PID %s)" % (cmd, p.name),
                              "critical", {"pid": int(p.name), "process": cmd})
                    break
            fd_dir = p / "fd"
            if fd_dir.exists():
                for fd in fd_dir.iterdir():
                    try:
                        link = os.readlink(str(fd))
                        if "input" in link and "event" in link:
                            send_event("keylog_detected", "%s reading input: %s" % (cmd, link),
                                      "high", {"pid": int(p.name), "process": cmd})
                            break
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            log("Process read error for PID %s" % p.name)
            continue

_fim_baseline = {}
_fim_targets = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/ssh/sshd_config",
                "/etc/sudoers", "/etc/crontab", "/etc/resolv.conf"]

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except (OSError, FileNotFoundError):
        log("FIM hash_file failed for %s" % path)
        return ""

def check_fim():
    global _fim_baseline
    if not _fim_baseline:
        for t in _fim_targets:
            if Path(t).is_file(): _fim_baseline[t] = hash_file(t)
        log("FIM baseline: %d files" % len(_fim_baseline))
        return
    for t, prev in list(_fim_baseline.items()):
        if not Path(t).is_file(): continue
        cur = hash_file(t)
        if cur != prev:
            send_event("file_changed", "FIM: %s hash changed" % t, "high", {"file": t})
            _fim_baseline[t] = cur

# ==================================================
#  FILE MONITORING -- Detect malicious files in user dirs
# ==================================================
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".cpl",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".py", ".rb", ".pl", ".sh", ".bash",
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".ppsm", ".potm",
    ".lnk", ".url",
    ".iso", ".vhd", ".vhdx", ".dmg",
    ".zip", ".rar", ".7z", ".gz", ".tar",
    ".jar", ".jnlp", ".gadget",
    ".drv", ".sys", ".ko",
    ".app", ".command",
}
MAGIC_BYTES = {
    b"MZ": ".exe", b"\x7fELF": ".elf", b"PK\x03\x04": ".zip",
    b"Rar!": ".rar", b"\x1f\x8b": ".gz", b"\xfd7z": ".7z",
    b"BZh": ".bz2", b"%PDF": ".pdf",
    b"\x89PNG": ".png", b"\xff\xd8\xff": ".jpg",
    b"GIF8": ".gif", b"{\n": ".json", b"<html": ".html",
}
_seen_new_files = set()
_file_scan_cycle = 0

def _get_user_dirs():
    dirs = []
    home = Path.home()
    for sub in ["Downloads", "Desktop", "Documents"]:
        p = home / sub
        if p.is_dir():
            dirs.append(str(p))
    for tmp in ["/tmp", "/var/tmp"]:
        if Path(tmp).is_dir():
            dirs.append(tmp)
    return dirs

def _detect_real_type(header):
    if not header:
        return "empty"
    for magic, ftype in MAGIC_BYTES.items():
        if header.startswith(magic):
            return ftype
    try:
        header.decode("ascii")
        return "text"
    except Exception:
        pass
    return "binary"

def _analyze_new_file(fpath):
    try:
        fpath = Path(fpath)
        if not fpath.is_file():
            return
        fsize = fpath.stat().st_size
        if fsize == 0 or fsize > 50 * 1024 * 1024:
            return
        ext = fpath.suffix.lower()
        fname = fpath.name
        parent = str(fpath.parent)
        header = b""
        try:
            with open(fpath, "rb") as f:
                header = f.read(16)
        except Exception:
            pass
        real_type = _detect_real_type(header)
        try:
            with open(fpath, "rb") as f:
                data = f.read(4096)
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                if p > 0:
                    entropy -= p * math.log2(p)
            entropy = round(entropy, 4)
        except Exception:
            entropy = 0.0
        findings = []
        risk_score = 0
        event_type = "file_scanned"
        severity = "low"
        # Dangerous extension
        if ext in DANGEROUS_EXTENSIONS:
            findings.append("dangerous_extension:%s" % ext)
            risk_score = max(risk_score, 50)
            severity = "high"
            event_type = "suspicious_file"
        # Extension mismatch (disguised file)
        if ext and real_type and real_type not in ("unknown", "error", "binary", "text"):
            if ext != real_type and real_type in DANGEROUS_EXTENSIONS:
                findings.append("extension_mismatch:%s->%s" % (ext, real_type))
                risk_score = max(risk_score, 90)
                severity = "critical"
                event_type = "suspicious_file"
        # Double extension (invoice.pdf.exe)
        if fname.count(".") >= 2:
            last_ext = fname.rsplit(".", 1)[-1].lower()
            if last_ext in DANGEROUS_EXTENSIONS:
                findings.append("double_extension:%s" % fname)
                risk_score = max(risk_score, 80)
                severity = "critical"
                event_type = "suspicious_file"
        # High entropy (encoded/encrypted)
        if fsize > 100 and entropy > 7.5:
            findings.append("high_entropy:%.2f" % entropy)
            risk_score = max(risk_score, 60)
            if severity == "low": severity = "medium"
            if event_type == "file_scanned": event_type = "suspicious_file"
        # Executable in user-writable path
        if ext in (".exe", ".dll", ".scr", ".msi", ".dmg", ".sh", ".py", ".elf"):
            home_str = str(Path.home()).lower()
            if home_str in parent.lower() or "/tmp" in parent.lower():
                findings.append("executable_in_user_path:%s" % parent)
                risk_score = max(risk_score, 70)
                severity = "high"
                event_type = "suspicious_file"
        if not findings:
            return
        sha256 = hash_file(str(fpath))
        send_event(
            event_type,
            "%s: %s -- %s" % (severity.upper(), fname, "; ".join(findings)),
            severity,
            {
                "file_name": fname,
                "file_path": str(fpath),
                "file_size": fsize,
                "sha256": sha256,
                "entropy": entropy,
                "detected_type": real_type,
                "extension": ext,
                "findings": findings,
                "risk_score": risk_score,
            },
        )
    except Exception as e:
        log("File analysis error: %s" % e)

def _seed_existing_files():
    """Pre-seed existing files so we don't flood the backend on first scan."""
    global _seen_new_files
    count = 0
    for d in _get_user_dirs():
        try:
            for root, dirs, files in os.walk(d):
                depth = root.replace(d, "").count(os.sep)
                if depth > 4:
                    dirs.clear()
                    continue
                for fname in files:
                    try:
                        _seen_new_files.add(os.path.join(root, fname))
                        count += 1
                    except Exception:
                        continue
                if count > 100000:
                    break
        except (OSError, PermissionError):
            continue
        if count > 100000:
            break
    log("Pre-indexed %d existing files for monitoring" % count)

# Pre-seed on startup so the first scan only analyzes NEW files
_seed_existing_files()

def check_new_files():
    global _seen_new_files, _file_scan_cycle
    _file_scan_cycle += 1
    # Only scan every 3rd cycle to reduce CPU usage
    if _file_scan_cycle % 3 != 0:
        return
    try:
        new_count = 0
        for d in _get_user_dirs():
            try:
                for root, dirs, files in os.walk(d):
                    # Limit depth to avoid performance issues
                    depth = root.replace(d, "").count(os.sep)
                    if depth > 4:
                        dirs.clear()
                        continue
                    for fname in files:
                        try:
                            fpath = os.path.join(root, fname)
                            if fpath in _seen_new_files:
                                continue
                            _seen_new_files.add(fpath)
                            _analyze_new_file(fpath)
                            new_count += 1
                        except Exception:
                            continue
                    # Cap: clear and re-seed to prevent unbounded growth
                    if len(_seen_new_files) > 50000:
                        _seen_new_files.clear()
                        _seed_existing_files()
            except (OSError, PermissionError):
                continue
        if new_count > 0:
            log("Scanned %d new files" % new_count)
    except Exception as e:
        log("File scan error: %s" % e)

log("CyberNova Host Defender v2 on %s" % HOSTNAME)
log("Process / Network / USB / Keylogger / FIM / File monitoring active")
while True:
    check_usb()
    check_keyloggers()
    check_fim()
    check_new_files()
    send_batch({"processes": get_processes(), "connections": get_connections()})
    time.sleep(INTERVAL)
'''
