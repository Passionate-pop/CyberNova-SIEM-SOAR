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


WINDOWS_AGENT = r"""
# ═════════════════════════════════════════════════════
#  CyberNova Host Defender — Windows
#  Install:  $env:CYBERNOVA_API_URL="http://SERVER:8000"; irm http://SERVER:8000/agent.ps1 | iex
#  Manual:   powershell -ExecutionPolicy Bypass -File "C:\\Program Files\\CyberNova\\hostdefender.ps1"
# ═════════════════════════════════════════════════════
$ErrorActionPreference = "SilentlyContinue"

$API_URL = if ($env:CYBERNOVA_API_URL) { $env:CYBERNOVA_API_URL } else { "http://localhost:8000" }
$INSTALL_DIR = "$env:ProgramFiles\\CyberNova"
$CONFIG_FILE = "$INSTALL_DIR\\agent_config.json"
$AGENT_FILE = "$INSTALL_DIR\\hostdefender.ps1"

# ═════════════════════════════════════════════════════
#  INSTALL MODE — runs when piped via iex ($PSScriptRoot is empty)
# ═════════════════════════════════════════════════════
if ([string]::IsNullOrEmpty($PSScriptRoot)) {

    Write-Host "`n  ==========================================" -ForegroundColor Cyan
    Write-Host "  CyberNova — Security Agent Installer" -ForegroundColor Cyan
    Write-Host "  ==========================================`n" -ForegroundColor Cyan

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  [ERROR] This needs Administrator access!" -ForegroundColor Red
        Write-Host "  Right-click PowerShell -> Run as administrator`n" -ForegroundColor Yellow
        pause
        exit 1
    }

    Write-Host "  [1/6] Creating install directory..." -ForegroundColor White
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path "$INSTALL_DIR\\logs" -Force | Out-Null
    Write-Host "        OK  $INSTALL_DIR" -ForegroundColor Green

    Write-Host "  [2/6] Saving agent..." -ForegroundColor White
    try {
        $dlHeaders = @{}
        if ($env:CYBERNOVA_API_KEY) { $dlHeaders["X-API-Key"] = $env:CYBERNOVA_API_KEY }
        Invoke-WebRequest -Uri "$API_URL/agent.ps1" -OutFile $AGENT_FILE -Headers $dlHeaders -TimeoutSec 30 -UseBasicParsing
        Write-Host "        OK" -ForegroundColor Green
    } catch {
        Write-Host "        Download failed, saving embedded agent..." -ForegroundColor Yellow
        $content = @"
`$ErrorActionPreference = "SilentlyContinue"
`$API_URL = "$API_URL"
`$INSTALL_DIR = "$INSTALL_DIR"
`$CONFIG_FILE = "$CONFIG_FILE"
`$AGENT_FILE = "$AGENT_FILE"
if ((Get-Item `$AGENT_FILE -ErrorAction SilentlyContinue).Length -lt 1000) {
    try {
        `$h = @{}
        if (`$env:CYBERNOVA_API_KEY) { `$h["X-API-Key"] = `$env:CYBERNOVA_API_KEY }
        Invoke-WebRequest -Uri "`$API_URL/agent.ps1" -OutFile `$AGENT_FILE -Headers `$h -TimeoutSec 30 -UseBasicParsing
    } catch {}
}
if (Test-Path `$AGENT_FILE) { . `$AGENT_FILE }
"@
        Set-Content -Path $AGENT_FILE -Value $content -Force
        Write-Host "        OK (launcher saved)" -ForegroundColor Green
    }

    Write-Host "  [3/6] Saving configuration..." -ForegroundColor White
    @{ api_url = $API_URL; installed_at = (Get-Date).ToString("o") } | ConvertTo-Json | Set-Content -Path $CONFIG_FILE -Force
    Write-Host "        OK" -ForegroundColor Green

    Write-Host "  [4/6] Creating desktop shortcut..." -ForegroundColor White
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\\CyberNova Agent.lnk")
    $lnk.TargetPath = "powershell.exe"
    $lnk.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AGENT_FILE`""
    $lnk.Description = "CyberNova Security Agent"
    $lnk.IconLocation = "shell32.dll,47"
    $lnk.Save()
    Write-Host "        OK" -ForegroundColor Green

    Write-Host "  [5/6] Registering auto-start service..." -ForegroundColor White
    $taskName = "CyberNova-HostDefender"
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
    Write-Host "        OK" -ForegroundColor Green

    Write-Host "  [6/6] Starting agent..." -ForegroundColor White
    Start-ScheduledTask -TaskName $taskName
    Write-Host "        OK`n" -ForegroundColor Green

    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host "  CyberNova installed and running!" -ForegroundColor Green
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Installed:  $INSTALL_DIR" -ForegroundColor White
    Write-Host "  Desktop:    CyberNova Agent.lnk" -ForegroundColor White
    Write-Host "  Auto-start: Yes (runs 24/7, no terminal needed)" -ForegroundColor White
    Write-Host "  API:        $API_URL" -ForegroundColor Cyan
    Write-Host ""
} else {

# ═════════════════════════════════════════════════════
#  MONITOR MODE — background service
# ═════════════════════════════════════════════════════

if (Test-Path $CONFIG_FILE) {
    try {
        $cfg = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
        if ($cfg.api_url) { $API_URL = $cfg.api_url }
    } catch {}
}

$API_KEY = $env:CYBERNOVA_API_KEY
$headers = @{ "Content-Type" = "application/json" }
if ($API_KEY) { $headers["X-API-Key"] = $API_KEY }

Write-Host "CyberNova Host Defender starting..." -ForegroundColor Cyan

$info = @{
    hostname = $env:COMPUTERNAME
    os = (Get-CimInstance Win32_OperatingSystem).Caption
    os_ver = (Get-CimInstance Win32_OperatingSystem).Version
    ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress
    ips = @((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress)
    macs = @((Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).MacAddress)
    kernel = (Get-CimInstance Win32_OperatingSystem).BuildNumber
}

$script:knownUsb = @{}
$script:fimBaseline = @{}
$script:regBaseline = @{}
$script:seq = 0
$script:procCache = @{}

function Send-BatchTelemetry {
    param([hashtable]$extra = @{})
    $script:seq++
    $body = @{
        system = @{
            hostname = $info.hostname
            os_type = "windows"
            os_version = $info.os_ver
            ip_addresses = $info.ips
            mac_addresses = $info.macs
            kernel_version = $info.kernel
            cpu_usage = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
            memory_usage = (Get-CimInstance Win32_OperatingSystem | ForEach-Object { [math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize * 100, 1) })
            agent_version = "2.0.0"
        }
        heartbeat_interval = $INTERVAL
        sequence_number = $script:seq
        timestamp = (Get-Date).ToString("o")
    }
    if ($extra.Count -gt 0) { $body += $extra }
    try {
        $json = $body | ConvertTo-Json -Depth 5 -Compress
        Invoke-RestMethod -Uri "$API_URL/api/v1/agent/telemetry" -Method POST -Body $json -Headers $headers -TimeoutSec 10
    } catch {}
}

function Send-Event($type, $msg, $severity, $extra) {
    $body = @{
        source = "agent"
        hostname = $info.hostname
        event_type = $type
        message = $msg
        timestamp = (Get-Date).ToString("o")
        ip_address = $info.ip
        os_type = "windows"
        severity = $severity
    }
    if ($extra) { $body += $extra }
    try {
        $json = $body | ConvertTo-Json -Depth 3 -Compress
        Invoke-RestMethod -Uri "$API_URL/api/v1/ingest/event" -Method POST -Body $json -Headers $headers -TimeoutSec 5
    } catch {}
}

function Get-ProcessTelemetry {
    $procs = @()
    try {
        Get-Process -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
            $procs += @{
                pid = $_.Id
                name = $_.ProcessName
                command_line = ""
                user = "unknown"
                cpu_percent = 0.0
                memory_mb = [math]::Round($_.WorkingSet64 / 1MB, 1)
                path = $_.Path
                start_time = if ($_.StartTime) { $_.StartTime.ToString("o") } else { "" }
                event_type = "process_running"
            }
        }
    } catch {}
    return $procs
}

function Get-NetworkTelemetry {
    $conns = @()
    try {
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
            $conns += @{
                local_ip = $_.LocalAddress
                local_port = $_.LocalPort
                remote_ip = $_.RemoteAddress
                remote_port = $_.RemotePort
                state = $_.State
                protocol = "tcp"
            }
        }
    } catch {}
    return $conns
}

function Get-UsbDevices {
    $devices = @{}
    try {
        $usb = Get-CimInstance -Class Win32_USBControllerDevice -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Dependent -replace '.*="(.*?)".*', '$1' }
        foreach ($u in $usb) { $devices[$u] = $true }
    } catch {}
    try {
        Get-CimInstance -Class Win32_DiskDrive | Where-Object { $_.InterfaceType -eq "USB" } | ForEach-Object {
            $devices["DISK_$($_.DeviceID)"] = $true
        }
    } catch {}
    return $devices
}

function Check-Usb {
    $current = Get-UsbDevices
    if ($script:knownUsb.Count -eq 0) { $script:knownUsb = $current; return }
    foreach ($key in $current.Keys) {
        if (-not $script:knownUsb.ContainsKey($key)) {
            Send-Event "usb_connected" "USB device connected: $key" "low" @{device=$key; action="connected"}
        }
    }
    foreach ($key in $script:knownUsb.Keys) {
        if (-not $current.ContainsKey($key)) {
            Send-Event "usb_removed" "USB device removed: $key" "info" @{device=$key; action="removed"}
        }
    }
    $script:knownUsb = $current
}

$regTargets = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

function Get-RegistrySnapshot {
    $snap = @{}
    foreach ($path in $regTargets) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($items) {
                $data = $items.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }
                $snap[$path] = $data -join "|"
            }
        } catch {}
    }
    return $snap
}

function Check-Registry {
    $current = Get-RegistrySnapshot
    if ($script:regBaseline.Count -eq 0) { $script:regBaseline = $current; return }
    foreach ($key in $current.Keys) {
        $prev = $script:regBaseline[$key]
        $now = $current[$key]
        if ($prev -and $now -and $prev -ne $now) {
            Send-Event "registry_changed" "Registry modified: $key" "high" @{registry_key=$key}
        }
    }
    $script:regBaseline = $current
}

$keylogSignatures = @("keylog", "hook", "wh_keyboard", "getasynckeystate", "setwindowshookex")

function Check-Keyloggers {
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $name = $p.ProcessName.ToLower()
        foreach ($sig in $keylogSignatures) {
            if ($name -match $sig) {
                Send-Event "keylog_detected" "Possible keylogger: $name (PID $($p.Id))" "critical" @{pid=$p.Id; process=$name; signature=$sig}
                break
            }
        }
    }
    Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        public class WinAPI {
            [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr hWnd, int uCmd);
            [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
            [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
        }
"@ -ErrorAction SilentlyContinue
}

$fimTargets = @(
    "$env:WINDIR\System32\drivers\etc\hosts",
    "$env:WINDIR\System32\config\SAM",
    "$env:WINDIR\System32\config\SECURITY"
)

function Get-FileHashSha256($path) {
    try {
        $stream = [System.IO.File]::OpenRead($path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($stream)
        $stream.Close()
        return [BitConverter]::ToString($hash) -replace "-", ""
    } catch { return "" }
}

function Check-Fim {
    if ($script:fimBaseline.Count -eq 0) {
        foreach ($f in $fimTargets) {
            if (Test-Path $f) { $script:fimBaseline[$f] = Get-FileHashSha256 $f }
        }
        return
    }
    foreach ($f in $fimTargets) {
        if (-not (Test-Path $f)) { continue }
        $current = Get-FileHashSha256 $f
        $prev = $script:fimBaseline[$f]
        if ($prev -and $current -ne $prev) {
            Send-Event "file_changed" "File integrity violation: $f — hash changed" "high" @{file=$f}
            $script:fimBaseline[$f] = $current
        }
    }
}

Write-Host "Monitoring $($info.hostname) ($($info.ip))" -ForegroundColor Green
Write-Host "USB / Registry / Keylogger / File Integrity / Process / Network" -ForegroundColor Cyan

$cycle = 0
while ($true) {
    $cycle++
    Check-Usb
    Check-Registry
    $extra = @{}
    if ($cycle % 2 -eq 0) {
        Check-Keyloggers
        Check-Fim
        $extra["processes"] = Get-ProcessTelemetry
        $extra["connections"] = Get-NetworkTelemetry
    }
    Send-BatchTelemetry $extra
    Start-Sleep -Seconds $INTERVAL
}
}
"""


LINUX_AGENT = """#!/usr/bin/env python3
# CyberNova Host Defender v2 — Linux
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

# ═════════════════════════════════════════════════════
#  INSTALL MODE — when piped via curl | python3
# ═════════════════════════════════════════════════════
def _is_install_mode():
    try:
        f = globals().get("__file__", "")
        return not f or not os.path.isfile(f) or "<stdin>" in str(f)
    except Exception:
        return True

if _is_install_mode():
    print()
    print("  ==========================================")
    print("  CyberNova — Security Agent Installer")
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
        _desktop = \"\"\"[Desktop Entry]
Name=CyberNova Agent
Comment=CyberNova Security Agent
Exec=xdg-open %s
Icon=security-high
Terminal=false
Type=Application
Categories=Security;System;
\"\"\" % API_URL
        with open(desktop_file, "w") as f:
            f.write(_desktop)
        os.chmod(desktop_file, 0o755)
        print("        OK")
    except Exception as e:
        print("        Failed: %s" % e)

    # 5. Create systemd service
    print("  [5/6] Registering auto-start service...")
    _svc = \"\"\"[Unit]
Description=CyberNova Host Defender
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=10
Environment=CYBERNOVA_API_URL=%s
Environment=CYBERNOVA_API_KEY=%s

[Install]
WantedBy=multi-user.target
\"\"\" % (sys.executable, AGENT_FILE, API_URL, API_KEY or "")
    service_path = "/etc/systemd/system/cyberhost.service"
    try:
        with open(service_path, "w") as f:
            f.write(_svc)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "cyberhost"], capture_output=True)
        subprocess.run(["systemctl", "start", "cyberhost"], capture_output=True)
        print("        OK")
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

# ═════════════════════════════════════════════════════
#  MONITOR MODE — background service
# ═════════════════════════════════════════════════════

# Read config if exists
if os.path.isfile(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        if cfg.get("api_url"):
            API_URL = cfg["api_url"]
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
        if API_KEY: req.add_header("X-API-Key", API_KEY)
        urllib.request.urlopen(req, timeout=10)
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
        if API_KEY: req.add_header("X-API-Key", API_KEY)
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

log("CyberNova Host Defender v2 on %s" % HOSTNAME)
log("Process / Network / USB / Keylogger / FIM monitoring active")
while True:
    check_usb()
    check_keyloggers()
    check_fim()
    send_batch({"processes": get_processes(), "connections": get_connections()})
    time.sleep(INTERVAL)
"""
