# CyberNova Host Defender - Windows
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
        exit 1
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
        exit 1
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

    # Step 5: Register service
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

    # Telemetry test
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
                $saved | ConvertTo-Json | Set-Content -Path $CONFIG_FILE -Force
                Write-Host "        Device token saved" -ForegroundColor Green
            } catch {}
        }
    } catch {
        Write-Host "        WARNING: telemetry failed" -ForegroundColor Yellow
    }

    Write-Host "`n  ============================================"
    Write-Host "  CyberNova Agent installed!"
    Write-Host "  ============================================"
    Write-Host ""
    Write-Host "  Installed:  $INSTALL_DIR"
    Write-Host "  API:        $API_URL"
    Write-Host ""
    exit 0

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
    $body = @{
        system = $hostInfo
        system_detail = @{ cpu_usage = $cpu; memory_usage = $mem }
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
