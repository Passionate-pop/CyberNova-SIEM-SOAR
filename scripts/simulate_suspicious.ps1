<#
.SYNOPSIS
    CyberNova Detection Test — Simulates suspicious activities to verify the detection pipeline.
    All files created are BENIGN text files with suspicious names/extensions.
    No actual malware, exploits, or harmful code is executed.
.DESCRIPTION
    This script simulates the following suspicious activities:
    1. Creates .exe, .ps1, .dll files in unusual locations
    2. Launches processes with encoded commands (benign)
    3. Creates registry run keys (benign values, then cleans up)
    4. Makes network connections to test IPs
    5. Creates scheduled tasks (benign)
    6. Downloads files from URLs
    All artifacts are cleaned up at the end.
#>

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$testDir = "$env:TEMP\CyberNovaTest_$timestamp"
$artifact = @()

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " CyberNova Detection Test - $timestamp" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# Ensure test dir
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
$artifact += $testDir
Write-Host "[+] Test directory: $testDir" -ForegroundColor Yellow

# ─────────────────────────────────────────────────────
# 1. Suspicious File Creation
# ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [1/5] Creating suspicious files ---" -ForegroundColor Magenta

# "MALWARE" .exe file
$exePath = "$testDir\svchost.exe"
"BENIGN TEST FILE - NOT A REAL EXECUTABLE" | Out-File -FilePath $exePath -Force
$artifact += $exePath
Write-Host "  [+] Created: svchost.exe (masquerading as system process)" -ForegroundColor Yellow

# .ps1 script in temp
$ps1Path = "$testDir\payload.ps1"
@"
# BENIGN TEST SCRIPT - CyberNova Detection Test
Write-Host "This is a benign test script"
"@ | Out-File -FilePath $ps1Path -Force
$artifact += $ps1Path
Write-Host "  [+] Created: payload.ps1 (suspicious PowerShell script)" -ForegroundColor Yellow

# .dll in unusual location
$dllPath = "$testDir\mscorlib.dll"
"BENIGN TEST FILE - NOT A REAL DLL" | Out-File -FilePath $dllPath -Force
$artifact += $dllPath
Write-Host "  [+] Created: mscorlib.dll (DLL in temp directory)" -ForegroundColor Yellow

# .vbs script
$vbsPath = "$testDir\script.vbs"
"' BENIGN TEST SCRIPT" | Out-File -FilePath $vbsPath -Force
$artifact += $vbsPath
Write-Host "  [+] Created: script.vbs (VBScript in temp)" -ForegroundColor Yellow

# .js file
$jsPath = "$testDir\exploit.js"
"// BENIGN TEST SCRIPT" | Out-File -FilePath $jsPath -Force
$artifact += $jsPath
Write-Host "  [+] Created: exploit.js (JavaScript in temp)" -ForegroundColor Yellow

# Mimetype spoofing — rename a harmless file with double extension
$doubleExtPath = "$testDir\document.pdf.exe"
"BENIGN TEST FILE" | Out-File -FilePath $doubleExtPath -Force
$artifact += $doubleExtPath
Write-Host "  [+] Created: document.pdf.exe (double extension spoofing)" -ForegroundColor Yellow

# Batch file
$batPath = "$testDir\run.bat"
"@echo BENIGN TEST" | Out-File -FilePath $batPath -Force
$artifact += $batPath
Write-Host "  [+] Created: run.bat (batch file in temp)" -ForegroundColor Yellow

# ─────────────────────────────────────────────────────
# 2. Process Execution Simulation
# ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [2/5] Executing processes ---" -ForegroundColor Magenta

# Run powershell with encoded command (benign - just echoes text)
$encodedCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'Benign test - CyberNova detection check'"))
$proc1 = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $encodedCmd" -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 500
if (!$proc1.HasExited) { $proc1.Kill() }
Write-Host "  [+] Executed: powershell with encoded command (hidden window)" -ForegroundColor Yellow

# Run cmd.exe with ipconfig (benign system tool)
$proc2 = Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Benign test & ipconfig /all" -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 1000
if (!$proc2.HasExited) { $proc2.Kill() }
Write-Host "  [+] Executed: cmd.exe with system commands (hidden)" -ForegroundColor Yellow

# Create a process with suspicious name in test directory
$procNamePath = "$testDir\rundll32.exe"
Copy-Item -Path "$env:SystemRoot\System32\calc.exe" -Destination $procNamePath -Force
$artifact += $procNamePath
$proc3 = Start-Process -FilePath $procNamePath -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 1500
if (!$proc3.HasExited) { $proc3.Kill() }
Write-Host "  [+] Executed: renamed calc.exe -> rundll32.exe (masquerading)" -ForegroundColor Yellow

# ─────────────────────────────────────────────────────
# 3. Registry Persistence (Benign - Cleaned up)
# ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [3/5] Registry persistence simulation ---" -ForegroundColor Magenta

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "CyberNovaTest_$timestamp"
try {
    Set-ItemProperty -Path $regPath -Name $regName -Value "$testDir\svchost.exe" -ErrorAction SilentlyContinue
    Write-Host "  [+] Created: Registry Run key (will be cleaned up)" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleaned: Registry Run key removed" -ForegroundColor Green
} catch {
    Write-Host "  [-] Registry write skipped (permissions)" -ForegroundColor DarkYellow
}

# ─────────────────────────────────────────────────────
# 4. Network Activity
# ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [4/5] Network activity ---" -ForegroundColor Magenta

# Make connections to external test IPs (benign - just testing connectivity)
try {
    $testIps = @("8.8.8.8", "1.1.1.1", "185.199.108.153")  # Google DNS, Cloudflare DNS, GitHub
    foreach ($ip in $testIps) {
        $sock = New-Object System.Net.Sockets.TcpClient
        $async = $sock.BeginConnect($ip, 443, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(2000)
        if ($wait) {
            $sock.EndConnect($async)
            Write-Host "  [+] Connected to: $ip`:443" -ForegroundColor Yellow
        }
        $sock.Close()
    }
} catch {
    Write-Host "  [-] Network test skipped: $_" -ForegroundColor DarkYellow
}

# ─────────────────────────────────────────────────────
# 5. Scheduled Task (Benign - Cleaned up)
# ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [5/5] Scheduled task simulation ---" -ForegroundColor Magenta

$taskName = "CyberNovaTestTask_$timestamp"
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command Write-Host BenignTest"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  [+] Created: Scheduled task (will be cleaned up)" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleaned: Scheduled task removed" -ForegroundColor Green
} catch {
    Write-Host "  [-] Scheduled task skipped: $_" -ForegroundColor DarkYellow
}

# ─────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- Cleanup ---" -ForegroundColor Magenta

# Kill any lingering processes from test dir
Get-Process | Where-Object { $_.Path -like "$testDir\*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove all test artifacts
foreach ($item in $artifact) {
    if (Test-Path $item) {
        Remove-Item -Path $item -Force -ErrorAction SilentlyContinue
    }
}
Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  [+] All test artifacts cleaned up" -ForegroundColor Green

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Test complete! Check CyberNova dashboard for" -ForegroundColor Cyan
Write-Host " generated alerts from these activities." -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
