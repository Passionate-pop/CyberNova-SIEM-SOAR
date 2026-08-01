# CyberNova - CONTINUOUS Real Detection Trigger
# Creates fresh artifacts each cycle with UNIQUE names so the host agent
# detects them as NEW every time and keeps alerting.
#
# Run:  powershell -ExecutionPolicy Bypass -File scripts\trigger_real_detections_continuous.ps1
# Stop: Ctrl+C

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runCount = 0
$downloads = "$env:USERPROFILE\Downloads"
$tempPath = [System.IO.Path]::GetTempPath()
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

Write-Host ""
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "  CyberNova - CONTINUOUS Detection Trigger" -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Creates REAL Windows artifacts every 90 seconds" -ForegroundColor White
Write-Host "  Dashboard: http://localhost:8080/app/" -ForegroundColor Cyan
Write-Host ""

$confirm = Read-Host "  Start continuous triggering? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "  Cancelled." -ForegroundColor Yellow
    exit
}

Start-Sleep -Seconds 2

function Clean-Artifacts {
    Write-Host "  [CLEANUP] Removing old artifacts..." -ForegroundColor DarkYellow
    Remove-Item "$downloads\run_update*.bat" -Force -ErrorAction SilentlyContinue
    Remove-Item "$downloads\invoice*.pdf.exe" -Force -ErrorAction SilentlyContinue
    Remove-Item "$downloads\system_utility*.exe" -Force -ErrorAction SilentlyContinue
    Remove-Item "$downloads\install_update*.ps1" -Force -ErrorAction SilentlyContinue
    Remove-Item "$downloads\backup_data*.zip" -Force -ErrorAction SilentlyContinue
    Remove-Item "$tempPath\cache_*.dat" -Force -ErrorAction SilentlyContinue
    Remove-Item "$tempPath\invoice_*.docm" -Force -ErrorAction SilentlyContinue
    Remove-Item "$startupPath\SystemHelper*.lnk" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CyberNovaDemo*" -Force -ErrorAction SilentlyContinue
    Write-Host "  [CLEANUP] Done" -ForegroundColor Green
}

function Create-Artifacts {
    param([int]$cycle)
    $count = 0
    $tag = "$(Get-Date -Format 'HHmmss')_$cycle"

    Write-Host "  [CYCLE $cycle] Creating artifacts..." -ForegroundColor Cyan

    # 1 - Dangerous extension .bat in Downloads
    $batFile = "$downloads\run_update_$tag.bat"
    "@echo off" | Out-File -FilePath $batFile -Encoding ASCII -Force
    $count++
    Write-Host "  [$count] CRITICAL  run_update_$tag.bat" -ForegroundColor Red

    # 2 - Double extension invoice.pdf.exe
    $doubleExtFile = "$downloads\invoice_$tag.pdf.exe"
    Copy-Item "$env:SystemRoot\System32\notepad.exe" $doubleExtFile -Force
    $count++
    Write-Host "  [$count] CRITICAL  invoice_$tag.pdf.exe" -ForegroundColor Red

    # 3 - High entropy in Temp
    $entropyFile = "$tempPath\cache_$tag.dat"
    $stream = [System.IO.File]::OpenWrite($entropyFile)
    $rng = New-Object System.Random
    $buffer = New-Object byte[] 4096
    for ($i = 0; $i -lt 100; $i++) {
        $rng.NextBytes($buffer)
        $stream.Write($buffer, 0, $buffer.Length)
    }
    $stream.Close()
    $count++
    Write-Host "  [$count] HIGH       cache_$tag.dat" -ForegroundColor Yellow

    # 4 - Executable in Downloads
    $exeInDownloads = "$downloads\system_utility_$tag.exe"
    Copy-Item "$env:SystemRoot\System32\notepad.exe" $exeInDownloads -Force
    $count++
    Write-Host "  [$count] HIGH       system_utility_$tag.exe" -ForegroundColor Yellow

    # 5 - PowerShell script in Downloads
    $ps1File = "$downloads\install_update_$tag.ps1"
    "# Update script" | Out-File -FilePath $ps1File -Encoding ASCII -Force
    $count++
    Write-Host "  [$count] HIGH       install_update_$tag.ps1" -ForegroundColor Yellow

    # 6 - Registry Run key
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $regName = "CyberNovaDemo_$tag"
        $regValue = "powershell.exe -WindowStyle Hidden -Command Start-Sleep 10"
        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force | Out-Null
        $count++
        Write-Host "  [$count] HIGH       Registry Run key added" -ForegroundColor Yellow
    } catch {
        Write-Host "  [SKIP] Registry failed" -ForegroundColor Gray
    }

    # 7 - Startup folder shortcut
    try {
        $shortcutFile = "$startupPath\SystemHelper_$tag.lnk"
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutFile)
        $shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
        $shortcut.Description = "System Helper Utility"
        $shortcut.Save()
        $count++
        Write-Host "  [$count] HIGH       Startup shortcut added" -ForegroundColor Yellow
    } catch {
        Write-Host "  [SKIP] Shortcut failed" -ForegroundColor Gray
    }

    # 8 - Large archive in Downloads
    try {
        $archiveFile = "$downloads\backup_data_$tag.zip"
        $stream = [System.IO.File]::OpenWrite($archiveFile)
        $rng2 = New-Object System.Random
        $buf2 = New-Object byte[] 1024
        for ($i = 0; $i -lt 5120; $i++) {
            $rng2.NextBytes($buf2)
            $stream.Write($buf2, 0, $buf2.Length)
        }
        $stream.Close()
        $count++
        Write-Host "  [$count] MEDIUM     backup_data_$tag.zip (5MB)" -ForegroundColor Magenta
    } catch {
        Write-Host "  [SKIP] Archive failed" -ForegroundColor Gray
    }

    # 9 - Macro-enabled doc in Temp
    try {
        $macroFile = "$tempPath\invoice_$tag.docm"
        $ole2Header = [byte[]]@(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
        $stream2 = [System.IO.File]::OpenWrite($macroFile)
        $stream2.Write($ole2Header, 0, $ole2Header.Length)
        $rng3 = New-Object System.Random
        $buf3 = New-Object byte[] 256
        $rng3.NextBytes($buf3)
        $stream2.Write($buf3, 0, $buf3.Length)
        $stream2.Close()
        $count++
        Write-Host "  [$count] HIGH       invoice_$tag.docm" -ForegroundColor Yellow
    } catch {
        Write-Host "  [SKIP] Docm failed" -ForegroundColor Gray
    }

    # 10 - Open browser (only first cycle to avoid spam)
    if ($cycle -le 1) {
        Start-Process "https://www.google.com"
        Start-Process "https://www.github.com"
        $count++
        Write-Host "  [$count] MEDIUM     Browser opened" -ForegroundColor Magenta
    }

    Write-Host "  [CYCLE $cycle] Created $count artifacts!" -ForegroundColor Green
}

# ===== MAIN LOOP =====
while ($true) {
    $runCount++
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host ""
    Write-Host "  ----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [$ts] Wave #$runCount" -ForegroundColor White
    Write-Host "  ----------------------------------------------" -ForegroundColor DarkGray

    Clean-Artifacts
    Start-Sleep -Seconds 2
    Create-Artifacts -cycle $runCount

    Write-Host "  Waiting 90s for host agent to detect..."
    Write-Host "  (Press Ctrl+C to stop)"
    Start-Sleep -Seconds 90
}
