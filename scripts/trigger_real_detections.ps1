# CyberNova - REAL Detection Trigger Script
# This script does REAL things on your Windows machine that the
# CyberNova HOST AGENT detects in real-time.
#
# NOT fake JSON. NOT API calls.
# Real files. Real registry. Real processes.
# The host agent detects them naturally.

Write-Host ""
Write-Host "  ==========================================" -ForegroundColor Cyan
Write-Host "  CyberNova - REAL Detection Trigger" -ForegroundColor Cyan
Write-Host "  ==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  This script does REAL things on your PC that" -ForegroundColor White
Write-Host "  the CyberNova host agent detects in real-time." -ForegroundColor White
Write-Host ""
Write-Host "  NOT fake JSON - REAL Windows activity" -ForegroundColor Yellow
Write-Host "  Watch the dashboard populate LIVE!" -ForegroundColor Yellow
Write-Host ""

# Confirm
$confirm = Read-Host "  Continue? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "  Cancelled." -ForegroundColor Yellow
    exit
}

Write-Host ""
Write-Host "  Triggering detections in 3 seconds..." -ForegroundColor Gray
Start-Sleep -Seconds 3

$downloads = "$env:USERPROFILE\Downloads"
$desktop = [Environment]::GetFolderPath("Desktop")
$tempPath = [System.IO.Path]::GetTempPath()
$count = 0

# 1. Dangerous extension - Create a .bat file in Downloads
$batFile = "$downloads\run_update.bat"
@"
@echo off
echo Checking system status...
ping localhost -n 2 > nul
echo Done.
"@ | Out-File -FilePath $batFile -Encoding ASCII -Force
$count++
Write-Host "  [$count] CRITICAL  Created dangerous file: run_update.bat" -ForegroundColor Red

# 2. Double extension - Create invoice.pdf.exe (exe disguised as PDF)
$doubleExtFile = "$downloads\invoice.pdf.exe"
Copy-Item "$env:SystemRoot\System32\notepad.exe" $doubleExtFile -Force
$count++
Write-Host "  [$count] CRITICAL  Double extension: invoice.pdf.exe (disguised exe)" -ForegroundColor Red

# 3. High entropy - Create random data file in Temp
$entropyFile = "$tempPath\cache_7f3d.dat"
$stream = [System.IO.File]::OpenWrite($entropyFile)
$rng = New-Object System.Random
$buffer = New-Object byte[] 4096
for ($i = 0; $i -lt 100; $i++) {
    $rng.NextBytes($buffer)
    $stream.Write($buffer, 0, $buffer.Length)
}
$stream.Close()
$count++
Write-Host "  [$count] HIGH       High entropy file: cache_7f3d.dat (400KB random data)" -ForegroundColor Yellow

# 4. Executable in user path - Copy exe to Downloads
$exeInDownloads = "$downloads\system_utility.exe"
Copy-Item "$env:SystemRoot\System32\notepad.exe" $exeInDownloads -Force
$count++
Write-Host "  [$count] HIGH       Executable in user path: system_utility.exe in Downloads" -ForegroundColor Yellow

# 5. Script in Downloads - Create a .ps1 script in Downloads
$ps1File = "$downloads\install_update.ps1"
@"
# Update script
Write-Host "Checking for updates..."
Start-Sleep -Seconds 1
Write-Host "No updates found."
"@ | Out-File -FilePath $ps1File -Encoding ASCII -Force
$count++
Write-Host "  [$count] HIGH       Dangerous script: install_update.ps1 in Downloads" -ForegroundColor Yellow

# 6. Registry Run key - Add a persistence entry
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $existing = Get-ItemProperty -Path $regPath -Name "CyberNovaDemo" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ItemProperty -Path $regPath -Name "CyberNovaDemo" `
            -Value "powershell.exe -WindowStyle Hidden -Command Start-Sleep 10" `
            -PropertyType String -Force | Out-Null
        $count++
        Write-Host "  [$count] HIGH       Registry Run key added: CyberNovaDemo (persistence)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [SKIP] Registry write failed (may need admin)" -ForegroundColor Gray
}

# 7. Startup folder - Place shortcut
try {
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $shortcutFile = "$startupPath\SystemHelper.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutFile)
    $shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
    $shortcut.Description = "System Helper Utility"
    $shortcut.Save()
    $count++
    Write-Host "  [$count] HIGH       Startup folder item: SystemHelper.lnk (persistence)" -ForegroundColor Yellow
} catch {
    Write-Host "  [SKIP] Shortcut creation failed" -ForegroundColor Gray
}

# 8. Large archive in Downloads (staging indicator)
try {
    $archiveFile = "$downloads\backup_data.zip"
    $stream = [System.IO.File]::OpenWrite($archiveFile)
    $rng2 = New-Object System.Random
    $buf2 = New-Object byte[] 1024
    for ($i = 0; $i -lt 5120; $i++) {
        $rng2.NextBytes($buf2)
        $stream.Write($buf2, 0, $buf2.Length)
    }
    $stream.Close()
    $count++
    Write-Host "  [$count] MEDIUM     Large archive: backup_data.zip (5MB, possible staging)" -ForegroundColor Magenta
} catch {
    Write-Host "  [SKIP] Archive creation failed" -ForegroundColor Gray
}

# 9. Macro-enabled Office doc in Temp
$macroFile = "$tempPath\invoice_01.docm"
$ole2Header = [byte[]]@(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
$stream2 = [System.IO.File]::OpenWrite($macroFile)
$stream2.Write($ole2Header, 0, $ole2Header.Length)
$rng3 = New-Object System.Random
$buf3 = New-Object byte[] 256
$rng3.NextBytes($buf3)
$stream2.Write($buf3, 0, $buf3.Length)
$stream2.Close()
$count++
Write-Host "  [$count] HIGH       Macro-enabled doc in Temp: invoice_01.docm" -ForegroundColor Yellow

# 10. Open browser - Triggers external connection detection
Start-Process "https://www.google.com"
Start-Process "https://www.github.com"
$count++
Write-Host "  [$count] MEDIUM     Browser opened - external connections established" -ForegroundColor Magenta

# Done
Write-Host ""
Write-Host "  ==========================================" -ForegroundColor Green
Write-Host "  $count REAL detections triggered!" -ForegroundColor Green
Write-Host "  ==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  The host agent will detect these in its next scan cycle (~30s)." -ForegroundColor White
Write-Host "  Watch the dashboard at: http://localhost:8080/app/" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Alerts you will see:" -ForegroundColor White
Write-Host "    [CRITICAL]  run_update.bat (dangerous_extension)" -ForegroundColor Red
Write-Host "    [CRITICAL]  invoice.pdf.exe (double_extension)" -ForegroundColor Red
Write-Host "    [HIGH]      cache_7f3d.dat (high_entropy)" -ForegroundColor Yellow
Write-Host "    [HIGH]      system_utility.exe (executable_in_user_path)" -ForegroundColor Yellow
Write-Host "    [HIGH]      install_update.ps1 (dangerous_extension)" -ForegroundColor Yellow
Write-Host "    [HIGH]      CyberNovaDemo Run key (startup_item)" -ForegroundColor Yellow
Write-Host "    [HIGH]      SystemHelper.lnk (startup_item)" -ForegroundColor Yellow
Write-Host "    [HIGH]      invoice_01.docm (macro_doc_in_temp)" -ForegroundColor Yellow
Write-Host "    [MEDIUM]    backup_data.zip (large_archive)" -ForegroundColor Magenta
Write-Host "    [MEDIUM]    External connections to google.com, github.com" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
