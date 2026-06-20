@echo off
:: ============================================================================
:: CyberNova — One-Click Installer
:: Double-click this to install CyberNova as a real app (24/7, no terminal)
:: ============================================================================

echo.
echo  ============================================
echo   CyberNova — One-Click Installer
echo   Installs as a real Windows application
echo   (Desktop icon, auto-start, runs 24/7)
echo  ============================================
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] This installer needs Administrator access.
    echo.
    echo  Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Check Docker
docker --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] Docker Desktop is required but not installed.
    echo.
    echo  Download Docker Desktop from:
    echo  https://docker.com/products/docker-desktop
    echo.
    echo  Install Docker, restart your PC, then run this again.
    echo.
    pause
    exit /b 1
)

:: Run the PowerShell installer
echo  Starting installer...
echo.
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0scripts\windows\install.ps1" -SourceDir "%~dp0"
