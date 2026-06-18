@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   CyberNova - Security Platform
echo   One-click Install & Run
echo ========================================
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run as Administrator
    pause
    exit /b 1
)

:: Get install dir
set "INSTALL_DIR=%ProgramFiles%\CyberNova"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo [1/5] Installing CyberNova...

:: Copy files
copy /Y "%~dp0docker-compose.yml" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0Dockerfile" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0.env" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0requirements.txt" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0host_agent.py" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0start_agent.py" "%INSTALL_DIR%\" >nul
xcopy /E /Y /Q "%~dp0cybernova" "%INSTALL_DIR%\cybernova\" >nul

echo [2/5] Setting up environment...
cd "%INSTALL_DIR%"

:: Start Docker if not running
docker info >nul 2>&1
if %errorLevel% neq 0 (
    echo Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    timeout /t 30 /nobreak >nul
)

echo [3/5] Starting CyberNova services...
docker compose up -d --build

:: Wait for backend
echo [4/5] Waiting for services...
timeout /t 15 /nobreak >nul

:: Check services
for /L %%a in (1,1,30) do (
    curl -s http://localhost:8000/health >nul 2>&1
    if !errorLevel! equ 0 goto :service_ready
    timeout /t 1 /nobreak >nul
)
:service_ready

echo [5/5] Starting Security Agent...
start "" pythonw "%INSTALL_DIR%\host_agent.py"

echo.
echo ========================================
echo   CyberNova is ready!
echo ========================================
echo.
echo URLS:
echo   Dashboard:  http://localhost:3000
echo   API:        http://localhost:8000  
echo   SOAR:       Built-in
echo.
echo The security agent is running in the background.
echo.

:: Open browser
start http://localhost:3000

pause