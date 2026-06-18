@echo off
color 0a
cls
echo.
echo  #########  #########  ########  #########  ###    ###  ######### 
echo  #         #        #  #      #  #      #   #    #   #        # 
echo  #         #        #  #      #  #      #   #    #   #        # 
echo  #########  ########   #      #  #########  ###    ###  ######### 
echo       #   #         #  #      #       #   #    #   #        # 
echo       #   #         #  #      #       #   #    #   #        # 
echo  #########  #########  ########  #########  ###    ###  ######### 
echo.
echo          ONE-CLICK SECURITY PLATFORM
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run as Administrator
    pause
    exit /b 1
)

cd /d "%~dp0"

:: Check Docker
docker info >nul 2>&1
if %errorLevel% neq 0 (
    echo Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    timeout /t 30 /nobreak
    docker info >nul 2>&1
    if %errorLevel% neq 0 (
        echo [ERROR] Docker not running
        pause
        exit /b 1
    )
)

:: Fix/Build
docker compose down >nul 2>&1
docker compose rm -f >nul 2>&1
docker compose build

:: Start
docker compose up -d

:: Wait API
for /L %%i in (1,1,30) do (
    curl -s http://localhost:8000/health >nul
    if !errorLevel! equ 0 goto :api_ok
    timeout /t 1 /nobreak
)
:api_ok

:: Start Frontend
cd cybernova-frontend
start "" cmd /c "npm run dev"
cd ..

:: Start Security Agent
start "" pythonw "%~dp0host_agent.py"

timeout /t 5 /nobreak

:: Ready
echo.echo  #########  #########  #########  #########  ######### 
echo.
echo           READY!
echo.
echo   Dashboard:   http://localhost:5173
  echo   API:         http://localhost:8000
  echo   SOAR:        Built-in
  echo.
  echo   Security Agent: Running
  echo.
  echo  #########  #########  #########  #########  ######### 
start http://localhost:5173
echo Press key to exit...
pause >nul