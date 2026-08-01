@echo off
chcp 65001 >nul
title CyberNova — Live Attack Demo
color 0a

echo.
echo  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
echo ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
echo ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
echo ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
echo ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
echo  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║           LIVE ATTACK DEMO — REAL SUSPICIOUS ACTIVITY       ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

set /p USER="  Username: "
set /p PASS="  Password: "

echo.
echo [*] Logging in as %USER%...
curl -s -X POST "http://localhost:8000/api/v1/auth/login" ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"%USER%\",\"password\":\"%PASS%\"}" > login.json 2>&1

findstr /C:"access_token" login.json >nul
if errorlevel 1 (
  echo [!] Login failed! Check username/password.
  type login.json
  del login.json >nul 2>&1
  pause
  exit /b 1
)

for /f "tokens=*" %%a in ('findstr /C:access_token login.json') do set raw=%%a
set "TOKEN=%raw:~14,-2%"
del login.json >nul 2>&1
echo [+] Logged in!

echo.
echo ────────────────────────────────────────────────────────────────
echo  SENDING 13 REAL ATTACK EVENTS TO CYBERNOVA PIPELINE...
echo ────────────────────────────────────────────────────────────────

echo ^
curl -s -X POST "http://localhost:8000/api/v1/pipeline/ingest" ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -d "{\"source\":\"live_demo\",\"source_type\":\"api\",\"events\":[{\"event_type\":\"failed_login\",\"severity\":\"high\",\"message\":\"SSH brute force: 1,247 failed attempts from 45.33.32.156 to root@10.0.0.5:22 - credential stuffing\",\"source_ip\":\"45.33.32.156\",\"user\":\"root\"},{\"event_type\":\"malicious_process\",\"severity\":\"critical\",\"message\":\"Suspicious process /tmp/.systemd-boot with no parent - masquerading as system binary\",\"source_ip\":\"10.0.0.5\",\"process_name\":\".systemd-boot\"},{\"event_type\":\"unusual_process\",\"severity\":\"high\",\"message\":\"Reverse shell from 10.0.0.5:4444 to 198.51.100.20:9999 - possible C2 callback\",\"source_ip\":\"10.0.0.5\",\"dest_ip\":\"198.51.100.20\"},{\"event_type\":\"scheduled_task\",\"severity\":\"high\",\"message\":\"Cron @reboot /var/tmp/.cache-update added for www-data - persistence mechanism\",\"source_ip\":\"10.0.0.5\",\"user\":\"www-data\"},{\"event_type\":\"user_created\",\"severity\":\"high\",\"message\":\"New user supportadmin with UID 0 and sudo - possible backdoor account\",\"source_ip\":\"10.0.0.5\",\"user\":\"supportadmin\"},{\"event_type\":\"file_changed\",\"severity\":\"high\",\"message\":\"/etc/shadow accessed outside normal password change - credential harvesting\",\"source_ip\":\"10.0.0.5\"},{\"event_type\":\"encoded_powershell\",\"severity\":\"critical\",\"message\":\"Encoded PowerShell download cradle detected on Windows host\",\"source_ip\":\"10.0.0.5\"},{\"event_type\":\"tamper_detected\",\"severity\":\"critical\",\"message\":\"auditd config cleared - audit will not start on reboot, attacker covering tracks\",\"source_ip\":\"10.0.0.5\"},{\"event_type\":\"new_listener\",\"severity\":\"high\",\"message\":\"New TCP listener on 0.0.0.0:4444 - possible bind shell, no known service\",\"source_ip\":\"10.0.0.5\"},{\"event_type\":\"suspicious_network\",\"severity\":\"high\",\"message\":\"Port scan: 185.220.101.20 scanned 2,304 ports on 10.0.0.5 in 12s - reconnaissance\",\"source_ip\":\"185.220.101.20\",\"dest_ip\":\"10.0.0.5\"},{\"event_type\":\"external_connection\",\"severity\":\"high\",\"message\":\"Unknown outbound to 198.51.100.50:443 - no DNS match, possible C2 beacon\",\"source_ip\":\"10.0.0.5\",\"dest_ip\":\"198.51.100.50\"},{\"event_type\":\"suspicious_file\",\"severity\":\"high\",\"message\":\"Web shell /var/www/html/upload.php with system() + base64_decode - RCE possible\",\"source_ip\":\"192.168.1.100\"},{\"event_type\":\"phishing_in_message\",\"severity\":\"high\",\"message\":\"Email with fake login page link detected in user inbox - credential phish\",\"source_ip\":\"45.33.32.156\",\"user\":\"staff@company.com\"}]}" > response.json

echo.
echo [+] Events accepted! Pipeline processing...
echo.

:: Wait for pipeline to process
echo  ⏳ Pipeline processing: Enrichment -^> Detection -^> Alert
echo  ⏳ This takes ~10-15 seconds...
echo.

timeout /t 15 /nobreak >nul

echo.
echo ────────────────────────────────────────────────────────────────
echo  CHECKING RESULTS...
echo ────────────────────────────────────────────────────────────────
echo.

curl -s -H "Authorization: Bearer %TOKEN%" "http://localhost:8000/api/v1/dashboard/summary" > summary.json
for /f "tokens=2 delims=:," %%a in ('findstr /C:total_alerts summary.json') do set ALERTS=%%a
for /f "tokens=2 delims=:," %%a in ('findstr /C:critical summary.json') do set CRIT=%%a
for /f "tokens=2 delims=:," %%a in ('findstr /C:high summary.json'') do set HIGH=%%a
del summary.json >nul 2>&1

echo  ╔════════════════════════════════════════╗
echo  ║         ATTACK RESULTS                 ║
echo  ╠════════════════════════════════════════╣
echo  ║                                      ║
echo  ║  🔴 Critical alerts detected         ║
echo  ║  🟠 High severity alerts             ║
echo  ║  📊 Total: alerts in dashboard       ║
echo  ║                                      ║
echo  ╚════════════════════════════════════════╝
echo.

echo ────────────────────────────────────────────────────────────────
echo  WHAT TO CHECK IN THE UI:
echo ────────────────────────────────────────────────────────────────
echo.
echo  1. DASHBOARD: http://localhost:8080/app/
echo     -> Alert cards with severity badges (CRITICAL/HIGH)
echo     -> Live toast popups via WebSocket
echo     -> Security score drops as threats appear
echo.
echo  2. MONITORING: Click "Monitoring" in sidebar
echo     -> System Logs tab: RAW attack events streaming in
echo     -> Each attack shows: timestamp, level, source, message
echo     -> Events: SSH brute force, reverse shell, web shell, etc.
echo.
echo  3. WEB SOCKET: Live notifications pop up on screen
echo     ->  CRITICAL: malicious_process
echo     ->  CRITICAL: tamper_detected  
echo     ->  CRITICAL: encoded_powershell
echo.
echo ────────────────────────────────────────────────────────────────
echo  ATTACKS SENT (Check Monitoring ^> System Logs):
echo ────────────────────────────────────────────────────────────────
echo.
echo  [HIGH]     SSH brute force - 1,247 attempts from 45.33.32.156
echo  [CRITICAL] Reverse shell /tmp/.systemd-boot - C2 masquerading
echo  [HIGH]     Python reverse shell to 198.51.100.20:9999
echo  [HIGH]     Cron persistence added for www-data
echo  [HIGH]     Backdoor user 'supportadmin' with UID 0
echo  [HIGH]     /etc/shadow accessed - credential harvesting
echo  [CRITICAL] Encoded PowerShell download cradle
echo  [CRITICAL] Auditd config cleared - covering tracks
echo  [HIGH]     Bind shell listener on port 4444
echo  [HIGH]     Port scan from TOR exit node 185.220.101.20
echo  [HIGH]     C2 beacon to unknown host on port 443
echo  [HIGH]     Web shell /var/www/html/upload.php
echo  [HIGH]     Phishing email with fake login page
echo.

pause
