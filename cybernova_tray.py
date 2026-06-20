#!/usr/bin/env python3
"""
CyberNova System Tray Icon
Shows in Windows notification area. Right-click for options.
Left-click opens the dashboard in browser.
Polls for new threats and shows Windows toast notifications.
"""
import os
import json
import time
import webbrowser
import subprocess
import threading
import urllib.request
from pathlib import Path

# Try to import pystray (lightweight tray icon library)
try:
    from PIL import Image
    import pystray
    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False

INSTALL_DIR = os.environ.get("CYBERNOVA_INSTALL_DIR", str(Path(__file__).parent))
DASHBOARD_URL = "http://localhost:8888"
API_URL = "http://localhost:8000"
LOG_DIR = Path(INSTALL_DIR) / "logs"
SERVICE_SCRIPT = Path(INSTALL_DIR) / "scripts" / "windows" / "cybernova-service.ps1"


def open_dashboard():
    """Open CyberNova dashboard in default browser."""
    webbrowser.open(DASHBOARD_URL)


def check_status():
    """Quick health check."""
    try:
        resp = urllib.request.urlopen(f"{API_URL}/health", timeout=3)
        return resp.status == 200
    except Exception:
        return False


def get_status_text():
    """Get status text for tooltip."""
    if check_status():
        return "CyberNova — Online"
    return "CyberNova — Offline"


def run_service_action(action: str):
    """Run a service management action."""
    if SERVICE_SCRIPT.exists():
        subprocess.Popen(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
             "-File", str(SERVICE_SCRIPT), f"-{action}"],
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )


def start_service():
    """Start CyberNova services."""
    # Start Docker compose directly (the SYSTEM scheduled task handles boot/logon)
    try:
        subprocess.Popen(
            ["docker", "compose", "up", "-d"],
            cwd=INSTALL_DIR,
            creationflags=0x08000000
        )
    except Exception:
        pass


def stop_service():
    """Stop CyberNova services."""
    run_service_action("Stop")


def open_logs():
    """Open the logs folder."""
    if LOG_DIR.exists():
        os.startfile(str(LOG_DIR))
    else:
        os.startfile(INSTALL_DIR)


def create_image():
    """Load the tray icon image from logo.png."""
    icon_path = Path(INSTALL_DIR) / "cybernova.ico"
    if icon_path.exists():
        return Image.open(str(icon_path))
    
    # Try logo.png from install dir or frontend public
    for candidate in [
        Path(INSTALL_DIR) / "cybernova-frontend" / "public" / "logo.png",
        Path(INSTALL_DIR) / "logo.png",
        Path(INSTALL_DIR) / "web-page" / "public" / "logo.png",
    ]:
        if candidate.exists():
            return Image.open(str(candidate))
    
    # Generate a fallback 16x16 cyan square
    img = Image.new('RGBA', (16, 16), (0, 200, 240, 255))
    return img


def build_menu():
    """Build the right-click context menu."""
    items = [
        pystray.MenuItem("Open Dashboard", lambda: open_dashboard(), default=True),
        pystray.MenuItem("Check Status", lambda: _show_status()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Start Services", lambda: start_service()),
        pystray.MenuItem("Stop Services", lambda: stop_service()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("View Alerts", lambda: _open_alerts()),
        pystray.MenuItem("Open Logs", lambda: open_logs()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", lambda: icon.stop()),
    ]
    return pystray.Menu(*items)


def _show_status():
    """Show status notification."""
    status = "Online ✓" if check_status() else "Offline ✗"
    icon.notify(f"CyberNova is {status}", "CyberNova Status")


def fetch_recent_alerts():
    """Fetch recent alerts from the backend API."""
    try:
        req = urllib.request.Request(
            f"{API_URL}/api/v1/dashboard/alerts?limit=10",
            headers={"Accept": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


# Track notified alert IDs to avoid duplicates
_notified_alert_ids: set = set()

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",
}


def poll_threats(tray_icon):
    """Background thread: poll for new threats and show notifications."""
    global _notified_alert_ids
    # Wait 30s before first poll (let services start up)
    time.sleep(30)
    
    while True:
        try:
            alerts = fetch_recent_alerts()
            
            for alert in alerts:
                alert_id = str(alert.get("id", ""))
                if alert_id and alert_id not in _notified_alert_ids:
                    _notified_alert_ids.add(alert_id)
                    
                    severity = (alert.get("severity") or "medium").lower()
                    title = alert.get("title") or alert.get("rule_name") or "Security Alert"
                    message = alert.get("message") or alert.get("description") or "New threat detected"
                    icon_char = SEVERITY_ICONS.get(severity, "⚠️")
                    
                    # Show Windows notification
                    try:
                        tray_icon.notify(
                            f"{icon_char} [{severity.upper()}] {message[:200]}",
                            f"CyberNova — {title}"
                        )
                    except Exception:
                        pass
            
            # Update tooltip with threat count
            total = len(alerts)
            critical = sum(1 for a in alerts if (a.get("severity") or "").lower() == "critical")
            if critical > 0:
                tray_icon.title = f"CyberNova — {critical} critical alert(s)"
            elif total > 0:
                tray_icon.title = f"CyberNova — {total} alert(s)"
            elif check_status():
                tray_icon.title = "CyberNova — Online ✓"
            else:
                tray_icon.title = "CyberNova — Offline"
            
            # Keep notified set manageable (last 200 IDs)
            if len(_notified_alert_ids) > 200:
                _notified_alert_ids = set(list(_notified_alert_ids)[-100:])
                
        except Exception:
            pass
        
        time.sleep(15)  # Poll every 15 seconds


icon = None


def main():
    global icon
    if not HAS_PYSTRAY:
        # If pystray isn't installed, just open the dashboard
        print("pystray not installed — opening dashboard in browser")
        webbrowser.open(DASHBOARD_URL)
        return
    
    image = create_image()
    menu = build_menu()
    
    icon = pystray.Icon(
        name="CyberNova",
        icon=image,
        title=get_status_text(),
        menu=menu,
    )
    
    # Start threat poller in background (replaces old tooltip updater)
    threat_thread = threading.Thread(target=poll_threats, args=(icon,), daemon=True)
    threat_thread.start()
    
    icon.run()


if __name__ == '__main__':
    main()
