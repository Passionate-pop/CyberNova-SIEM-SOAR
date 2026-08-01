"""Inject test alerts into the CyberNova backend for immediate dashboard display."""
import json
import requests

API = "http://localhost:8000"
TOKEN_FILE = "login.json"

with open(TOKEN_FILE) as f:
    auth = json.load(f)
token = auth["access_token"]

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
}

events = [
    {
        "event_type": "suspicious_file",
        "severity": "critical",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "CRITICAL: run_update.bat - dangerous_extension:.bat in Downloads",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "run_update.bat",
            "file_path": "C:/Users/HP/Downloads/run_update.bat",
            "findings": ["dangerous_extension:.bat"],
            "risk_score": 90,
        },
    },
    {
        "event_type": "suspicious_file",
        "severity": "critical",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "CRITICAL: invoice.pdf.exe - double extension (disguised executable)",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "invoice.pdf.exe",
            "file_path": "C:/Users/HP/Downloads/invoice.pdf.exe",
            "findings": ["double_extension", "disguised_executable"],
            "risk_score": 85,
        },
    },
    {
        "event_type": "suspicious_file",
        "severity": "high",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "HIGH: cache_7f3d.dat - high entropy file (possible encoded payload)",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "cache_7f3d.dat",
            "file_path": "C:/Users/HP/AppData/Local/Temp/cache_7f3d.dat",
            "findings": ["high_entropy"],
            "risk_score": 60,
        },
    },
    {
        "event_type": "suspicious_file",
        "severity": "high",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "HIGH: system_utility.exe - executable in user Downloads folder",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "system_utility.exe",
            "file_path": "C:/Users/HP/Downloads/system_utility.exe",
            "findings": ["executable_in_user_path"],
            "risk_score": 70,
        },
    },
    {
        "event_type": "suspicious_file",
        "severity": "high",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "HIGH: install_update.ps1 - dangerous script extension in Downloads",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "install_update.ps1",
            "file_path": "C:/Users/HP/Downloads/install_update.ps1",
            "findings": ["dangerous_extension:.ps1"],
            "risk_score": 55,
        },
    },
    {
        "event_type": "startup_item",
        "severity": "high",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "HIGH: CyberNovaDemo Run key added for persistence",
        "log_type": "startup_item",
        "source_ip": "10.0.0.5",
        "details": {
            "registry_key": "HKCU:/Software/Microsoft/Windows/CurrentVersion/Run",
            "value_name": "CyberNovaDemo",
            "value_data": "powershell.exe -WindowStyle Hidden -Command Start-Sleep 10",
            "findings": ["registry_persistence"],
            "risk_score": 65,
        },
    },
    {
        "event_type": "startup_item",
        "severity": "high",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "HIGH: SystemHelper.lnk - startup folder persistence item",
        "log_type": "startup_item",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "SystemHelper.lnk",
            "file_path": "C:/Users/HP/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/SystemHelper.lnk",
            "findings": ["startup_persistence"],
            "risk_score": 70,
        },
    },
    {
        "event_type": "suspicious_file",
        "severity": "high",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "HIGH: invoice_01.docm - macro-enabled document in Temp folder",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "invoice_01.docm",
            "file_path": "C:/Users/HP/AppData/Local/Temp/invoice_01.docm",
            "findings": ["macro_doc_in_temp"],
            "risk_score": 55,
        },
    },
    {
        "event_type": "suspicious_file",
        "severity": "medium",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "MEDIUM: backup_data.zip - large archive in Downloads (possible staging)",
        "log_type": "suspicious_file",
        "source_ip": "10.0.0.5",
        "details": {
            "file_name": "backup_data.zip",
            "file_path": "C:/Users/HP/Downloads/backup_data.zip",
            "findings": ["large_archive"],
            "risk_score": 40,
        },
    },
    {
        "event_type": "suspicious_network",
        "severity": "medium",
        "source": "host_agent",
        "hostname": "DESKTOP",
        "message": "MEDIUM: External connections established to google.com, github.com",
        "log_type": "suspicious_network",
        "source_ip": "10.0.0.5",
        "details": {
            "connections": ["google.com:443", "github.com:443"],
            "count": 2,
            "findings": ["external_connections"],
            "risk_score": 30,
        },
    },
]

print("=" * 60)
print("Injecting test alerts into CyberNova backend...")
print("=" * 60)

# First try the pipeline ingest endpoint
print("\n--- Method 1: Pipeline ingest endpoint ---")
payload = {
    "source": "host_agent",
    "source_type": "agent",
    "events": events,
}
try:
    r = requests.post(f"{API}/api/v1/pipeline/ingest", json=payload, headers=headers, timeout=15)
    print(f"Pipeline ingest: {r.status_code}")
    print(f"Response: {r.text[:200]}")
except Exception as e:
    print(f"Pipeline ingest failed: {e}")

# Try agent ingest endpoint individually
print("\n--- Method 2: Agent ingest endpoint (individual events) ---")
success_count = 0
for event in events:
    payload = {"events": [event], "source": "host_agent", "source_type": "agent"}
    try:
        r = requests.post(f"{API}/api/v1/ingest/agent", json=payload, headers=headers, timeout=15)
        msg = f"  [{r.status_code}] {event['event_type']}/{event['severity']}"
        if r.status_code in (200, 202):
            msg += " OK"
            success_count += 1
        else:
            msg += f" {r.text[:80]}"
        print(msg)
    except Exception as e:
        print(f"  [ERR] {event['event_type']}: {e}")

print(f"\n{'=' * 60}")
print(f"Sent {len(events)} events, {success_count} accepted")
print(f"{'=' * 60}")
print(f"\nCheck the dashboard at: http://localhost:8080/app/")
print(f"Or Alerts page:        http://localhost:8080/app/alerts")
