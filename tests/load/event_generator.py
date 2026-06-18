"""
Realistic security event generator for load testing.
Produces events mimicking Suricata, Windows EVTX, firewall logs, and EDR telemetry.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4
import random


SEVERITIES = ["info", "low", "medium", "high", "critical"]
EVENT_TYPES = [
    "suricata_alert", "windows_security", "firewall_deny",
    "edr_process", "edr_network", "auth_failure",
    "dns_query", "web_proxy", "vpn_connect",
    "email_phishing",
]
SOURCE_IPS = [
    "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "172.16.0.50", "172.16.0.100",
    "203.0.113.1", "198.51.100.2", "185.220.101.3",
]
DEST_IPS = [
    "10.0.0.100", "10.0.0.200",
    "192.168.1.1", "192.168.1.254",
    "8.8.8.8", "1.1.1.1",
]
USERS = ["alice", "bob", "charlie", "dave", "eve", "admin", "svc_backup", "svc_monitor"]
RULE_NAMES = [
    "brute_force", "malware_signature", "ransomware_behavior",
    "port_scan", "dns_tunneling", "data_exfil",
    "phishing_url", "anomalous_login", "powershell_obfuscated",
]


def _weighted_severity() -> str:
    r = random.random()
    if r < 0.40:
        return "info"
    elif r < 0.70:
        return "low"
    elif r < 0.88:
        return "medium"
    elif r < 0.97:
        return "high"
    else:
        return "critical"


def _random_ip(pool: List[str]) -> str:
    if random.random() < 0.8:
        return random.choice(pool)
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_load_event(load_run_id: str, sequence: int) -> Dict[str, Any]:
    event_type = random.choice(EVENT_TYPES)
    severity = _weighted_severity()
    sent_at = datetime.now(timezone.utc).isoformat()

    event: Dict[str, Any] = {
        "_load_test": {
            "run_id": load_run_id,
            "sequence": sequence,
            "sent_at": sent_at,
        },
        "event_id": str(uuid4()),
        "event_type": event_type,
        "timestamp": sent_at,
        "severity": severity,
        "source_ip": _random_ip(SOURCE_IPS),
        "dest_ip": _random_ip(DEST_IPS),
        "source_port": random.randint(1024, 65535),
        "dest_port": random.choice([22, 80, 443, 3389, 445, 8080, 8443]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "user": random.choice(USERS),
        "rule_name": random.choice(RULE_NAMES),
        "risk_score": random.randint(0, 100),
        "message": f"Load test event #{sequence} type={event_type} severity={severity}",
    }

    if event_type == "suricata_alert":
        event["alert_id"] = str(uuid4())
        event["action"] = random.choice(["alert", "drop", "reject"])
        event["signature"] = f"ET {severity.upper()} {random.choice(['MALWARE', 'SCAN', 'POLICY'])} event #{sequence}"
        event["category"] = random.choice(["attempted-recon", "malware-command-and-control", "not-suspicious"])
    elif event_type == "auth_failure":
        event["logon_type"] = random.choice([2, 3, 8, 10])
        event["failure_reason"] = random.choice(["bad_password", "account_locked", "mfa_failed"])
        event["user"] = random.choice(USERS)
    elif event_type == "edr_process":
        event["process_name"] = random.choice(["powershell.exe", "cmd.exe", "wscript.exe", "rundll32.exe"])
        event["parent_process"] = "explorer.exe"
        event["command_line"] = f"-enc {''.join(random.choices('abcdef0123456789', k=32))}" if random.random() < 0.3 else "-nop -exec bypass"
        event["pid"] = random.randint(1000, 99999)
    elif event_type == "firewall_deny":
        event["action"] = "deny"
        event["rule_name"] = random.choice(["block-malicious-ips", "deny-all-inbound", "block-unknown"])
    elif event_type == "dns_query":
        event["query"] = random.choice([
            "evil.example.com", "malware.xyz", "phishing.tech",
            "google.com", "update.microsoft.com",
        ])
        event["response_code"] = random.choice([0, 1, 2, 3])

    return event


def generate_event_batch(
    load_run_id: str,
    start_sequence: int,
    count: int,
) -> List[Dict[str, Any]]:
    return [generate_load_event(load_run_id, start_sequence + i) for i in range(count)]
