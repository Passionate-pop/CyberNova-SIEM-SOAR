"""
CyberNova — Suricata IDS/IPS Alert Parser
Parses Suricata EVE JSON alert logs.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.suricata")

SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

ALERT_CATEGORY_MAP = {
    "Attempted Administrator Privilege Gain": "TA0004",
    "Attempted User Privilege Gain": "TA0004",
    "Attempted Credential Access": "TA0006",
    "Unsuccessful Login Attempt": "TA0006",
    "Shellcode Detected": "TA0002",
    "Malware Detected": "TA0002",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Reconnaissance": "TA0043",
    "Executable was downloaded": "TA0005",
    "Web Application Attack": "TA0001",
    "Network Trojan": "TA0002",
}


def _parse_flow(data: Dict[str, Any], result: Dict[str, Any]) -> None:
    flow = data.get("flow", {})
    if isinstance(flow, dict):
        result["metadata"]["flow_id"] = flow.get("id", "")
        result["metadata"]["flow_state"] = flow.get("state", "")
        result["metadata"]["flow_reason"] = flow.get("reason", "")


def _parse_http(data: Dict[str, Any], result: Dict[str, Any]) -> None:
    http = data.get("http", {})
    if isinstance(http, dict):
        result["metadata"]["http_hostname"] = http.get("hostname", "")
        result["metadata"]["http_url"] = http.get("url", "")
        result["metadata"]["http_user_agent"] = http.get("http_user_agent", http.get("user_agent", ""))
        result["metadata"]["http_method"] = http.get("http_method", http.get("method", ""))
        result["metadata"]["http_content_type"] = http.get("http_content_type", http.get("content_type", ""))


def _parse_dns(data: Dict[str, Any], result: Dict[str, Any]) -> None:
    dns = data.get("dns", {})
    if isinstance(dns, dict):
        result["metadata"]["dns_query"] = dns.get("rrname", dns.get("query", ""))
        result["metadata"]["dns_type"] = dns.get("rrtype", dns.get("type", ""))
        result["metadata"]["dns_answer"] = dns.get("answers", dns.get("rdata", ""))


def _parse_tls(data: Dict[str, Any], result: Dict[str, Any]) -> None:
    tls = data.get("tls", {})
    if isinstance(tls, dict):
        result["metadata"]["tls_subject"] = tls.get("subject", "")
        result["metadata"]["tls_issuer"] = tls.get("issuerdn", tls.get("issuer", ""))
        result["metadata"]["tls_version"] = tls.get("version", "")


def parse_suricata_alert(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("Suricata JSON parse failed: %s", exc)
            return {"event_type": "suricata", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "suricata", "severity": "info", "message": str(raw)}

    event_type = raw.get("event_type", "alert")
    timestamp = raw.get("timestamp", raw.get("time", ""))

    src_ip = raw.get("src_ip", raw.get("source_ip", ""))
    dest_ip = raw.get("dest_ip", raw.get("destination_ip", ""))
    src_port = raw.get("src_port", raw.get("source_port", 0))
    dest_port = raw.get("dest_port", raw.get("destination_port", 0))
    proto = raw.get("proto", raw.get("protocol", ""))

    alert = raw.get("alert", {})
    if not isinstance(alert, dict):
        alert = {}

    alert_action = alert.get("action", "")
    alert_severity = alert.get("severity", 3)
    alert_category = alert.get("category", "")
    alert_sig_id = alert.get("signature_id", alert.get("gid", 0))
    alert_sig = alert.get("signature", alert.get("sig", ""))
    alert_rev = alert.get("rev", 0)

    severity = SEVERITY_MAP.get(alert_severity, "medium")

    mitre_tactic = ALERT_CATEGORY_MAP.get(alert_category, "")

    payload = raw.get("payload", "")
    payload_printable = raw.get("payload_printable", "")

    result: Dict[str, Any] = {
        "event_type": "suricata_alert",
        "event_subtype": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": src_port,
        "dest_port": dest_port,
        "protocol": proto,
        "alert_action": alert_action,
        "alert_category": alert_category,
        "alert_signature": alert_sig,
        "alert_signature_id": alert_sig_id,
        "alert_revision": alert_rev,
        "timestamp": timestamp,
        "message": f"Suricata alert: {alert_sig or 'unknown'} [{alert_category}] from {src_ip}:{src_port} -> {dest_ip}:{dest_port}",
        "mitre_tactic": mitre_tactic,
        "metadata": {
            "payload": payload_printable or payload,
            "in_iface": raw.get("in_iface", ""),
            "vlan": raw.get("vlan", []),
        },
    }

    _parse_flow(raw, result)
    _parse_http(raw, result)
    _parse_dns(raw, result)
    _parse_tls(raw, result)

    return result


PARSER_REGISTRY_KEY = "suricata"
