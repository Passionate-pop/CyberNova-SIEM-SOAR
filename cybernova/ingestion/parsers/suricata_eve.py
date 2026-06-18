"""
CyberNova — Suricata EVE JSON Parser
Parses Newline-Delimited JSON Suricata EVE output.
Maps alert categories/signatures to event_types + MITRE ATT&CK.
Handles all EVE event types: alert, flow, dns, http, tls, smtp, ssh, etc.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.suricata_eve")

ALERT_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

EVE_EVENT_TYPES = {
    "alert": "suricata_alert",
    "flow": "suricata_flow",
    "dns": "suricata_dns",
    "http": "suricata_http",
    "tls": "suricata_tls",
    "smtp": "suricata_smtp",
    "ssh": "suricata_ssh",
    "ftp": "suricata_ftp",
    "fileinfo": "suricata_file",
    "files": "suricata_file",
    "nfs": "suricata_nfs",
    "smb": "suricata_smb",
    "dhcp": "suricata_dhcp",
    "mqtt": "suricata_mqtt",
    "kafka": "suricata_kafka",
    "ikev2": "suricata_ikev2",
    "krb5": "suricata_krb5",
    "sip": "suricata_sip",
    "applayer": "suricata_applayer",
    "stats": "suricata_stats",
    "anomaly": "suricata_anomaly",
    "netflow": "suricata_netflow",
    "drop": "suricata_drop",
    "packet": "suricata_packet",
}

ALERT_CATEGORY_MAP = {
    "Attempted Administrator Privilege Gain": "privilege_escalation",
    "Unsuccessful Administrator Privilege Gain": "privilege_escalation_failed",
    "Attempted User Privilege Gain": "privilege_escalation",
    "Unsuccessful User Privilege Gain": "privilege_escalation_failed",
    "Attempted Credential Access": "credential_access_attempted",
    "Credential Theft": "credential_theft",
    "Unsuccessful Login Attempt": "login_brute_force",
    "Successful Login Attempt": "login_success",
    "Access to a Potentially Vulnerable Web Application": "web_app_scan",
    "Web Application Attack": "web_app_attack",
    "Attempted Information Leak": "information_leak",
    "Potentially Bad Traffic": "suspicious_traffic",
    "Attempted Denial of Service": "dos_attempt",
    "Denial of Service": "dos",
    "Detection of a Network Scan": "network_scan",
    "Detection of a Port Scan": "port_scan",
    "Reconnaissance": "reconnaissance",
    "Recon": "reconnaissance",
    "Recon Activities": "reconnaissance",
    "Attempted Recon": "reconnaissance",
    "Suspicious DNS Query": "suspicious_dns",
    "Suspicious DNS": "suspicious_dns",
    "Malware Detected": "malware_detected",
    "Malware": "malware_detected",
    "Malware Command and Control": "c2_traffic",
    "Command and Control": "c2_traffic",
    "CnC": "c2_traffic",
    "C2": "c2_traffic",
    "Policy Violation": "policy_violation",
    "Policy Violation Detected": "policy_violation",
    "Corporate Policy Violation": "policy_violation",
    "Attempt to Drop by Filter": "evasion_attempt",
    "Filter Drop": "drop",
    "Known Attack": "known_attack",
    "Known Attacker": "known_attacker",
    "Suspicious User Agent": "suspicious_user_agent",
    "Executable was downloaded": "executable_download",
    "Executable and VBA DLL": "executable_download",
    "MALWARE-CNC": "c2_traffic",
    "Malware CnC": "c2_traffic",
    "ET MALWARE": "malware_detected",
    "ET CNC": "c2_traffic",
    "ET POLICY": "policy_violation",
    "ET WEB_SERVER": "web_app_attack",
    "ET SCAN": "network_scan",
    "ET TROJAN": "trojan_activity",
    "ET CNC Group": "c2_traffic",
    "ET INFO": "info_event",
    "ETP INFO": "info_event",
    "Suspicious Traffic": "suspicious_traffic",
    "Not Suspicious Traffic": "false_positive",
    "Generic ICMP Event": "icmp_event",
    "Attempted Login": "login_attempt",
    "Successful Privileged Gain Unknown": "privilege_escalation",
    "System Call": "syscall",
    "Shellcode Detected": "shellcode",
    "Shellcode": "shellcode",
    "Exploit": "exploit",
    "Exploit Detected": "exploit",
    "Attempted Exploit": "exploit_attempted",
    "Network Trojan": "trojan_activity",
    "Worm": "worm_activity",
    "Virus": "virus_detected",
    "Ransomware": "ransomware",
    "Ransomware Detected": "ransomware",
    "Phishing": "phishing",
    "Phishing Detected": "phishing",
    "DNS Tunneling": "dns_tunneling",
    "DNS Tunnel": "dns_tunneling",
    "Data Exfiltration": "data_exfiltration",
    "Exfiltration": "data_exfiltration",
    "File Exfiltration": "data_exfiltration",
    "Suspicious Filename": "suspicious_filename",
    "SMB Alert": "smb_alert",
    "SMB Alert Detected": "smb_alert",
    "SSL Certificate Mismatch": "ssl_cert_mismatch",
    "SSL Invalid Certificate": "ssl_cert_invalid",
    "SSL Expired Certificate": "ssl_cert_expired",
    "SSL Self-Signed Certificate": "ssl_cert_self_signed",
    "TLS Certificate Expired": "tls_cert_expired",
    "TLS Invalid Certificate": "tls_cert_invalid",
    "TLS Self-Signed Certificate": "tls_cert_self_signed",
    "DTLS Alert": "dtls_alert",
    "Tor Traffic": "tor_traffic",
    "Tor Exit Node": "tor_traffic",
    "TOR Connection": "tor_traffic",
    "Encrypted Traffic Detected": "encrypted_traffic",
    "Non-Encrypted Traffic": "clear_text_traffic",
    "Unknown Protocol": "unknown_protocol",
    "Protocol Mismatch": "protocol_mismatch",
    "HTTP Policy Violation": "http_policy_violation",
    "DNS Policy Violation": "dns_policy_violation",
}

ALERT_CATEGORY_MITRE = {
    "Attempted Administrator Privilege Gain": {"tactic": "TA0004", "technique": "T1068"},
    "Attempted User Privilege Gain": {"tactic": "TA0004", "technique": "T1068"},
    "Privilege Escalation": {"tactic": "TA0004", "technique": "T1068"},
    "Attempted Credential Access": {"tactic": "TA0006", "technique": "T1110"},
    "Unsuccessful Login Attempt": {"tactic": "TA0006", "technique": "T1110"},
    "Malware Detected": {"tactic": "TA0002", "technique": "T1204"},
    "Malware Command and Control": {"tactic": "TA0011", "technique": "T1071"},
    "Command and Control": {"tactic": "TA0011", "technique": "T1071"},
    "Reconnaissance": {"tactic": "TA0043", "technique": "T1595"},
    "Recon Activities": {"tactic": "TA0043", "technique": "T1595"},
    "Detection of a Network Scan": {"tactic": "TA0043", "technique": "T1595"},
    "Detection of a Port Scan": {"tactic": "TA0043", "technique": "T1046"},
    "Web Application Attack": {"tactic": "TA0001", "technique": "T1190"},
    "Attempted Denial of Service": {"tactic": "TA0040", "technique": "T1498"},
    "Denial of Service": {"tactic": "TA0040", "technique": "T1498"},
    "Executable was downloaded": {"tactic": "TA0005", "technique": "T1204"},
    "Data Exfiltration": {"tactic": "TA0010", "technique": "T1048"},
    "Exfiltration": {"tactic": "TA0010", "technique": "T1048"},
    "Shellcode Detected": {"tactic": "TA0002", "technique": "T1059"},
    "Exploit": {"tactic": "TA0002", "technique": "T1203"},
    "Exploit Detected": {"tactic": "TA0002", "technique": "T1203"},
    "Ransomware": {"tactic": "TA0040", "technique": "T1486"},
    "Ransomware Detected": {"tactic": "TA0040", "technique": "T1486"},
    "Phishing": {"tactic": "TA0001", "technique": "T1566"},
    "Phishing Detected": {"tactic": "TA0001", "technique": "T1566"},
    "Network Trojan": {"tactic": "TA0002", "technique": "T1204"},
    "DNS Tunneling": {"tactic": "TA0011", "technique": "T1572"},
    "Tor Traffic": {"tactic": "TA0005", "technique": "T1090.003"},
    "Suspicious DNS Query": {"tactic": "TA0011", "technique": "T1572"},
    "Policy Violation": {"tactic": "TA0005", "technique": "T1078"},
    "Suspicious User Agent": {"tactic": "TA0005", "technique": "T1036"},
    "Suspicious Traffic": {"tactic": "TA0005", "technique": "T1078"},
    "Encrypted Traffic Detected": {"tactic": "TA0005", "technique": "T1573"},
}


def _parse_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    category = alert.get("category", "")
    sig_id = alert.get("signature_id", alert.get("gid", 0))
    sig = alert.get("signature", "")
    rev = alert.get("rev", 0)
    sev = alert.get("severity", 3)
    action = alert.get("action", "")

    mapped_category = ALERT_CATEGORY_MAP.get(category, f"suricata_{category.lower().replace(' ', '_')}")
    ALERT_SEVERITY_MAP.get(sev, "medium")
    mitre = ALERT_CATEGORY_MITRE.get(category, {})

    return {
        "alert_category": category,
        "alert_mapped_category": mapped_category,
        "alert_signature": sig,
        "alert_signature_id": sig_id,
        "alert_revision": rev,
        "alert_action": action,
        "alert_severity": sev,
        "mitre_tactic": mitre.get("tactic", ""),
        "mitre_technique": mitre.get("technique", ""),
    }


def _parse_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flow_id": flow.get("id", ""),
        "flow_state": flow.get("state", ""),
        "flow_reason": flow.get("reason", ""),
        "flow_alerted": flow.get("alerted", False),
        "flow_age": flow.get("age", 0),
        "flow_vlan": flow.get("vlan", []),
    }


def _parse_http(http: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "http_hostname": http.get("hostname", ""),
        "http_url": http.get("url", ""),
        "http_user_agent": http.get("http_user_agent", http.get("user_agent", "")),
        "http_method": http.get("http_method", http.get("method", "")),
        "http_content_type": http.get("http_content_type", http.get("content_type", "")),
        "http_refer": http.get("referrer", http.get("http_referer", "")),
        "http_status": http.get("status", http.get("http_status", 0)),
        "http_length": http.get("length", http.get("response_len", 0)),
        "http_mime": http.get("resp_mime", http.get("mime", [])),
    }


def _parse_dns(dns: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "dns_query": dns.get("rrname", dns.get("dns_rrname", "")),
        "dns_type": dns.get("rrtype", dns.get("dns_rrtype", "")),
        "dns_rcode": dns.get("rcode", dns.get("dns_rcode", "")),
        "dns_tc": dns.get("tc", False),
        "dns_answers": dns.get("answers", []),
        "dns_grouped": dns.get("grouped", False),
    }


def _parse_tls(tls: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tls_subject": tls.get("subject", ""),
        "tls_issuer": tls.get("issuerdn", tls.get("issuer", "")),
        "tls_version": tls.get("version", ""),
        "tls_cipher": tls.get("cipher", ""),
        "tls_sni": tls.get("sni", tls.get("servername", "")),
        "tls_fingerprint": tls.get("fingerprint", tls.get("ja3", tls.get("ja3s", ""))),
        "tls_notbefore": tls.get("notbefore", ""),
        "tls_notafter": tls.get("notafter", ""),
        "tls_serial": tls.get("serial", ""),
    }


def _parse_ssh(ssh: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ssh_client_version": ssh.get("client", {}).get("software_version", ""),
        "ssh_server_version": ssh.get("server", {}).get("software_version", ""),
        "ssh_client_proto": ssh.get("client", {}).get("proto_version", ""),
        "ssh_server_proto": ssh.get("server", {}).get("proto_version", ""),
    }


def _parse_smtp(smtp: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "smtp_from": smtp.get("mail_from", ""),
        "smtp_to": smtp.get("rcpt_to", []),
        "smtp_subject": smtp.get("subject", ""),
        "smtp_agent": smtp.get("agent", ""),
        "smtp_helo": smtp.get("helo", ""),
    }


def _parse_fileinfo(fileinfo: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file_name": fileinfo.get("filename", ""),
        "file_magic": fileinfo.get("magic", ""),
        "file_size": fileinfo.get("size", 0),
        "file_md5": fileinfo.get("md5", ""),
        "file_sha1": fileinfo.get("sha1", ""),
        "file_sha256": fileinfo.get("sha256", ""),
        "file_state": fileinfo.get("state", ""),
        "file_stored": fileinfo.get("stored", False),
    }


def _classify_suricata_severity(event_type: str, alert_severity: int, action: str) -> str:
    if event_type == "alert":
        return ALERT_SEVERITY_MAP.get(alert_severity, "medium")
    if action in ("drop", "reject"):
        return "high"
    if event_type in ("anomaly", "drop"):
        return "medium"
    return "info"


def parse_suricata_eve_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("Suricata EVE JSON parse failed: %s", exc)
            return {"event_type": "suricata", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "suricata", "severity": "info", "message": str(raw)}

    eve_type = raw.get("event_type", "alert")
    mapped_type = EVE_EVENT_TYPES.get(eve_type, f"suricata_{eve_type}")

    timestamp = raw.get("timestamp", "")
    src_ip = raw.get("src_ip", raw.get("source_ip", ""))
    dest_ip = raw.get("dest_ip", raw.get("destination_ip", ""))
    src_port = raw.get("src_port", raw.get("source_port", 0))
    dest_port = raw.get("dest_port", raw.get("destination_port", 0))
    proto = raw.get("proto", raw.get("protocol", ""))

    if isinstance(src_port, str):
        try:
            src_port = int(src_port)
        except ValueError:
            src_port = 0
    if isinstance(dest_port, str):
        try:
            dest_port = int(dest_port)
        except ValueError:
            dest_port = 0

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "eve_type": eve_type,
        "severity": "info",
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": src_port,
        "dest_port": dest_port,
        "protocol": proto,
        "timestamp": timestamp,
        "message": "",
        "metadata": {
            "pcap_cnt": raw.get("pcap_cnt", raw.get("packet_id", "")),
            "vlan": raw.get("vlan", []),
            "in_iface": raw.get("in_iface", ""),
            "community_id": raw.get("community_id", ""),
        },
    }

    if eve_type == "alert":
        alert_data = raw.get("alert", {})
        if isinstance(alert_data, dict):
            alert_parsed = _parse_alert(alert_data)
            result.update(alert_parsed)
            result["severity"] = _classify_suricata_severity(eve_type, alert_parsed.get("alert_severity", 3), alert_parsed.get("alert_action", ""))
            result["message"] = (
                f"Suricata alert: {alert_parsed.get('alert_signature', 'unknown')} "
                f"[{alert_parsed.get('alert_category', '')}] {src_ip}:{src_port} -> {dest_ip}:{dest_port}"
            )

    elif eve_type == "flow":
        flow_data = raw.get("flow", {})
        if isinstance(flow_data, dict):
            result.update(_parse_flow(flow_data))
            result["severity"] = "info"
        result["message"] = f"Suricata flow: {src_ip}:{src_port} -> {dest_ip}:{dest_port} proto={proto}"

    elif eve_type == "http":
        http_data = raw.get("http", {})
        if isinstance(http_data, dict):
            result.update(_parse_http(http_data))
        result["severity"] = "info"
        hostname = result.get("http_hostname", "")
        url = result.get("http_url", "")
        result["message"] = f"Suricata HTTP: {result.get('http_method', '')} http://{hostname}{url}"

    elif eve_type == "dns":
        dns_data = raw.get("dns", {})
        if isinstance(dns_data, dict):
            result.update(_parse_dns(dns_data))
        result["message"] = f"Suricata DNS: {result.get('dns_query', '')} type={result.get('dns_type', '')}"

    elif eve_type == "tls":
        tls_data = raw.get("tls", {})
        if isinstance(tls_data, dict):
            result.update(_parse_tls(tls_data))
        result["message"] = f"Suricata TLS: {result.get('tls_subject', '')} -> {result.get('tls_sni', '')}"

    elif eve_type == "ssh":
        ssh_data = raw.get("ssh", {})
        if isinstance(ssh_data, dict):
            result.update(_parse_ssh(ssh_data))
        result["message"] = f"Suricata SSH: client={result.get('ssh_client_version', '')}"

    elif eve_type == "smtp":
        smtp_data = raw.get("smtp", {})
        if isinstance(smtp_data, dict):
            result.update(_parse_smtp(smtp_data))
        result["message"] = f"Suricata SMTP: {result.get('smtp_from', '')} -> {result.get('smtp_to', '')}"

    elif eve_type == "fileinfo":
        file_data = raw.get("fileinfo", {})
        if isinstance(file_data, dict):
            result.update(_parse_fileinfo(file_data))
        result["message"] = f"Suricata file: {result.get('file_name', '')} ({result.get('file_size', 0)} bytes)"

    else:
        result["message"] = f"Suricata {eve_type} event"
        result["metadata"]["extra"] = {k: v for k, v in raw.items()
                                       if k not in ("event_type", "timestamp", "src_ip", "dest_ip",
                                                     "src_port", "dest_port", "proto", "vlan", "in_iface")}

    result.get("mitre_tactic", "")
    result.get("mitre_technique", "")

    payload_printable = raw.get("payload_printable", "")
    if payload_printable:
        result["metadata"]["payload_printable"] = payload_printable

    return result


PARSER_REGISTRY_KEY = "suricata_eve"
