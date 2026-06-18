"""
CyberNova — Zeek SSL/TLS Log Parser
Parses Zeek ssl.log TSV format.
Extracts server_name, cert info, cipher, validation status.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.zeek_ssl_log")

FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "version", "cipher", "curve", "server_name", "resumed",
          "last_alert", "next_protocol", "established", "cert_chain_fuids",
          "client_cert_chain_fuids", "subject", "issuer",
          "client_subject", "client_issuer", "validation_status",
          "ja3", "ja3s", "sni", "ocsp_status", "notary"]

VALIDATION_STATUS_SERVERITY = {
    "self signed certificate": "medium",
    "self signed certificate in certificate chain": "medium",
    "unable to get local issuer certificate": "medium",
    "certificate has expired": "high",
    "certificate is not yet valid": "medium",
    "unable to verify the first certificate": "medium",
    "invalid certificate": "high",
    "certificate revoked": "high",
    "unable to get certificate CRL": "low",
    "tlsv1 alert unknown ca": "high",
    "certificate signature failure": "high",
    "ok": "info",
    "-": "info",
}

KNOWN_MALICIOUS_JA3 = set()  # populated via external feeds at runtime


def _parse_tsv_line(line: str, fields: list[str]) -> Dict[str, str]:
    vals = line.strip().split("\t")
    result: Dict[str, str] = {}
    for i, name in enumerate(fields):
        if i < len(vals):
            val = vals[i]
            if val != "-":
                result[name] = val
    return result


def _parse_fields_header(line: str) -> list[str]:
    raw = line.strip()
    if raw.startswith("#fields"):
        raw = raw[7:].strip()
    return [p.strip() for p in raw.split("\t") if p.strip()]


def _parse_timestamp(ts_str: str) -> str:
    try:
        from datetime import datetime, timezone
        ts = float(ts_str)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError) as exc:
        log.debug("Invalid Zeek SSL timestamp: %s — %s", ts_str, exc)
        return ts_str


def _classify_ssl_event(validation_status: str, established: bool, last_alert: str) -> str:
    if not established:
        return "zeek_ssl_not_established"
    if validation_status and validation_status.lower() != "ok" and validation_status != "-":
        val_lower = validation_status.lower()
        if "expired" in val_lower:
            return "zeek_ssl_cert_expired"
        if "revoked" in val_lower:
            return "zeek_ssl_cert_revoked"
        if "self signed" in val_lower:
            return "zeek_ssl_self_signed"
        if "invalid" in val_lower:
            return "zeek_ssl_cert_invalid"
        return "zeek_ssl_cert_error"
    if last_alert and last_alert != "-":
        return "zeek_ssl_alert"
    return "zeek_ssl_connection"


def parse_zeek_ssl_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                data = _json.loads(raw)
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("Zeek SSL JSON parse failed: %s", exc)
                return {"event_type": "zeek_ssl", "severity": "info", "message": raw}
        else:
            lines = raw.split("\n")
            field_names = FIELDS
            for line in lines:
                if line.startswith("#fields"):
                    field_names = _parse_fields_header(line)
                    break
            data_line = ""
            for line in lines:
                ls = line.strip()
                if ls and not ls.startswith("#"):
                    data_line = ls
                    break
            if not data_line and lines and not lines[0].startswith("#"):
                data_line = lines[0].strip()
            if data_line:
                data = _parse_tsv_line(data_line, field_names)
            else:
                return {"event_type": "zeek_ssl", "severity": "info", "message": raw}
    else:
        return {"event_type": "zeek_ssl", "severity": "info", "message": str(raw)}

    ts = data.get("ts", "")
    timestamp = _parse_timestamp(ts) if ts else ""

    src_ip = data.get("id.orig_h", data.get("orig_h", data.get("src_ip", "")))
    src_port = data.get("id.orig_p", data.get("orig_p", data.get("src_port", 0)))
    dst_ip = data.get("id.resp_h", data.get("resp_h", data.get("dest_ip", "")))
    dst_port = data.get("id.resp_p", data.get("resp_p", data.get("dest_port", 0)))

    if isinstance(src_port, str):
        try:
            src_port = int(src_port)
        except ValueError:
            src_port = 0
    if isinstance(dst_port, str):
        try:
            dst_port = int(dst_port)
        except ValueError:
            dst_port = 0

    version = data.get("version", "")
    cipher = data.get("cipher", "")
    curve = data.get("curve", "")
    server_name = data.get("server_name", data.get("sni", ""))
    resumed = data.get("resumed", "")
    if isinstance(resumed, str):
        resumed = resumed.lower() in ("t", "true", "1")
    last_alert = data.get("last_alert", "")
    next_protocol = data.get("next_protocol", "")
    established = data.get("established", "")
    if isinstance(established, str):
        established = established.lower() in ("t", "true", "1")

    subject = data.get("subject", "")
    issuer = data.get("issuer", "")
    client_subject = data.get("client_subject", "")
    client_issuer = data.get("client_issuer", "")
    validation_status = data.get("validation_status", "")
    ja3 = data.get("ja3", "")
    ja3s = data.get("ja3s", "")
    sni = data.get("sni", "")
    ocsp_status = data.get("ocsp_status", "")
    notary = data.get("notary", "")

    uid = data.get("uid", "")
    cert_chain = data.get("cert_chain_fuids", "")

    event_type = _classify_ssl_event(validation_status, established, last_alert)

    sev_key = validation_status.lower().strip() if validation_status else ""
    severity = VALIDATION_STATUS_SERVERITY.get(sev_key, "info")
    if not established:
        severity = "medium"
    if last_alert and last_alert != "-":
        severity = "medium"

    return {
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": "tcp",
        "timestamp": timestamp,
        "uid": uid,
        "server_name": server_name,
        "sni": sni,
        "version": version,
        "cipher": cipher,
        "curve": curve,
        "resumed": resumed,
        "established": established,
        "last_alert": last_alert,
        "next_protocol": next_protocol,
        "subject": subject,
        "issuer": issuer,
        "client_subject": client_subject,
        "client_issuer": client_issuer,
        "validation_status": validation_status,
        "ja3": ja3,
        "ja3s": ja3s,
        "ocsp_status": ocsp_status,
        "notary": notary,
        "message": (
            f"Zeek SSL: {server_name or sni or subject or 'unknown'} "
            f"[{version}/{cipher}] valid={validation_status}"
        ),
        "metadata": {
            "uid": uid,
            "cert_chain_fuids": cert_chain,
            "curve": curve,
            "ocsp_status": ocsp_status,
            "notary": notary,
            "client_subject": client_subject,
            "client_issuer": client_issuer,
        },
    }


PARSER_REGISTRY_KEY = "zeek_ssl"
