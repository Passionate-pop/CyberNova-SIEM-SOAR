"""
CyberNova — Suricata Event Bridge
Tails Suricata EVE JSON log and forwards parsed events to the backend.
Runs alongside Suricata in the same container.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")
ADMIN_USER = os.environ.get("ADMIN_USER", "cybernova_agent")
ADMIN_PASS = os.environ.get("ADMIN_PASS")
if not ADMIN_PASS:
    raise RuntimeError("ADMIN_PASS environment variable is required for Suricata event bridge")
EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
SENSOR_HOSTNAME = os.environ.get("SENSOR_HOSTNAME", "suricata-sensor-1")

logging.basicConfig(level=logging.INFO, format="[event_bridge] %(message)s")
log = logging.getLogger("event_bridge")

EVENT_TYPE_MAP = {
    "alert": "suricata_alert",
    "dns": "dns_query",
    "http": "http_request",
    "flow": "network_flow",
    "tls": "tls_connection",
    "ssh": "ssh_connection",
    "fileinfo": "file_transfer",
    "anomaly": "network_anomaly",
}

SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

_token_refresh_counter = 0


async def authenticate(session):
    async with session.post(
        f"{BACKEND_URL}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=10,
    ) as r:
        if r.status != 200:
            raise Exception(f"Auth failed: {r.status}")
        data = await r.json()
        return data["access_token"]


async def send_event(session, token, event_type, message, severity="info", extra=None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    event = {
        "source": "suricata",
        "hostname": SENSOR_HOSTNAME,
        "event_type": event_type,
        "message": message[:500],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
    }
    if extra:
        event.update(extra)
    try:
        async with session.post(
            f"{BACKEND_URL}/api/v1/ingest/event",
            json=event,
            headers=headers,
            timeout=5,
        ) as r:
            if r.status == 429:
                log.warning("Rate limited, backing off")
                await asyncio.sleep(1)
            elif r.status not in (200, 201):
                log.debug("Event send returned %s", r.status)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log.warning("Send error: %s", e)


def map_suricata_event(eve: dict) -> list[dict]:
    event_type = eve.get("event_type", "unknown")
    ts = eve.get("timestamp", "")
    src_ip = eve.get("src_ip", "")
    dest_ip = eve.get("dest_ip", "")
    src_port = eve.get("src_port", 0)
    dest_port = eve.get("dest_port", 0)
    proto = eve.get("proto", "")
    mapped = EVENT_TYPE_MAP.get(event_type, f"suricata_{event_type}")
    results = []

    if event_type == "alert":
        alert = eve.get("alert", {})
        sev = SEVERITY_MAP.get(alert.get("severity", 3), "medium")
        sig = alert.get("signature", "Unknown")
        cat = alert.get("category", "")
        results.append({
            "event_type": mapped, "message": f"NIDS alert: {sig} [{cat}]", "severity": sev,
            "extra": {
                "signature": sig, "category": cat,
                "signature_id": alert.get("signature_id", 0),
                "gid": alert.get("gid", 1),
                "src_ip": src_ip, "dest_ip": dest_ip,
                "src_port": src_port, "dest_port": dest_port,
                "proto": proto,
            },
        })

    elif event_type == "dns":
        dns = eve.get("dns", {})
        dns_type = dns.get("type", "query")
        rrname = dns.get("rrname", "")
        results.append({
            "event_type": mapped, "message": f"DNS {dns_type}: {rrname}", "severity": "info",
            "extra": {
                "dns_type": dns_type, "rrname": rrname,
                "rrtype": dns.get("rrtype", ""),
                "src_ip": src_ip, "dest_ip": dest_ip,
            },
        })

    elif event_type == "http":
        http = eve.get("http", {})
        host = http.get("hostname", "")
        url = http.get("url", "")
        method = http.get("http_method", "GET")
        status = http.get("status", 0)
        length = http.get("length", 0)
        mime = http.get("mime", [])
        results.append({
            "event_type": mapped, "message": f"HTTP {method} {host}{url} -> {status}", "severity": "info",
            "extra": {
                "hostname": host, "url": url,
                "method": method, "status_code": status,
                "content_length": length,
                "mime_types": mime[:3] if isinstance(mime, list) else [],
                "src_ip": src_ip, "dest_ip": dest_ip,
                "src_port": src_port, "dest_port": dest_port,
            },
        })

    elif event_type == "ssh":
        ssh = eve.get("ssh", {})
        client = ssh.get("client", {}).get("software_version", "")
        server = ssh.get("server", {}).get("software_version", "")
        results.append({
            "event_type": mapped,
            "message": f"SSH: {client or 'unknown'} -> {server or 'unknown'}",
            "severity": "info",
            "extra": {
                "client_version": client, "server_version": server,
                "src_ip": src_ip, "dest_ip": dest_ip,
                "src_port": src_port, "dest_port": dest_port,
            },
        })

    elif event_type == "tls":
        tls = eve.get("tls", {})
        sni = tls.get("sni", "")
        ver = tls.get("version", "")
        subject = tls.get("subject", "")
        issuer = tls.get("issuer", "")
        fp = tls.get("fingerprint", "")
        results.append({
            "event_type": mapped,
            "message": f"TLS: {sni or 'no SNI'} ({ver or 'unknown'})",
            "severity": "info",
            "extra": {
                "sni": sni, "tls_version": ver,
                "subject": subject, "issuer": issuer,
                "fingerprint": fp,
                "src_ip": src_ip, "dest_ip": dest_ip,
                "dest_port": dest_port,
            },
        })

    elif event_type == "fileinfo":
        fi = eve.get("fileinfo", {})
        fname = fi.get("filename", "")
        md5 = fi.get("md5", "")
        size = fi.get("size", 0)
        mime_type = fi.get("mime", "")
        results.append({
            "event_type": mapped,
            "message": f"File transfer: {fname or 'unnamed'} ({size} bytes, {mime_type})",
            "severity": "medium",
            "extra": {
                "filename": fname, "md5": md5,
                "size": size, "mime": mime_type,
                "src_ip": src_ip, "dest_ip": dest_ip,
                "dest_port": dest_port,
            },
        })

    elif event_type == "anomaly":
        anomaly = eve.get("anomaly", {})
        atype = anomaly.get("type", "unknown")
        results.append({
            "event_type": mapped,
            "message": f"Network anomaly: {atype}",
            "severity": "high",
            "extra": {
                "anomaly_type": atype,
                "src_ip": src_ip, "dest_ip": dest_ip,
                "proto": proto,
            },
        })

    elif event_type in ("flow", "stats", "packet"):
        # Flow/stat/packet events are high-volume operational data — skip by default
        # to avoid flooding the ingest pipeline. Re-enable for flow analytics.
        pass

    else:
        results.append({
            "event_type": mapped,
            "message": f"Suricata {event_type} event",
            "severity": "info",
            "extra": {
                "src_ip": src_ip, "dest_ip": dest_ip,
                "src_port": src_port, "dest_port": dest_port,
                "proto": proto,
            },
        })

    return results


async def tail_and_forward():
    global _token_refresh_counter
    eve_path = Path(EVE_PATH)
    log.info("Watching %s...", EVE_PATH)
    token = None

    async with aiohttp.ClientSession() as session:
        while token is None:
            try:
                token = await authenticate(session)
                log.info("Authenticated with backend")
            except Exception as e:
                log.warning("Auth failed, retrying in 10s: %s", e)
                await asyncio.sleep(10)

        while True:
            try:
                if not eve_path.exists():
                    await asyncio.sleep(5)
                    continue

                with open(eve_path, "r") as f:
                    f.seek(0, 2)
                    while True:
                        line = f.readline()
                        if not line:
                            await asyncio.sleep(0.5)
                            continue
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        mapped = map_suricata_event(ev)
                        for m in mapped:
                            await send_event(
                                session, token,
                                m["event_type"], m["message"],
                                m["severity"], m.get("extra"),
                            )

                        _token_refresh_counter += 1
                        if _token_refresh_counter >= 500:
                            try:
                                token = await authenticate(session)
                                _token_refresh_counter = 0
                            except Exception as e:
                                log.warning("Token refresh failed: %s", e)

            except FileNotFoundError:
                log.warning("eve.json not found, retrying...")
                await asyncio.sleep(5)
            except Exception as e:
                log.error("Bridge error: %s", e)
                await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(tail_and_forward())
