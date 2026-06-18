"""
CyberNova — Zeek DNS Log Parser
Parses Zeek dns.log TSV format.
Extracts queries, answers, rcode. Maps to DNS-scoped event types.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.zeek_dns_log")

FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "trans_id", "query", "qclass", "qclass_name",
          "qtype", "qtype_name", "rcode", "rcode_name", "AA",
          "TC", "RD", "RA", "Z", "answers", "TTLs", "rejected"]

RCODE_MAP = {
    "0": "noerror", "1": "formerr", "2": "servfail",
    "3": "nxdomain", "4": "notimp", "5": "refused",
    "6": "yxdomain", "7": "yxrrset", "8": "nxrrset",
    "9": "notauth", "10": "notzone",
}

QTYPE_MAP = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
    "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV",
    "35": "NAPTR", "48": "DNSKEY", "65": "HTTPS", "99": "SPF",
    "108": "EUI48", "109": "EUI64", "255": "ANY",
}

KNOWN_DGA_DOMAINS_RE = None

SUSPICIOUS_TLDS = {".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".ga", ".pw", ".icu", ".work", ".date", ".loan", ".men", ".click", ".download", ".review", ".stream", ".trade"}

HIGH_BYTE_QUERY_LEN = 40


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
        log.debug("Invalid Zeek DNS timestamp: %s — %s", ts_str, exc)
        return ts_str


def _classify_dns_event(query: str, rcode: str, rejected: bool, answers: list) -> str:
    if rejected:
        return "zeek_dns_rejected"
    if rcode in ("nxdomain", "3"):
        return "zeek_dns_nxdomain"
    if rcode in ("servfail", "2"):
        return "zeek_dns_servfail"
    if rcode not in ("", "noerror", "0"):
        return "zeek_dns_error"
    if not answers:
        return "zeek_dns_no_answer"
    return "zeek_dns_request"


def _classify_dns_severity(rejected: bool, rcode: str, query_len: int, query: str) -> str:
    if rejected:
        return "medium"
    if rcode in ("servfail", "2"):
        return "medium"
    if rcode in ("nxdomain", "3"):
        return "low"
    q_lower = query.lower()
    for tld in SUSPICIOUS_TLDS:
        if q_lower.endswith(tld):
            return "medium"
    if query_len > HIGH_BYTE_QUERY_LEN * 2:
        return "medium"
    return "info"


def parse_zeek_dns_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            import json as _json
            try:
                data = _json.loads(raw)
            except (ValueError, _json.JSONDecodeError) as exc:
                log.debug("Zeek DNS JSON parse failed: %s", exc)
                return {"event_type": "zeek_dns", "severity": "info", "message": raw}
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
                return {"event_type": "zeek_dns", "severity": "info", "message": raw}
    else:
        return {"event_type": "zeek_dns", "severity": "info", "message": str(raw)}

    ts = data.get("ts", "")
    timestamp = _parse_timestamp(ts) if ts else ""

    src_ip = data.get("id.orig_h", data.get("src_ip", data.get("orig_h", "")))
    src_port = data.get("id.orig_p", data.get("src_port", data.get("orig_p", 0)))
    dst_ip = data.get("id.resp_h", data.get("dest_ip", data.get("resp_h", "")))
    dst_port = data.get("id.resp_p", data.get("dest_port", data.get("resp_p", 0)))
    proto = data.get("proto", "udp")
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

    query = data.get("query", "")
    qtype_name = data.get("qtype_name", "")
    qtype_val = data.get("qtype", "")
    qclass_name = data.get("qclass_name", "")
    rcode_name = data.get("rcode_name", "")
    rcode_val = data.get("rcode", "")
    rejected = data.get("rejected", "")
    if isinstance(rejected, str):
        rejected = rejected.lower() in ("true", "t", "1")
    aa = data.get("AA", "")
    tc = data.get("TC", "")
    rd = data.get("RD", "")
    ra = data.get("RA", "")

    raw_answers = data.get("answers", data.get("answer", ""))
    if isinstance(raw_answers, str):
        answer_list = [a.strip() for a in raw_answers.split(",") if a.strip()]
    elif isinstance(raw_answers, list):
        answer_list = raw_answers
    else:
        answer_list = []

    query_len = len(query)
    qtype = QTYPE_MAP.get(qtype_val, qtype_name)
    rcode = rcode_name or RCODE_MAP.get(rcode_val, rcode_val)

    event_type = _classify_dns_event(query, rcode, rejected, answer_list)
    severity = _classify_dns_severity(rejected, rcode, query_len, query)

    uid = data.get("uid", "")
    trans_id = data.get("trans_id", "")
    ttl_str = data.get("TTLs", data.get("ttls", ""))

    return {
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": proto,
        "timestamp": timestamp,
        "uid": uid,
        "query": query,
        "query_length": query_len,
        "qtype": qtype,
        "qclass": qclass_name,
        "rcode": rcode,
        "rcode_val": rcode_val,
        "rejected": rejected,
        "answers": answer_list,
        "authoritative": aa,
        "truncated": tc,
        "recursion_desired": rd,
        "recursion_available": ra,
        "trans_id": trans_id,
        "message": f"Zeek DNS: {query} -> {rcode} ({','.join(answer_list[:3])})",
        "metadata": {
            "uid": uid,
            "trans_id": trans_id,
            "qtype_val": qtype_val,
            "rcode_val": rcode_val,
            "AA": aa, "TC": tc, "RD": rd, "RA": ra,
            "ttls": ttl_str,
        },
    }


PARSER_REGISTRY_KEY = "zeek_dns"
