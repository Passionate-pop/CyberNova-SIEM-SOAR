"""
CyberNova — Parser Registry
Format-specific parsers for CEF, syslog, JSON, agent payloads.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict

from cybernova.ingestion.parsers.windows_evtx import parse_windows_event
from cybernova.ingestion.parsers.web_server import parse_web_server_log
from cybernova.ingestion.parsers.suricata import parse_suricata_alert
from cybernova.ingestion.parsers.zeek import parse_zeek_log
from cybernova.ingestion.parsers.cisco_asa import parse_cisco_asa_log
from cybernova.ingestion.parsers.palo_alto import parse_palo_alto_log
from cybernova.ingestion.parsers.paloalto_traffic import parse_paloalto_traffic_log
from cybernova.ingestion.parsers.auditd import parse_auditd_log
from cybernova.ingestion.parsers.kubernetes import parse_kubernetes_log
from cybernova.ingestion.parsers.okta import parse_okta_log
from cybernova.ingestion.parsers.github_audit import parse_github_audit_log
from cybernova.ingestion.parsers.crowdstrike import parse_crowdstrike_event
from cybernova.ingestion.parsers.sentinelone import parse_sentinelone_event
from cybernova.ingestion.parsers.fortinet import parse_fortinet_log
from cybernova.ingestion.parsers.checkpoint import parse_checkpoint_log
from cybernova.ingestion.parsers.juniper_srx import parse_juniper_srx_log
from cybernova.ingestion.parsers.elasticsearch import parse_elasticsearch_log
from cybernova.ingestion.parsers.mongodb import parse_mongodb_log
from cybernova.ingestion.parsers.apache_access import parse_apache_access_log
from cybernova.ingestion.parsers.nginx_access import parse_nginx_access_log
from cybernova.ingestion.parsers.nginx_error import parse_nginx_error_log
from cybernova.ingestion.parsers.suricata_eve import parse_suricata_eve_log
from cybernova.ingestion.parsers.zeek_conn_log import parse_zeek_conn_log
from cybernova.ingestion.parsers.zeek_dns_log import parse_zeek_dns_log
from cybernova.ingestion.parsers.zeek_http_log import parse_zeek_http_log
from cybernova.ingestion.parsers.zeek_ssl_log import parse_zeek_ssl_log
from cybernova.ingestion.parsers.paloalto_threat import parse_paloalto_threat_log
from cybernova.ingestion.parsers.macos_unified import parse_macos_unified_log
from cybernova.ingestion.parsers.docker_logs import parse_docker_logs
from cybernova.ingestion.parsers.k8s_audit import parse_k8s_audit_log

log = logging.getLogger("cybernova.ingestion.parsers")


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: Dict[str, Callable] = {
            "syslog": self.parse_syslog, "cef": self.parse_cef,
            "agent": self.parse_agent, "webhook": self.parse_json,
            "api": self.parse_json, "json": self.parse_json,
            "windows_evtx": self.parse_windows_evtx,
            "web_server": self.parse_web_server,
            "apache": self.parse_web_server,
            "nginx": self.parse_web_server,
            "suricata": self.parse_suricata,
            "zeek": self.parse_zeek,
            "cisco_asa": self.parse_cisco_asa,
            "palo_alto": self.parse_palo_alto,
            "paloalto_traffic": self.parse_paloalto_traffic,
            "paloalto_threat": self.parse_paloalto_threat,
            "macos_unified": self.parse_macos_unified,
            "docker_logs": self.parse_docker_logs,
            "k8s_audit": self.parse_k8s_audit,
            "auditd": self.parse_auditd,
            "kubernetes": self.parse_kubernetes,
            "okta": self.parse_okta,
            "github_audit": self.parse_github_audit,
            "crowdstrike": self.parse_crowdstrike,
            "sentinelone": self.parse_sentinelone,
            "fortinet": self.parse_fortinet,
            "checkpoint": self.parse_checkpoint,
            "juniper_srx": self.parse_juniper_srx,
            "elasticsearch": self.parse_elasticsearch,
            "mongodb": self.parse_mongodb,
            "apache_access": self.parse_apache_access,
            "nginx_access": self.parse_nginx_access,
            "nginx_error": self.parse_nginx_error,
            "suricata_eve": self.parse_suricata_eve,
            "zeek_conn": self.parse_zeek_conn,
            "zeek_dns": self.parse_zeek_dns,
            "zeek_http": self.parse_zeek_http,
            "zeek_ssl": self.parse_zeek_ssl,
        }

    def register(self, source_type: str, parser: Callable) -> None:
        self._parsers[source_type] = parser

    def parse(self, source_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        parser = self._parsers.get(source_type, self.parse_json)
        try:
            return parser(payload)
        except Exception as exc:
            log.warning("Parser %s failed: %s — fallback to generic", source_type, exc)
            return self.parse_json(payload)

    def parse_syslog(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = payload.get("raw", "")
        result: Dict[str, Any] = {"event_type": "syslog", "severity": "info", "message": raw}
        if raw.startswith("<"):
            end = raw.find(">")
            if end > 0:
                try:
                    pri = int(raw[1:end])
                    severity_code = pri & 0x07
                    sev_map = {0: "critical", 1: "critical", 2: "critical",
                               3: "high", 4: "medium", 5: "low", 6: "info", 7: "info"}
                    result["severity"] = sev_map.get(severity_code, "info")
                    raw = raw[end + 1:].strip()
                except ValueError:
                    pass
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        if len(ips) >= 1:
            result["source_ip"] = ips[0]
        if len(ips) >= 2:
            result["dest_ip"] = ips[1]
        result["message"] = raw
        return result

    def parse_cef(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = payload.get("raw", str(payload))
        result: Dict[str, Any] = {"event_type": "cef", "severity": "info"}
        parts = raw.split("|", 7)
        if len(parts) >= 7:
            result["event_type"] = parts[5].strip() if parts[5] else "cef"
            try:
                sev = int(parts[6].strip())
                if sev >= 8:
                    result["severity"] = "critical"
                elif sev >= 6:
                    result["severity"] = "high"
                elif sev >= 4:
                    result["severity"] = "medium"
                else:
                    result["severity"] = "low"
            except ValueError:
                result["severity"] = parts[6].strip().lower()
            if len(parts) == 8:
                ext_pairs = re.findall(r"(\w+)=(.*?)(?=\s\w+=|$)", parts[7])
            for key, value in ext_pairs:
                if key in ("src", "sourceAddress"):
                    result["source_ip"] = value.strip()
                elif key in ("dst", "destinationAddress"):
                    result["dest_ip"] = value.strip()
                elif key in ("spt", "sourcePort"):
                    result["source_port"] = int(value.strip())
                elif key in ("dpt", "destinationPort"):
                    result["dest_port"] = int(value.strip())
                elif key in ("suser", "sourceUserName"):
                    result["user"] = value.strip()
                elif key == "proto":
                    result["protocol"] = value.strip()
                result["metadata"] = {"vendor": parts[1], "product": parts[2]}
        result["message"] = raw
        return result

    def parse_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": payload.get("event_type", "agent_event"),
            "severity": payload.get("severity", "info"),
            "source_ip": payload.get("src_ip") or payload.get("source_ip"),
            "dest_ip": payload.get("dest_ip") or payload.get("destination_ip"),
            "source_port": payload.get("src_port") or payload.get("source_port"),
            "dest_port": payload.get("dest_port") or payload.get("destination_port"),
            "protocol": payload.get("protocol"),
            "user": payload.get("user") or payload.get("username"),
            "device_id": payload.get("device_id"),
            "message": payload.get("message", ""),
            "timestamp": payload.get("timestamp"),
            "metadata": {k: v for k, v in payload.items()
                         if k not in {"event_type", "severity", "src_ip", "dest_ip",
                                       "source_ip", "destination_ip", "message", "timestamp"}},
        }

    def parse_windows_evtx(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_windows_event(payload)

    def parse_web_server(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_web_server_log(payload)

    def parse_suricata(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_suricata_alert(payload)

    def parse_zeek(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_zeek_log(payload)

    def parse_cisco_asa(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_cisco_asa_log(payload)

    def parse_palo_alto(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_palo_alto_log(payload)

    def parse_paloalto_traffic(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_paloalto_traffic_log(payload)

    def parse_paloalto_threat(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_paloalto_threat_log(payload)

    def parse_macos_unified(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_macos_unified_log(payload)

    def parse_docker_logs(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_docker_logs(payload)

    def parse_k8s_audit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_k8s_audit_log(payload)

    def parse_auditd(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_auditd_log(payload)

    def parse_kubernetes(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_kubernetes_log(payload)

    def parse_okta(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_okta_log(payload)

    def parse_github_audit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_github_audit_log(payload)

    def parse_crowdstrike(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_crowdstrike_event(payload)

    def parse_sentinelone(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_sentinelone_event(payload)

    def parse_fortinet(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_fortinet_log(payload)

    def parse_checkpoint(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_checkpoint_log(payload)

    def parse_juniper_srx(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_juniper_srx_log(payload)

    def parse_elasticsearch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_elasticsearch_log(payload)

    def parse_mongodb(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_mongodb_log(payload)

    def parse_apache_access(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_apache_access_log(payload)

    def parse_nginx_access(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_nginx_access_log(payload)

    def parse_nginx_error(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_nginx_error_log(payload)

    def parse_suricata_eve(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_suricata_eve_log(payload)

    def parse_zeek_conn(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_zeek_conn_log(payload)

    def parse_zeek_dns(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_zeek_dns_log(payload)

    def parse_zeek_http(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_zeek_http_log(payload)

    def parse_zeek_ssl(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return parse_zeek_ssl_log(payload)

    _SOURCE_SIGNATURES: list[tuple[set[str], str, str]] = [
        ({"kind", "verb", "objectRef", "requestURI", "user.username"}, "k8s_audit", "Kubernetes Audit"),
        ({"objectRef.resource", "objectRef.namespace", "verb", "stage"}, "k8s_audit", "Kubernetes Audit"),
        ({"event_type", "src_ip", "dest_ip", "alert", "proto"}, "suricata_eve", "Suricata EVE"),
        ({"event_type", "alert", "src_ip", "dest_ip"}, "suricata_eve", "Suricata EVE"),
        ({"id.orig_h", "id.resp_h", "proto", "uid"}, "zeek", "Zeek Log"),
        ({"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"}, "zeek", "Zeek Log"),
        ({"type", "subtype", "threat_id", "action", "app"}, "palo_alto", "Palo Alto NGFW"),
        ({"type", "subtype", "action", "severity", "threatid"}, "palo_alto", "Palo Alto NGFW"),
        ({"log", "stream", "time"}, "docker_logs", "Docker Log"),
        ({"container_id", "container_name", "log"}, "docker_logs", "Docker Log"),
        ({"EventId", "EventType", "Provider", "Level"}, "windows_evtx", "Windows Event"),
        ({"providerName", "id", "level", "message"}, "windows_evtx", "Windows Event (XML-API)"),
        ({"syslog.facility", "syslog.severity", "syslog.hostname", "syslog.appname"}, "syslog", "Structured Syslog"),
        ({"@timestamp", "host", "facility", "priority"}, "syslog", "Syslog RFC 5424"),
        ({"remote_addr", "remote_user", "request", "status", "body_bytes_sent"}, "web_server", "HTTP Access Log"),
        ({"http_method", "http_user_agent", "remote_addr", "status"}, "web_server", "HTTP Access Log"),
        ({"@version", "type", "tags", "message"}, "logstash", "Logstash"),
        ({"kubernetes", "docker", "stream", "log"}, "k8s_container", "Kubernetes Container"),
        ({"EventName", "EventType", "SourceName", "Message"}, "windows_evtx", "Windows Event"),
        ({"host", "ident", "pid", "message"}, "syslog", "Syslog"),
        ({"hostname", "facility", "severity", "program"}, "syslog", "Syslog"),
        ({"service", "message", "severity", "@timestamp"}, "generic_service", "Generic Service Log"),
        ({"action", "src_ip", "dest_ip", "rule", "app"}, "palo_alto", "Palo Alto Traffic"),
        ({"EventTime", "Hostname", "Keywords", "EventType"}, "windows_evtx", "Windows Event"),
        ({"time", "level", "msg", "logger"}, "generic_application", "Application Log"),
        ({"level", "msg", "time", "logger"}, "generic_application", "Application Log"),
        ({"timestamp", "message", "level", "thread"}, "generic_application", "Application Log"),
        ({"time", "level", "message"}, "generic_application", "Application Log"),
    ]

    @staticmethod
    def _get_nested(payload: Dict[str, Any], dotted_key: str, default: Any = "") -> Any:
        parts = dotted_key.split(".")
        current: Any = payload
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, {})
            else:
                return default
        return current if current != {} else default

    @staticmethod
    def _score_signature(payload: Dict[str, Any], fields: set[str]) -> tuple[int, int]:
        exact_matches = 0
        nested_matches = 0
        for field in fields:
            if "." in field:
                val = ParserRegistry._get_nested(payload, field)
                if val:
                    nested_matches += 1
            else:
                val = payload.get(field)
                if val:
                    exact_matches += 1
        return exact_matches, nested_matches

    @staticmethod
    def _detect_source(payload: Dict[str, Any]) -> tuple[str, str]:
        best_source = ""
        best_label = ""
        best_score = 0
        for fields, source, label in ParserRegistry._SOURCE_SIGNATURES:
            exact, nested = ParserRegistry._score_signature(payload, fields)
            total = exact + nested
            if total > best_score:
                best_score = total
                best_source = source
                best_label = label
        if best_score == 0:
            event_type = payload.get("event_type") or payload.get("type") or payload.get("category", "generic")
            return "", f"generic ({event_type})"
        return best_source, best_label

    @staticmethod
    def _infer_severity(payload: Dict[str, Any]) -> str:
        sev = (
            payload.get("severity") or payload.get("level") or
            payload.get("severity_level") or payload.get("priority") or ""
        )
        if isinstance(sev, int):
            if sev >= 8:
                return "critical"
            if sev >= 6:
                return "high"
            if sev >= 4:
                return "medium"
            if sev >= 2:
                return "low"
            return "info"
        sev_lower = str(sev).lower()
        sev_map = {
            "critical": "critical", "crit": "critical", "emerg": "critical",
            "emergency": "critical", "fatal": "critical", "panic": "critical",
            "high": "high", "error": "high", "err": "high",
            "medium": "medium", "warn": "medium", "warning": "medium",
            "low": "low", "debug": "low", "trace": "debug",
            "info": "info", "informational": "info", "notice": "info",
        }
        if sev_lower in sev_map:
            return sev_map[sev_lower]

        http_code = None
        for key in ("status", "http_status", "status_code", "response_code", "code"):
            val = payload.get(key)
            if isinstance(val, int):
                http_code = val
                break
            if isinstance(val, str) and val.isdigit():
                http_code = int(val)
                break
        if http_code:
            if http_code >= 500:
                return "high"
            if http_code >= 400:
                return "medium"
            if http_code >= 300:
                return "info"
            return "info"

        msg = str(payload.get("message", payload.get("msg", payload.get("log", ""))))
        msg_lower = msg.lower()
        if any(w in msg_lower for w in ("critical", "fatal", "emergency", "panic")):
            return "critical"
        if any(w in msg_lower for w in ("error", "exception", "traceback", "failed", "crash")):
            return "high"
        if any(w in msg_lower for w in ("warn", "timeout", "unable")):
            return "medium"

        return "info"

    def parse_json(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        source_key, source_label = self._detect_source(payload)
        severity = self._infer_severity(payload)

        timestamp = (
            payload.get("@timestamp") or payload.get("timestamp") or payload.get("time") or
            payload.get("date") or payload.get("datetime") or payload.get("event_time") or
            payload.get("EventTime") or payload.get("@time") or ""
        )

        message = (
            payload.get("message") or payload.get("msg") or payload.get("log") or
            payload.get("Message") or payload.get("event_message") or ""
        )

        source_ip = (
            payload.get("src_ip") or payload.get("source_ip") or payload.get("ip_address") or
            payload.get("sourceAddress") or payload.get("SourceAddress") or
            payload.get("remote_addr") or payload.get("callerIpAddress") or
            payload.get("sourceIPAddress") or payload.get("srcip") or ""
        )

        dest_ip = (
            payload.get("dest_ip") or payload.get("destination_ip") or payload.get("dest_ip") or
            payload.get("destinationAddress") or payload.get("DestinationAddress") or
            payload.get("dest_ip") or payload.get("dst_ip") or payload.get("dst") or ""
        )

        source_port = payload.get("src_port") or payload.get("source_port") or payload.get("sport") or 0
        dest_port = payload.get("dest_port") or payload.get("destination_port") or payload.get("dport") or 0
        if isinstance(source_port, str):
            try:
                source_port = int(source_port)
            except ValueError:
                source_port = 0
        if isinstance(dest_port, str):
            try:
                dest_port = int(dest_port)
            except ValueError:
                dest_port = 0

        protocol = payload.get("protocol") or payload.get("proto") or ""
        user = payload.get("user") or payload.get("username") or payload.get("usr") or payload.get("user_name") or ""
        device_id = payload.get("device_id") or payload.get("host") or payload.get("hostname") or payload.get("Hostname") or ""

        _known_fields = {
            "@timestamp", "timestamp", "time", "date", "datetime", "event_time", "EventTime", "@time",
            "message", "msg", "log", "Message", "event_message",
            "src_ip", "source_ip", "ip_address", "sourceAddress", "SourceAddress", "remote_addr",
            "callerIpAddress", "sourceIPAddress", "srcip",
            "dest_ip", "destination_ip", "destinationAddress", "DestinationAddress", "dst_ip", "dst",
            "src_port", "source_port", "sport", "dest_port", "destination_port", "dport",
            "protocol", "proto",
            "user", "username", "usr", "user_name",
            "device_id", "host", "hostname", "Hostname",
            "severity", "level", "severity_level", "priority",
            "event_type", "type", "category",
            "status", "http_status", "status_code", "response_code", "code",
        }

        metadata = {k: v for k, v in payload.items() if k not in _known_fields and not k.startswith("@")}
        if source_key:
            metadata["_parser_hint"] = source_key
            metadata["_parser_hint_label"] = source_label

        event_type = (
            payload.get("event_type") or payload.get("type") or
            payload.get("category") or payload.get("eventType") or
            "generic"
        )
        if source_key:
            event_type = source_key

        result = {
            "event_type": event_type,
            "severity": severity,
            "source_ip": str(source_ip) if source_ip else "",
            "dest_ip": str(dest_ip) if dest_ip else "",
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "user": user,
            "device_id": device_id,
            "message": str(message) if message else "",
            "timestamp": str(timestamp) if timestamp else "",
            "metadata": metadata,
        }

        return result
