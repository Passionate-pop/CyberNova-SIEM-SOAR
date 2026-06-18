from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

log = logging.getLogger("cybernova.protection.app_shield")

SQLI_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.I), "sqli_union_select", 95),
    (re.compile(r"\bSELECT\b.{1,60}\bFROM\b", re.I), "sqli_select_from", 88),
    (re.compile(r"\bINSERT\s+INTO\b", re.I), "sqli_insert", 85),
    (re.compile(r"\bDELETE\s+FROM\b", re.I), "sqli_delete", 88),
    (re.compile(r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE)\b", re.I), "sqli_drop", 92),
    (re.compile(r"\bALTER\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE)\b", re.I), "sqli_alter", 88),
    (re.compile(r"\bEXEC(\s+xp_|\s*\(|\b)", re.I), "sqli_exec", 90),
    (re.compile(r"\bWAITFOR\s+DELAY\b", re.I), "sqli_time_based", 92),
    (re.compile(r"\bSLEEP\s*\(", re.I), "sqli_sleep", 92),
    (re.compile(r"\bBENCHMARK\s*\(", re.I), "sqli_benchmark", 92),
    (re.compile(r"/\*!.+?\*/", re.I), "sqli_mysql_comment", 80),
    (re.compile(r"'(\s*OR\b|\s*AND\b).{1,40}=", re.I), "sqli_tautology", 85),
    (re.compile(r"\bINFORMATION_SCHEMA\b", re.I), "sqli_information_schema", 82),
    (re.compile(r"\bLOAD_FILE\s*\(", re.I), "sqli_load_file", 88),
    (re.compile(r"\bINTO\s+(OUT|DUMP)FILE\b", re.I), "sqli_into_file", 90),
    (re.compile(r"\b(OR|AND)\s+1\s*=\s*1\b", re.I), "sqli_basic_auth_bypass", 85),
    (re.compile(r"';\s*(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER)\b", re.I), "sqli_stacked_queries", 95),
    (re.compile(r"'\s*(OR|AND)\s+['\"]?[0-9a-fA-F]+\s*=\s*['\"]?[0-9a-fA-F]+", re.I), "sqli_hex_bypass", 82),
    (re.compile(r"(xp_cmdshell|xp_regread|xp_regwrite|xp_servicecontrol)", re.I), "sqli_xp_cmdshell", 95),
    (re.compile(r"--[ \t\r\n]|#|/\*", re.I), "sqli_comment_injection", 75),
]

XSS_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"<script[\s>/]", re.I), "xss_script_tag", 90),
    (re.compile(r"javascript\s*:", re.I), "xss_javascript_protocol", 85),
    (re.compile(r"on\w+\s*=", re.I), "xss_event_handler", 88),
    (re.compile(r"<iframe[\s>/]", re.I), "xss_iframe", 88),
    (re.compile(r"<embed[\s>/]", re.I), "xss_embed", 85),
    (re.compile(r"<object[\s>/]", re.I), "xss_object", 85),
    (re.compile(r"<svg[\s>/]", re.I), "xss_svg", 80),
    (re.compile(r"eval\s*\(", re.I), "xss_eval", 88),
    (re.compile(r"String\.fromCharCode", re.I), "xss_fromcharcode", 82),
    (re.compile(r"<link[\s>/]", re.I), "xss_link", 75),
    (re.compile(r"<style[\s>/]", re.I), "xss_style", 75),
    (re.compile(r"<math[\s>/]", re.I), "xss_math", 75),
    (re.compile(r"<marquee[\s>/]", re.I), "xss_marquee", 60),
    (re.compile(r"<details[\s>/]", re.I), "xss_details", 60),
    (re.compile(r"document\.(cookie|location|domain|write|writeln)", re.I), "xss_dom_access", 82),
    (re.compile(r"alert\s*\(\s*(document\.cookie|document\.domain)", re.I), "xss_cookie_theft", 95),
    (re.compile(r"%3Cscript[\s>]|%3Ciframe[\s>]|%3Csvg[\s>]", re.I), "xss_url_encoded", 85),
    (re.compile(r"&#x?[0-9a-fA-F]{2,4};", re.I), "xss_html_entities", 70),
    (re.compile(r"<[^>]*src\s*=\s*['\"]?\s*(javascript|data:text/html)", re.I), "xss_src_javascript", 88),
]

CMD_INJECTION_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r";\s*(sh|bash|cmd|powershell|cmd\.exe)\b", re.I), "cmd_injection_shell", 95),
    (re.compile(r"\|\s*(sh|bash|cmd|powershell)\b", re.I), "cmd_pipe_shell", 95),
    (re.compile(r"`[^`]+`"), "cmd_backtick", 92),
    (re.compile(r"\$\([^)]+\)"), "cmd_subshell", 92),
    (re.compile(r"\b(wget|curl|nc|ncat|netcat)\s+", re.I), "cmd_download", 88),
    (re.compile(r"\b(python|perl|ruby|php)\s+-[ce]\s+", re.I), "cmd_interpreter", 90),
    (re.compile(r"\bbash\s+-i\b", re.I), "cmd_bash_interactive", 95),
    (re.compile(r"\|&\s*", re.I), "cmd_pipe_and", 88),
    (re.compile(r"\|\|\s*(sh|bash|cmd|powershell)", re.I), "cmd_or_shell", 92),
    (re.compile(r"&&\s*(sh|bash|cmd|powershell)", re.I), "cmd_and_shell", 92),
    (re.compile(r">>\s*/etc/|>\s*/etc/|>\s*/var/|>\s*/tmp/", re.I), "cmd_redir_system", 90),
    (re.compile(r"\b(rm|mv|cp|chmod|chown|dd)\s+(-rf|--recursive|-r)\s+/", re.I), "cmd_destructive", 95),
    (re.compile(r"\b(apt-get|yum|dnf|apk)\s+install\s+", re.I), "cmd_package_install", 70),
    (re.compile(r"\b(iptables|ufw|firewall-cmd)\s+-[FPX]\s+", re.I), "cmd_firewall_change", 85),
]

PATH_TRAVERSAL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"(\.\./){2,}"), "path_traversal_dotdot", 82),
    (re.compile(r"(\.\.\\){2,}"), "path_traversal_backslash", 82),
    (re.compile(r"/etc/passwd"), "path_etc_passwd", 85),
    (re.compile(r"/etc/shadow"), "path_etc_shadow", 88),
    (re.compile(r"/etc/sudoers"), "path_etc_sudoers", 88),
    (re.compile(r"/windows/system32", re.I), "path_windows_system32", 80),
    (re.compile(r"boot\.ini"), "path_boot_ini", 75),
    (re.compile(r"%2e%2e%2f|%c0%ae%c0%ae/|\.\.%00"), "path_traversal_encoded", 88),
]

SSRF_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"^https?://169\.254\.", re.I), "ssrf_metadata", 88),
    (re.compile(r"^https?://127\.", re.I), "ssrf_localhost", 82),
    (re.compile(r"^https?://0\.0\.0\.0", re.I), "ssrf_null", 82),
    (re.compile(r"^https?://10\.", re.I), "ssrf_rfc1918_10", 80),
    (re.compile(r"^https?://172\.1[6-9]\.", re.I), "ssrf_rfc1918_172", 80),
    (re.compile(r"^https?://192\.168\.", re.I), "ssrf_rfc1918_192", 80),
    (re.compile(r"^file://", re.I), "ssrf_file_protocol", 88),
    (re.compile(r"^gopher://", re.I), "ssrf_gopher", 90),
    (re.compile(r"^dict://", re.I), "ssrf_dict", 85),
    (re.compile(r"^ftp://", re.I), "ssrf_ftp", 70),
]

TEMPLATE_INJECTION: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\{\{.{1,100}}\}", re.I), "ssti_jinja", 88),
    (re.compile(r"#\{.{1,100}}"), "ssti_ruby", 85),
    (re.compile(r"\$\{.+\}"), "ssti_java", 82),
    (re.compile(r"<%.+%>"), "ssti_asp", 85),
    (re.compile(r"\{%.+%\}"), "ssti_jinja_block", 88),
    (re.compile(r"<t:template.+>", re.I), "ssti_java_template", 80),
]

NOSQL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\$\s*(ne|gt|lt|gte|lte|regex|where|exists|type)\b", re.I), "nosql_operator", 80),
    (re.compile(r"\{\s*\$[\w]+\s*:"), "nosql_json_operator", 82),
    (re.compile(r"\$gt\s*:\s*\"\""), "nosql_gt_empty", 85),
    (re.compile(r"\$ne\s*:\s*\"\""), "nosql_ne_empty", 85),
    (re.compile(r"\$where\s*:", re.I), "nosql_where", 88),
    (re.compile(r"\$regex\s*:", re.I), "nosql_regex", 80),
]

LDAP_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\*\)\s*\("), "ldap_close_open", 80),
    (re.compile(r"\|\([\w=]+\)"), "ldap_or_injection", 78),
    (re.compile(r"&\([\w=]+\)"), "ldap_and_injection", 78),
    (re.compile(r"\(\)\s*\(\)"), "ldap_empty_parens", 70),
]


class AppShield:
    def __init__(self):
        self._injection_count: Dict[str, int] = defaultdict(int)
        self._last_reset: float = time.time()

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        """Analyze an event for application-layer attacks (SQLi, XSS, CMDi, etc.)."""
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        path = extra.get("url", extra.get("path", ""))
        method = extra.get("method", "GET")
        body = extra.get("raw_body", extra.get("body", ""))
        query = extra.get("query_string", extra.get("query", ""))
        extra.get("headers", {})
        source_ip = event.get("source_ip", extra.get("src_ip", ""))
        combined_text = " ".join(filter(None, [method, path, query, body]))

        if etype not in ("http_request", "suricata_alert", "web_request", "api_request"):
            return results

        decoded = unquote(combined_text).replace("+", " ")
        self._scan_injections(decoded, results)
        self._check_rate(source_ip, results)
        self._check_exploit_mitigations(results)
        return results

    def _scan_injections(self, text: str, res: dict):
        all_patterns: List[Tuple[List[Tuple[re.Pattern, str, float]], str]] = [
            (SQLI_PATTERNS, "sqli"), (XSS_PATTERNS, "xss"),
            (CMD_INJECTION_PATTERNS, "cmd_injection"),
            (PATH_TRAVERSAL_PATTERNS, "path_traversal"),
            (SSRF_PATTERNS, "ssrf"),
            (TEMPLATE_INJECTION, "template_injection"),
            (NOSQL_PATTERNS, "nosql_injection"),
            (LDAP_PATTERNS, "ldap_injection"),
        ]
        for patterns, category in all_patterns:
            for pat, name, risk in patterns:
                if pat.search(text):
                    sev = "critical" if risk >= 85 else "high" if risk >= 70 else "medium"
                    event_type_map = {
                        "sqli": "sqli_detected", "xss": "xss_detected",
                        "cmd_injection": "cmd_injection_detected",
                        "path_traversal": "path_traversal_detected",
                        "ssrf": "ssrf_detected",
                        "template_injection": "template_injection_detected",
                        "nosql_injection": "nosql_injection_detected",
                        "ldap_injection": "ldap_injection_detected",
                    }
                    mapped = event_type_map.get(category, f"{category}_detected")
                    self._add_finding(res, mapped, f"{category.upper()} detected: {name}", risk, {
                        "category": category, "rule": name, "severity": sev,
                    })
                    break

    def _check_rate(self, source_ip: str, res: dict):
        now = time.time()
        if now - self._last_reset > 60:
            self._injection_count.clear()
            self._last_reset = now
        if not source_ip:
            return
        total = sum(self._injection_count.values())
        if total > 50:
            self._add_finding(res, "mass_injection_attempt", f"Mass injection wave: {total} attempts in 60s", 88, {"count": total})

    def _check_exploit_mitigations(self, res: dict):
        findings = []
        try:
            if Path("/proc/sys/kernel/randomize_va_space").exists():
                val = int(Path("/proc/sys/kernel/randomize_va_space").read_text().strip())
                if val == 0:
                    findings.append(("aslr_disabled", "ASLR is disabled — exploit mitigation missing", 95))
                elif val == 1:
                    findings.append(("aslr_partial", "ASLR set to partial (1) — recommend 2", 60))
            if Path("/proc/sys/kernel/exec-shield").exists():
                if Path("/proc/sys/kernel/exec-shield").read_text().strip() == "0":
                    findings.append(("execshield_disabled", "Exec Shield disabled — no NX protection", 90))
        except Exception as e:
            log.warning("Exploit mitigation check error: %s", e)
        for ftype, msg, risk in findings:
            self._add_finding(res, ftype, msg, risk, {})

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True
        self._injection_count[ftype] += 1


app_shield = AppShield()
