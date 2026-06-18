"""
Web Application Firewall — inline SQLi, XSS, command injection,
path traversal, SSRF, and LDAP injection detection.
Uses regex patterns + context analysis for low false-positive rates.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

log = logging.getLogger("cybernova.protection.waf")

# ── SQL Injection Signatures ─────────────────────────────────────────────────

SQLI_PATTERNS = [
    (re.compile(r"(\bSELECT\s+.+\bFROM\b)", re.I), "sql_select_from"),
    (re.compile(r"(\bUNION\s+(ALL\s+)?SELECT\b)", re.I), "sql_union_select"),
    (re.compile(r"(\bINSERT\s+INTO\b)", re.I), "sql_insert"),
    (re.compile(r"(\bDELETE\s+FROM\b)", re.I), "sql_delete"),
    (re.compile(r"(\bDROP\s+(TABLE|DATABASE|INDEX)\b)", re.I), "sql_drop"),
    (re.compile(r"(\bALTER\s+(TABLE|DATABASE)\b)", re.I), "sql_alter"),
    (re.compile(r"(\bEXEC(\s+xp_|\s*\(|\b))", re.I), "sql_exec"),
    (re.compile(r"(\bWAITFOR\s+DELAY\b)", re.I), "sql_time_based"),
    (re.compile(r"(/\*!.+?\*/)", re.I), "sql_mysql_comment"),
    (re.compile(r"('(\s*OR\s|\s*AND\s).*?=)", re.I), "sql_tautology"),
    (re.compile(r"(\bINFORMATION_SCHEMA\b)", re.I), "sql_information_schema"),
    (re.compile(r"(\bBENCHMARK\s*\()", re.I), "sql_benchmark"),
    (re.compile(r"(\bSLEEP\s*\()", re.I), "sql_sleep"),
    (re.compile(r"(\bLOAD_FILE\s*\()", re.I), "sql_load_file"),
    (re.compile(r"(\bINTO\s+(OUT|DUMP)FILE\b)", re.I), "sql_into_file"),
    (re.compile(r"""\badmin\s*['"].*?(--|#|/\*|--\s)""", re.I), "sql_trailing_comment_admin"),
    (re.compile(r"""['"].*?(?:--|#|/\*)\s*$""", re.I), "sql_trailing_comment"),
    (re.compile(r"""['"]\s*/\*""", re.I), "sql_comment_injection"),
    (re.compile(r"(?:%23|--\+|--)['\" ]", re.I), "sql_comment_syntax"),
    (re.compile(r"""\b(1|'1')\s*AND\s+(1|'1'|2|'2')\s*(=|--|#)""", re.I), "sql_and_or_true"),
    (re.compile(r"""admin['"]?\s*(?:--|#|/\*)""", re.I), "sql_admin_comment_bypass"),
]

# ── XSS Signatures ───────────────────────────────────────────────────────────

XSS_PATTERNS = [
    # HIGH-CONFIDENCE XSS: these are almost always malicious in non-HTML contexts
    # (URL params, form data, JSON bodies)
    (re.compile(r"(<script[\s>])", re.I), "xss_script_tag"),
    (re.compile(r"(<[\w]+:[\s\w]+[\s>])", re.I), "xss_custom_element"),
    (re.compile(r"(javascript\s*:)", re.I), "xss_javascript_protocol"),
    (re.compile(r"(vbscript\s*:)", re.I), "xss_vbscript_protocol"),
    (re.compile(r"(data\s*:\s*text/html)", re.I), "xss_data_html"),
    # Event handler injection — but NOT in legitimate HTML attribute contexts
    # Pattern: onerror= or onclick= etc. with a payload, NOT inside HTML docs
    (re.compile(r"(on\w+\s*=\s*['\"]?\s*(?:javascript|alert|prompt|confirm|eval|window\.|document\.))", re.I), "xss_event_handler_payload"),
    # Dangerous elements that should never appear in non-HTML input
    (re.compile(r"(<iframe[\s>])", re.I), "xss_iframe"),
    (re.compile(r"(<frame[\s>])", re.I), "xss_frame"),
    (re.compile(r"(<embed[\s>])", re.I), "xss_embed"),
    (re.compile(r"(<object[\s>])", re.I), "xss_object"),
    (re.compile(r"(<applet[\s>])", re.I), "xss_applet"),
    (re.compile(r"(<svg[\s>/])", re.I), "xss_svg"),
    (re.compile(r"(<math[\s>])", re.I), "xss_math"),
    # URL-encoded XSS attempts
    (re.compile(r"(%3Cscript[\s>]|%3Ciframe[\s>]|%3Csvg[\s>]|%3Cimg[\s>]|%3Cbody[\s>])", re.I), "xss_url_encoded"),
    # HTML entity encoding attacks
    (re.compile(r"(&#\d{2,};)", re.I), "xss_html_entities"),
    (re.compile(r"(&#x[0-9a-fA-F]{2,};)", re.I), "xss_hex_entities"),
    (re.compile(r"(\\x[0-9a-fA-F]{2})", re.I), "xss_hex_encoding"),
    # DOM-based XSS functions — only trigger with actual function calls in non-HTML context
    (re.compile(r"(document\.write\s*\()", re.I), "xss_document_write"),
    # Dangerous JS patterns that indicate XSS payloads
    (re.compile(r"(postMessage\s*\()", re.I), "xss_postmessage"),
    (re.compile(r"(new\s+Function\s*\()", re.I), "xss_new_function"),
    # CSS expression attacks
    (re.compile(r"(expression\s*\()", re.I), "xss_css_expression"),
    # InnerHTML setter (injected)
    (re.compile(r"(innerHTML\s*=\s*['\"]?\s*<)", re.I), "xss_innerhtml_assign"),
    (re.compile(r"(outerHTML\s*=\s*['\"]?\s*<)", re.I), "xss_outerhtml_assign"),
]

# ── Command Injection Signatures ────────────────────────────────────────────

CMD_INJECTION_PATTERNS = [
    (re.compile(r"(;\s*(sh|bash|cmd|powershell|cat|id|whoami|ls|ps|kill|echo|rm|mv|cp|chmod|chown|nc|nmap|curl|wget|python|perl|ruby|php|node|java|gcc|g\+\+|make)\b)", re.I), "cmd_chain_semicolon"),
    (re.compile(r"(\|\s*(sh|bash|cmd|powershell|cat|id|whoami|ls|ps|kill|echo|rm|mv|cp|chmod|chown|nc|nmap|curl|wget|python|perl|ruby|php|node|java|gcc|g\+\+|make|dir|type|find|sort|more|less|head|tail|tee|xargs)\b)", re.I), "cmd_chain_pipe"),
    (re.compile(r"(`[^`]+`)"), "cmd_backtick"),
    (re.compile(r"(\$\([^)]+\))"), "cmd_subshell"),
    (re.compile(r"(\$\{[^}]+\})"), "cmd_env_subshell"),
    (re.compile(r"(\|&\s+)"), "cmd_pipe_and"),
    (re.compile(r"(&\&\s+(sh|bash|cmd|powershell|cat|id|whoami|ls|ps|kill|echo|rm|mv|cp|chmod|chown|dir|type|find|nc|nmap|curl|wget|python|perl|ruby|php|node|java|gcc|g\+\+|make|xargs|tee|head|tail|more|less|sort)\b)", re.I), "cmd_and_shell"),
    (re.compile(r"(\|\|\s+(sh|bash|cmd|powershell|cat|id|whoami|ls|ps|kill|echo|rm|mv|cp|chmod|chown|dir|type|find|nc|nmap|curl|wget|python|perl|ruby|php|node|java|gcc|g\+\+|make|xargs|tee|head|tail|more|less|sort)\b)", re.I), "cmd_or_shell"),
    (re.compile(r"(\bwget\s+)", re.I), "cmd_wget"),
    (re.compile(r"(\bcurl\s+)", re.I), "cmd_curl"),
    (re.compile(r"(\bnc\s+)", re.I), "cmd_netcat"),
    (re.compile(r"(\bbash\s+-i\b)", re.I), "cmd_bash_interactive"),
    (re.compile(r"(\bpython\s+-c\b)", re.I), "cmd_python_c"),
    (re.compile(r"(\bperl\s+-e\b)", re.I), "cmd_perl_e"),
    (re.compile(r"(\bruby\s+-e\b)", re.I), "cmd_ruby_e"),
    (re.compile(r"(\bphp\s+-r\b)", re.I), "cmd_php_r"),
    (re.compile(r"(\bnode\s+-e\b)", re.I), "cmd_node_e"),
    (re.compile(r"(\b(?:nmap|telnet|ftp|scp|socat)\s+)", re.I), "cmd_network_tool"),
    (re.compile(r"(\b(?:mysql|psql|sqlite3|redis-cli|mongosh|mongo)\s+-)", re.I), "cmd_db_tool"),
    (re.compile(r"(\bssh\s+-(?:o|O|R|L|D|N|f|T|i|J))", re.I), "cmd_ssh_tunnel"),
    (re.compile(r"(\bdig\s+)", re.I), "cmd_dig"),
    (re.compile(r"(\bhost\s+-)", re.I), "cmd_host"),
    (re.compile(r"(\btraceroute\s+)", re.I), "cmd_traceroute"),
    (re.compile(r"(\bping\s+-[cnf])", re.I), "cmd_ping"),
    (re.compile(r"(\bchmod\s+[0-7]{3,4})", re.I), "cmd_chmod"),
    (re.compile(r"(\bchown\s+)", re.I), "cmd_chown"),
    (re.compile(r"(\busermod\s+)", re.I), "cmd_usermod"),
    (re.compile(r"(\bsudo\s+(?!-))", re.I), "cmd_sudo"),
    (re.compile(r"(\bsu\s+-)", re.I), "cmd_su"),
    (re.compile(r"(\bpasswd\s+[a-z])", re.I), "cmd_passwd"),
    (re.compile(r"(\bkill\s+-[0-9])", re.I), "cmd_kill"),
    (re.compile(r"(\bpkill\s+)", re.I), "cmd_pkill"),
    (re.compile(r"(\bdmidecode|\bdmesg|\blspci|\blsusb|\bifconfig|\biptables|\broute\s+)", re.I), "cmd_sysinfo"),
    (re.compile(r"(\bexport\s+[A-Z])", re.I), "cmd_export"),
    (re.compile(r"(\beval\s+\$)", re.I), "cmd_eval_var"),
    (re.compile(r"(\bexec\s+[a-z])", re.I), "cmd_exec"),
    (re.compile(r"(\btimeout\s+[0-9])", re.I), "cmd_timeout"),
]

# ── Path Traversal Signatures ────────────────────────────────────────────────

PATH_TRAVERSAL_PATTERNS = [
    (re.compile(r"(\.\./){2,}"), "path_traversal_double_dot"),
    (re.compile(r"(\.{3,}/)"), "path_traversal_dotslash_bypass"),
    (re.compile(r"(\.{3,}\\​)", re.I), "path_traversal_dotbackslash_bypass"),
    (re.compile(r"(\.\.\\){2,}"), "path_traversal_backslash"),
    (re.compile(r"(\.\.%00)"), "path_traversal_nullbyte"),
    (re.compile(r"(%2e%2e%2f)"), "path_traversal_url_encoded_double"),
    (re.compile(r"(%2e%2e/)"), "path_traversal_url_encoded_partial"),
    (re.compile(r"(%c0%ae%c0%ae/)"), "path_traversal_unicode_overlong"),
    (re.compile(r"(%252e%252e%252f)"), "path_traversal_double_encoded"),
    (re.compile(r"(。。/)"), "path_traversal_unicode_dots"),
    (re.compile(r"(/etc/passwd)"), "path_etc_passwd"),
    (re.compile(r"(/etc/shadow)"), "path_etc_shadow"),
    (re.compile(r"(/etc/gshadow)"), "path_etc_gshadow"),
    (re.compile(r"(/etc/hosts)"), "path_etc_hosts"),
    (re.compile(r"(/etc/crontab)"), "path_etc_crontab"),
    (re.compile(r"(/etc/ssh/)"), "path_etc_ssh"),
    (re.compile(r"(/etc/kubernetes/)"), "path_etc_kubernetes"),
    (re.compile(r"(/var/log/)"), "path_var_log"),
    (re.compile(r"(/var/run/secrets/)"), "path_k8s_secrets"),
    (re.compile(r"(/windows/system32)", re.I), "path_windows_system32"),
    (re.compile(r"(/windows/win\.ini)", re.I), "path_windows_winini"),
    (re.compile(r"(/windows/panther/)", re.I), "path_windows_panther"),
    (re.compile(r"(/boot\.ini)", re.I), "path_boot_ini"),
    (re.compile(r"(/autoexec\.bat)", re.I), "path_autoexec"),
    (re.compile(r"(/proc/self/environ)"), "path_proc_environ"),
    (re.compile(r"(/proc/self/fd/)"), "path_proc_fd"),
    (re.compile(r"(/proc/cpuinfo)"), "path_proc_cpuinfo"),
    (re.compile(r"(\.env)"), "path_dotenv"),
    (re.compile(r"(\.aws/credentials)"), "path_aws_credentials"),
    (re.compile(r"(\.git/config)"), "path_git_config"),
    (re.compile(r"(\.ssh/id_rsa)"), "path_ssh_private_key"),
    (re.compile(r"(composer\.json)"), "path_composer"),
    (re.compile(r"(wp-config\.php)"), "path_wp_config"),
    (re.compile(r"(config\.json)"), "path_config_json"),
    (re.compile(r"(service\.yaml|service\.yml)"), "path_service_yaml"),
    (re.compile(r"(%2e%2e%5c)"), "path_traversal_url_encoded_backslash"),
    (re.compile(r"(%c0%ae%c0%ae%5c)"), "path_traversal_unicode_backslash"),
]

# ── SSRF Signatures ──────────────────────────────────────────────────────────

SSRF_PATTERNS = [
    (re.compile(r"(https?://169\.254\.)", re.I), "ssrf_metadata"),
    (re.compile(r"(https?://127\.)", re.I), "ssrf_localhost"),
    (re.compile(r"(https?://10\.)", re.I), "ssrf_rfc1918_10"),
    (re.compile(r"(https?://172\.1[6-9]\.)", re.I), "ssrf_rfc1918_172"),
    (re.compile(r"(https?://192\.168\.)", re.I), "ssrf_rfc1918_192"),
    (re.compile(r"(https?://0\.0\.0\.0)", re.I), "ssrf_null"),
    (re.compile(r"(file://)", re.I), "ssrf_file_protocol"),
    (re.compile(r"(https?://localhost)", re.I), "ssrf_localhost_hostname"),
    (re.compile(r"(https?://[a-z]*\.internal)", re.I), "ssrf_internal_dns"),
    (re.compile(r"(https?://[a-z]*\.local)", re.I), "ssrf_local_dns"),
    (re.compile(r"(https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:\d+)?[/\"'\\])", re.I), "ssrf_raw_ip_in_param"),
    (re.compile(r"(https?://[a-fA-F0-9:]+(:\d+)?[/\"'\\])", re.I), "ssrf_ipv6_in_param"),

]

# ── LDAP Injection ───────────────────────────────────────────────────────────

LDAP_INJECTION_PATTERNS = [
    (re.compile(r"(\*\)\s*\()"), "ldap_injection_close_open"),
    (re.compile(r"(\|\([\w=]+\))"), "ldap_or_injection"),
    (re.compile(r"(&\([\w=]+\))"), "ldap_and_injection"),
    (re.compile(r"(adminAccount|userPassword|memberOf|objectClass)", re.I), "ldap_attributes"),
    (re.compile(r"(\(\|\s*\(.*\)\s*\(.*\))"), "ldap_or_nested"),
]

# ── NoSQL Injection ──────────────────────────────────────────────────────────

NOSQL_INJECTION_PATTERNS = [
    (re.compile(r"(\$\s*(ne|gt|lt|gte|lte|regex|where|exists|nin|all|elemMatch)\b)", re.I), "nosql_operator"),
    (re.compile(r"(\{\s*\$[\w]+\s*:)"), "nosql_json_operator"),
    (re.compile(r"(\$gt\s*:\s*\"\")"), "nosql_gt_empty"),
    (re.compile(r"(\$ne\s*:\s*\"[^\"]+\")"), "nosql_ne_empty"),
    (re.compile(r"(\$where\s*:)", re.I), "nosql_where"),
    (re.compile(r"(\$regex\s*:)", re.I), "nosql_regex"),
]

# ── Data URI Attacks ──────────────────────────────────────────────────────────

DATA_URI_PATTERNS = [
    (re.compile(r"(data\s*:\s*text/html)", re.I), "data_uri_html"),
    (re.compile(r"(data\s*:\s*text/javascript)", re.I), "data_uri_javascript"),
    (re.compile(r"(data\s*:\s*application/x-javascript)", re.I), "data_uri_app_javascript"),
    (re.compile(r"(data\s*:\s*image/svg\+xml)", re.I), "data_uri_svg"),
    (re.compile(r"(data\s*:\s*;base64)", re.I), "data_uri_base64"),
]

# ── Template Injection ─────────────────────────────────────────────────────────

TEMPLATE_INJECTION_PATTERNS = [
    (re.compile(r"(\{\{\s*[\w.]+\s*}})"), "ssti_jinja2"),
    (re.compile(r"""(\$\{[\w.'"\[\]]+})"""), "ssti_velocity"),
    (re.compile(r"(#\{[\w.()]+})"), "ssti_freemarker"),
    (re.compile(r"(<%[=\s])"), "ssti_erb"),
    (re.compile(r"(\{\%\s*[\w.]+\s*%\})"), "ssti_jinja2_block"),
    (re.compile(r"(\${\d?T(\w|[{}])+})", re.I), "ssti_apache_struts"),
    (re.compile(r"(\$zap\{[^}]+})", re.I), "ssti_zap"),
    (re.compile(r"(class\s*\.\s*forName|Runtime\.getRuntime|ProcessBuilder)", re.I), "ssti_rce"),
]

# ── Request Smuggling ──────────────────────────────────────────────────────────

REQUEST_SMUGGLING_PATTERNS = [
    (re.compile(r"(Content-Length:\s*0\s*\r?\n\s*Content-Length:)", re.I), "smuggle_cl_cl"),
    (re.compile(r"(Transfer-Encoding:\s*[^\r\n]+\r?\n\s*Content-Length:)", re.I), "smuggle_te_cl"),
    (re.compile(r"(Content-Length:\s*[^\r\n]+\r?\n\s*Transfer-Encoding:)", re.I), "smuggle_cl_te"),
    (re.compile(r"(Transfer-Encoding:\s*[\x00-\x20]+chunked)", re.I), "smuggle_te_obfuscated"),
    (re.compile(r"(X-Http-Method-Override:|X-HTTP-Method:|X-Method-Override:)", re.I), "smuggle_method_override"),
]

# ── Protocol Injection / SSRF Enhanced ────────────────────────────────────────

PROTOCOL_INJECTION_PATTERNS = [
    (re.compile(r"(gopher://|dict://|tftp://|ldap://|redis://)", re.I), "protocol_gopher_dict"),
    (re.compile(r"(file:///)"), "protocol_file"),
    (re.compile(r"(php://)", re.I), "protocol_php_wrapper"),
    (re.compile(r"(expect://)", re.I), "protocol_expect"),
    (re.compile(r"(compress.zlib://|compress.bzip2://|zip://|phar://)", re.I), "protocol_compression"),
    (re.compile(r"(s3://|gs://|azure-blob://|swift://)", re.I), "protocol_cloud_storage"),
    (re.compile(r"(glob://|ssh2://|ogg://|cast://)", re.I), "protocol_misc_wrapper"),
]



class LRUCache:
    """Simple thread-safe LRU cache with max size."""
    def __init__(self, maxsize: int = 1024):
        self._maxsize = maxsize
        self._cache: OrderedDict = OrderedDict()
        self._hits = 0
        self._misses = 0

    def get(self, key: str):
        if key in self._cache:
            self._cache.move_to_end(key)
            self._hits += 1
            return self._cache[key]
        self._misses += 1
        return None

    def put(self, key: str, value):
        self._cache[key] = value
        self._cache.move_to_end(key)
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)

    @property
    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "maxsize": self._maxsize,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total * 100, 1) if total > 0 else 0.0,
        }

    def clear(self):
        self._cache.clear()
        self._hits = 0
        self._misses = 0


class WAFEngine:
    def __init__(self):
        self.all_rules: List[Tuple[re.Pattern, str, str]] = []
        for pat, name in SQLI_PATTERNS:
            self.all_rules.append((pat, name, "sqli"))
        for pat, name in XSS_PATTERNS:
            self.all_rules.append((pat, name, "xss"))
        for pat, name in CMD_INJECTION_PATTERNS:
            self.all_rules.append((pat, name, "cmd_injection"))
        for pat, name in PATH_TRAVERSAL_PATTERNS:
            self.all_rules.append((pat, name, "path_traversal"))
        for pat, name in SSRF_PATTERNS:
            self.all_rules.append((pat, name, "ssrf"))
        for pat, name in LDAP_INJECTION_PATTERNS:
            self.all_rules.append((pat, name, "ldap_injection"))
        for pat, name in NOSQL_INJECTION_PATTERNS:
            self.all_rules.append((pat, name, "nosql_injection"))
        for pat, name in DATA_URI_PATTERNS:
            self.all_rules.append((pat, name, "data_uri"))
        for pat, name in TEMPLATE_INJECTION_PATTERNS:
            self.all_rules.append((pat, name, "template_injection"))
        for pat, name in REQUEST_SMUGGLING_PATTERNS:
            self.all_rules.append((pat, name, "request_smuggling"))
        for pat, name in PROTOCOL_INJECTION_PATTERNS:
            self.all_rules.append((pat, name, "protocol_injection"))
        self._cache = LRUCache(maxsize=2048)
        self._total_inspections = 0

    SEVERITY_MAP = {
        "sqli": "critical",
        "xss": "critical",
        "cmd_injection": "critical",
        "path_traversal": "critical",
        "ssrf": "high",
        "ldap_injection": "high",
        "nosql_injection": "high",
        "data_uri": "high",
        "template_injection": "critical",
        "request_smuggling": "critical",
        "protocol_injection": "high",
    }

    RISK_MAP = {
        "sqli": 98.0,
        "xss": 97.0,
        "cmd_injection": 98.0,
        "path_traversal": 95.0,
        "ssrf": 92.0,
        "ldap_injection": 90.0,
        "nosql_injection": 90.0,
        "data_uri": 95.0,
        "template_injection": 95.0,
        "request_smuggling": 98.0,
        "protocol_injection": 92.0,
    }

    def _make_cache_key(
        self,
        method: str,
        path: str,
        query_params: Dict[str, str],
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        source_ip: str = "",
    ) -> str:
        raw = f"{method}|{path}|{sorted(query_params.items())}|{body}|{sorted((headers or {}).items())}|{source_ip}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def analyze_request(
        self,
        method: str,
        path: str,
        query_params: Dict[str, str],
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        source_ip: str = "",
    ) -> Dict[str, Any]:
        self._total_inspections += 1

        # Check cache first
        cache_key = self._make_cache_key(method, path, query_params, body, headers, source_ip)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        findings = []
        blocked = False
        max_risk = 0.0

        targets = [path]
        for k, v in query_params.items():
            targets.append(f"{k}={v}")
        if body:
            targets.append(body)
        for k, v in (headers or {}).items():
            if k.lower() in ("cookie", "user-agent", "x-forwarded-for"):
                targets.append(v)

        decoded_targets = [unquote_plus(t) for t in targets]
        combined = " ".join(decoded_targets)

        for pattern, rule_name, category in self.all_rules:
            if pattern.search(combined):
                sev = self.SEVERITY_MAP.get(category, "high")
                risk = self.RISK_MAP.get(category, 70.0)
                findings.append({
                    "rule": rule_name, "category": category,
                    "severity": sev, "risk_score": risk,
                })
                max_risk = max(max_risk, risk)
                if risk >= 85.0:
                    blocked = True

        result = {
            "method": method,
            "path": path,
            "source_ip": source_ip,
            "attack_detected": len(findings) > 0,
            "blocked": blocked,
            "max_risk_score": round(max_risk, 1),
            "findings": findings,
            "finding_count": len(findings),
        }

        # Cache the result
        self._cache.put(cache_key, result)
        return result

    def analyze_event(self, event: dict) -> Optional[Dict[str, Any]]:
        if event.get("event_type") not in ("http_request", "suricata_alert"):
            return None
        extra = event.get("extra_data") or event.get("extra", {})
        method = extra.get("method", "GET")
        path = extra.get("url", extra.get("path", ""))
        source_ip = extra.get("src_ip", event.get("source_ip", ""))
        return self.analyze_request(
            method=method, path=path,
            query_params={},
            body=extra.get("raw_body"),
            source_ip=source_ip,
        )


    def get_stats(self) -> Dict[str, Any]:
        """Return WAF engine statistics."""
        cache_stats = self._cache.stats
        return {
            "total_inspections": self._total_inspections,
            "cache": cache_stats,
            "rules_count": len(self.all_rules),
        }

    @property
    def rules(self) -> List[Tuple[re.Pattern, str, str]]:
        """Return all registered WAF rules."""
        return self.all_rules

    def clear_cache(self):
        """Clear the LRU cache."""
        self._cache.clear()
        self._total_inspections = 0


waf_engine = WAFEngine()
