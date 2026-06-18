"""
Webshell Hunter — detects malicious web shells through signature analysis,
behavioral patterns, and file metadata anomalies.
Scans web directories for PHP, ASP, JSP, and Python-based webshells.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("cybernova.protection.webshell_hunter")

# ── PHP Webshell Signatures ─────────────────────────────────────────────────

PHP_WEBSHELL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"(\beval\s*\(\s*\$_)", re.I), "php_eval_input", 95.0),
    (re.compile(r"(\bassert\s*\(\s*\$_)", re.I), "php_assert_input", 95.0),
    (re.compile(r"(\bsystem\s*\(\s*\$_)", re.I), "php_system_input", 95.0),
    (re.compile(r"(\bshell_exec\s*\(\s*\$_)", re.I), "php_shellexec_input", 95.0),
    (re.compile(r"(\bexec\s*\(\s*\$_)", re.I), "php_exec_input", 90.0),
    (re.compile(r"(\bpopen\s*\(\s*\$_)", re.I), "php_popen_input", 90.0),
    (re.compile(r"(\bpassthru\s*\(\s*\$_)", re.I), "php_passthru_input", 90.0),
    (re.compile(r"(\bproc_open\s*\(\s*\$_)", re.I), "php_proc_open", 90.0),
    (re.compile(r"(preg_replace\s*\(\s*['\"]/.*e['\"])", re.I), "php_preg_replace_e", 90.0),
    (re.compile(r"(\bcreate_function\s*\(\s*['\"].*\$_)", re.I), "php_create_function", 85.0),
    (re.compile(r"(\$_\[\s*['\"]\w+['\"]\s*\]\s*\(\s*\$_)", re.I), "php_variable_function", 88.0),
    (re.compile(r"(\b(base64_decode|gzinflate|str_rot13)\s*\(\s*\$_)", re.I), "php_obfuscated_input", 88.0),
    (re.compile(r"(preg_replace\s*\(\s*['\"].*\.\$_)", re.I), "php_preg_replace_dynamic", 85.0),
    (re.compile(r"(\$_\[\s*\$_\[\b)", re.I), "php_nested_array_call", 92.0),
    (re.compile(r"(\bchmod\s*\(\s*\$_)", re.I), "php_chmod_input", 80.0),
    (re.compile(r"(@\s*(eval|assert|system|exec)\s*\()", re.I), "php_error_suppress_call", 90.0),
]

# ── ASP/ASP.NET Webshell Signatures ─────────────────────────────────────────

ASP_WEBSHELL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"(\bWScript\.Shell\b)", re.I), "asp_wscript_shell", 95.0),
    (re.compile(r"(\bServer\.CreateObject\s*\(\s*['\"]WScript)", re.I), "asp_create_wscript", 95.0),
    (re.compile(r"(\bProcess\.Start\b)", re.I), "asp_process_start", 90.0),
    (re.compile(r"(\bcmd\.exe\b|\bbash\b|\bbin/sh\b)", re.I), "asp_shell_cmd", 90.0),
    (re.compile(r"(\bRun\s*\(\s*['\"].*cmd)", re.I), "asp_run_cmd", 90.0),
    (re.compile(r"(\bExecute\s*\(\s*Request\b)", re.I), "asp_execute_request", 95.0),
    (re.compile(r"(\bEval\s*\(\s*Request\b)", re.I), "asp_eval_request", 95.0),
    (re.compile(r"(\bGetObject\s*\(\s*['\"]script:)", re.I), "asp_getobject_script", 88.0),
]

# ── Obfuscation / Encoding Indicators ──────────────────────────────────────

OBFUSCATION_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"(base64_decode\s*\(\s*['\"][A-Za-z0-9+/]{100,})"), "base64_large_decode", 80.0),
    (re.compile(r"(gzinflate\s*\(\s*base64_decode)"), "gzinflate_base64", 92.0),
    (re.compile(r"(str_rot13\s*\(\s*strrev\s*\()"), "str_rot13_strrev", 90.0),
    (re.compile(r"(eval\s*\(\s*gzinflate\s*\()"), "eval_gzinflate", 95.0),
    (re.compile(r"(chr\(\d{2,3}\)\.chr\(\d{2,3}\)\.chr)"), "chr_concat_obfuscation", 85.0),
    (re.compile(r"(\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})"), "hex_encoding_obfuscation", 80.0),
]

# ── Suspicious File Names / Extensions ──────────────────────────────────────

SUSPICIOUS_NAMES = [
    "shell", "webshell", "backdoor", "cmd", "eval", "uploader",
    "c99", "c100", "r57", "b374k", "andela", "404shell",
    "wso", "maika", "bypass", "safe0", "r00t", "1337",
]

SUSPICIOUS_EXTENSIONS = {".php", ".php5", ".phtml", ".asp", ".aspx", ".jsp",
                          ".jspx", ".cfm", ".shtml", ".py"}


def analyze_file(path: str, content: Optional[bytes] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "path": path, "is_webshell": False,
        "confidence": 0.0, "risk_score": 0.0,
        "findings": [], "indicators": [],
    }

    p = Path(path)
    ext = p.suffix.lower()
    if ext not in SUSPICIOUS_EXTENSIONS:
        return result

    name = p.stem.lower()
    for suspicious_name in SUSPICIOUS_NAMES:
        if suspicious_name in name:
            result["indicators"].append(f"suspicious_filename:{suspicious_name}")
            result["risk_score"] += 25.0
            result["findings"].append({
                "type": "suspicious_filename",
                "match": suspicious_name,
                "risk": 25.0,
            })

    if content is None:
        try:
            if p.exists():
                content = p.read_bytes()
            else:
                return result
        except (OSError, PermissionError) as e:
            log.warning("WebshellHunter: could not read file %s: %s", path, e)
            return result

    try:
        text = content.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, ValueError) as e:
        log.warning("WebshellHunter: could not decode file %s: %s", path, e)
        return result

    for pattern, rule_name, risk in PHP_WEBSHELL_PATTERNS:
        if pattern.search(text):
            result["findings"].append({"type": "php_webshell_signature", "rule": rule_name, "risk": risk})
            result["risk_score"] += risk * 0.7
            result["indicators"].append(f"php_sig:{rule_name}")

    for pattern, rule_name, risk in ASP_WEBSHELL_PATTERNS:
        if pattern.search(text):
            result["findings"].append({"type": "asp_webshell_signature", "rule": rule_name, "risk": risk})
            result["risk_score"] += risk * 0.7
            result["indicators"].append(f"asp_sig:{rule_name}")

    for pattern, rule_name, risk in OBFUSCATION_PATTERNS:
        if pattern.search(text):
            result["findings"].append({"type": "obfuscation", "rule": rule_name, "risk": risk})
            result["risk_score"] += risk * 0.6
            result["indicators"].append(f"obfuscation:{rule_name}")

    result["risk_score"] = min(result["risk_score"], 100.0)

    if result["risk_score"] >= 60.0:
        result["is_webshell"] = True
        result["confidence"] = min(result["risk_score"] / 100.0, 1.0)

    return result


def analyze_file_event(event: dict) -> Optional[Dict[str, Any]]:
    extra = event.get("extra_data") or event.get("extra", {})
    file_path = extra.get("file", extra.get("path", ""))
    if not file_path:
        return None
    return analyze_file(file_path)


class WebshellHunter:
    """Webshell detection engine — wraps pattern analysis with rule discovery."""

    @property
    def rules(self) -> Dict[str, List]:
        return {
            "php_webshell": [(r[1], r[2]) for r in PHP_WEBSHELL_PATTERNS],
            "asp_webshell": [(r[1], r[2]) for r in ASP_WEBSHELL_PATTERNS],
            "obfuscation": [(r[1], r[2]) for r in OBFUSCATION_PATTERNS],
        }

    def __call__(self, path: str, content: Optional[bytes] = None) -> Dict[str, Any]:
        return self.analyze(path, content)

    def analyze(self, path: str, content: Optional[bytes] = None) -> Dict[str, Any]:
        return analyze_file(path, content)

    def analyze_event(self, event: dict) -> Optional[Dict[str, Any]]:
        return analyze_file_event(event)


webshell_hunter = WebshellHunter()
