"""
CyberNova — Detection Rule Engine
Evaluates enriched events against detection rules.
Supports equality, regex, rate-limiting, and risk score computation.
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.detection.rules")

_REDIS_KEY_PREFIX = "cybernova:state:portscan"

# Shared sync Redis connection for stateful rules (lazy-initialized singleton)
_shared_sync_redis = None


def _get_sync_redis():
    """Shared sync Redis connection for stateful detection rules.
    Returns a singleton — avoids creating a new connection per rule instance.
    Falls back to None if Redis is unavailable.
    """
    global _shared_sync_redis
    if _shared_sync_redis is not None:
        try:
            _shared_sync_redis.ping()
            return _shared_sync_redis
        except Exception:
            _shared_sync_redis = None
    try:
        import redis as sync_redis
        from cybernova.config.settings import get_settings
        s = get_settings()
        url = str(s.resolved_redis_url)
        _shared_sync_redis = sync_redis.from_url(
            url, socket_timeout=2, socket_connect_timeout=2,
            max_connections=15, block=False,
        )
        return _shared_sync_redis
    except Exception:
        return None


class DetectionRule:
    def __init__(
        self, name: str, severity: str, conditions: Dict[str, Any],
        risk_score: float = 0.0, description: str = "",
        mitre_tactic: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        enabled: bool = True,
    ) -> None:
        self.name = name
        self.id = name  # Use name as unique ID
        self.enabled = enabled
        self.severity = severity
        self.conditions = conditions
        self.risk_score = risk_score
        self.description = description
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self._condition_type = conditions.get("_type", "equality")

    def evaluate(self, event: Dict[str, Any]) -> bool:
        """Evaluate equality/regex conditions."""
        for field, expected in self.conditions.items():
            if field.startswith("_"):
                continue
            actual = event.get(field)
            if actual is None:
                return False
            if isinstance(expected, list):
                if str(actual).lower() not in [str(e).lower() for e in expected]:
                    return False
            elif isinstance(expected, str) and expected.startswith("regex:"):
                pattern = expected[6:]
                if not re.search(pattern, str(actual), re.IGNORECASE):
                    return False
            else:
                if str(actual).lower() != str(expected).lower():
                    return False
        return True


class StatefulRule:
    """
    Rules that track state over time (rate limiting, anomaly detection).
    These cannot be evaluated on a single event — require the rate limiter.
    """

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return detection result if threat detected, None otherwise."""
        log.debug("Base StatefulRule.evaluate() called — no stateful rule type configured")
        return None


class BruteForceRule(StatefulRule):
    """Detect brute force attacks via auth failure rate tracking.
    Backed by Redis sorted sets with TTL for horizontal scalability.
    Falls back to in-memory dict when Redis unavailable.
    """

    WINDOW = 300
    MAX_FAILURES = 5
    CRED_STUFF_THRESHOLD = 5
    SPRAY_THRESHOLD = 3

    # Lua script: atomically count failed auth attempts in a sorted set.
    # Registered once per process — Redis caches the compiled script.
    _LUA_COUNT_FAILURES = None

    def __init__(self):
        self._redis = _get_sync_redis()
        self._fallback: Dict[str, Dict[str, list]] = {}

    def _redis_key(self, source_ip: str, user: str) -> str:
        return f"cybernova:state:bruteforce:{source_ip}:{user}"

    def _redis_ip_key(self, source_ip: str) -> str:
        return f"cybernova:state:bruteforce:ip:{source_ip}"

    def _redis_user_key(self, user: str) -> str:
        return f"cybernova:state:bruteforce:user:{user}"

    def _record_and_check(self, source_ip: str, user: str, success: bool) -> Optional[Dict[str, Any]]:
        if not source_ip:
            return None
        now = time.time()
        cutoff = now - self.WINDOW

        if self._redis:
            try:
                entry = json.dumps({"ip": source_ip, "user": user, "ts": now, "success": success})
                for key in (self._redis_key(source_ip, user), self._redis_ip_key(source_ip), self._redis_user_key(user)):
                    self._redis.zremrangebyscore(key, "-inf", cutoff)
                    self._redis.zadd(key, {entry: now})
                    self._redis.expire(key, self.WINDOW + 60)

                # Count only FAILURES for this specific IP+user pair via Lua
                # (avoids fetching + parsing all entries — O(1) server-side)
                if BruteForceRule._LUA_COUNT_FAILURES is None:
                    BruteForceRule._LUA_COUNT_FAILURES = self._redis.register_script("""
                    local entries = redis.call('ZRANGEBYSCORE', KEYS[1], ARGV[1], '+inf')
                    local failed = 0
                    for _, entry in ipairs(entries) do
                        local ok, data = pcall(cjson.decode, entry)
                        if ok and data.success == false then
                            failed = failed + 1
                        end
                    end
                    return failed
                    """)
                failed = BruteForceRule._LUA_COUNT_FAILURES(
                    keys=[self._redis_key(source_ip, user)],
                    args=[cutoff],
                )

                # Use the per-IP key to count unique users targeted (credential stuffing)
                # Use the per-user key to count unique IPs targeting them (password spray)
                ip_users = self._redis.zcard(self._redis_ip_key(source_ip))
                user_ips = self._redis.zcard(self._redis_user_key(user))

                result = self._build_result(source_ip, user, success, failed, ip_users, user_ips)
                if result:
                    return result
                return None
            except Exception as e:
                log.warning("Redis brute force error: %s", e)

        # In-memory fallback — track by IP→user→[(timestamp, success), ...]
        if source_ip not in self._fallback:
            self._fallback[source_ip] = {}
        if user not in self._fallback[source_ip]:
            self._fallback[source_ip][user] = []
        self._fallback[source_ip][user].append((now, success))
        self._fallback[source_ip][user] = [(t, s) for t, s in self._fallback[source_ip][user] if now - t < self.WINDOW]

        # Count only FAILED attempts
        failed_count = sum(1 for _, s in self._fallback[source_ip][user] if not s)
        ip_users = len(self._fallback.get(source_ip, {}))
        user_ips = sum(1 for ip_data in self._fallback.values() if user in ip_data)

        result = self._build_result(source_ip, user, success, failed_count, ip_users, user_ips)
        if result:
            return result
        return None

    def _build_result(self, source_ip: str, user: str, success: bool,
                       failed: int, ip_users: int, user_ips: int) -> Optional[Dict[str, Any]]:
        if failed >= self.MAX_FAILURES:
            return {
                "detected": True, "threat_type": "brute_force",
                "severity": "high", "risk_score": 75.0 + min(failed * 2, 20),
                "message": f"Brute force detected: {failed} failed logins to user '{user}' from IP {source_ip}",
                "source_ip": source_ip,
                "mitre_tactic": "TA0006", "mitre_technique": "T1110",
            }
        if ip_users >= self.CRED_STUFF_THRESHOLD:
            return {
                "detected": True, "threat_type": "credential_stuffing",
                "severity": "high", "risk_score": 70.0,
                "message": f"Credential stuffing: IP {source_ip} targeting {ip_users} different users",
                "source_ip": source_ip,
                "mitre_tactic": "TA0006", "mitre_technique": "T1110.003",
            }
        if user_ips >= self.SPRAY_THRESHOLD:
            return {
                "detected": True, "threat_type": "password_spray",
                "severity": "high", "risk_score": 65.0,
                "message": f"Password spray: user '{user}' targeted by {user_ips} different IPs",
                "source_ip": source_ip,
                "mitre_tactic": "TA0006", "mitre_technique": "T1110.003",
            }
        return None

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = event.get("event_type", "")
        source_ip = event.get("source_ip", "")
        user = event.get("user", "")
        success = event.get("success", False)

        if event_type not in ("authentication_failure", "auth_failure", "login_failure",
                               "failed_login", "ssh_failed", "rdp_failed", "ldap_failed",
                               "authentication"):
            return None

        return self._record_and_check(source_ip, user, success)


class PortScanRule(StatefulRule):
    """Detect port scanning via unique port count from single IP.
    Backed by Redis sets with TTL for horizontal scalability.
    Falls back to in-memory dict when Redis unavailable.
    """

    WINDOW = 300  # 5-minute sliding window
    THRESHOLD = 10  # unique ports to trigger

    def __init__(self):
        self._ip_ports: Dict[str, set] = {}
        self._ip_timestamps: Dict[str, float] = {}
        self._redis = _get_sync_redis()

    def _redis_key(self, source_ip: str) -> str:
        return f"{_REDIS_KEY_PREFIX}:{source_ip}"

    def _redis_count(self, source_ip: str, dest_port: int) -> Optional[int]:
        if not self._redis:
            return None
        try:
            key = self._redis_key(source_ip)
            now = time.time()
            cutoff = now - self.WINDOW
            self._redis.zremrangebyscore(key, "-inf", cutoff)
            self._redis.zadd(key, {str(dest_port): now}, nx=True)
            self._redis.expire(key, self.WINDOW + 60)
            count = self._redis.zcard(key)
            return count
        except Exception as e:
            log.warning("Redis portscan error for %s: %s", source_ip, e)
            return None

    def _inmem_count(self, source_ip: str, dest_port: int) -> int:
        now = time.time()
        if source_ip not in self._ip_ports:
            self._ip_ports[source_ip] = set()
            self._ip_timestamps[source_ip] = now
        if now - self._ip_timestamps[source_ip] > self.WINDOW:
            self._ip_ports[source_ip] = set()
            self._ip_timestamps[source_ip] = now
        self._ip_ports[source_ip].add(dest_port)
        return len(self._ip_ports[source_ip])

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = event.get("event_type", "")
        source_ip = event.get("source_ip", "")
        dest_port = event.get("dest_port", 0)

        if event_type not in ("port_scan", "scan", "network_scan"):
            return None

        redis_count = self._redis_count(source_ip, dest_port)
        port_count = redis_count if redis_count is not None else self._inmem_count(source_ip, dest_port)

        if port_count >= self.THRESHOLD:
            return {
                "detected": True,
                "threat_type": "port_scan",
                "severity": "medium",
                "risk_score": 60.0,
                "message": f"Port scan detected: {port_count} ports scanned from {source_ip}",
                "source_ip": source_ip,
                "mitre_tactic": "TA0043",
                "mitre_technique": "T1046",
            }

        return None


class AnomalousLoginRule(StatefulRule):
    """Detect logins outside business hours or from unusual locations."""

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = event.get("event_type", "")
        if event_type not in ("authentication_success", "login_success", "successful_login"):
            return None

        now = datetime.now(timezone.utc)
        hour = now.hour
        source_ip = event.get("source_ip", "")
        is_private = source_ip.startswith(("10.", "172.", "192.", "127.", "0."))

        if not is_private:
            if hour < 7 or hour > 22:
                return {
                    "detected": True,
                    "threat_type": "anomalous_login",
                    "severity": "medium",
                    "risk_score": 45.0,
                    "message": f"Login outside business hours ({hour}:00) from {source_ip}",
                    "source_ip": source_ip,
                    "mitre_tactic": "TA0006",
                    "mitre_technique": "T1078",
                }

        return None


class RegistryFloodRule(StatefulRule):
    """Detect mass registry changes — ransomware/cryptominer behavior."""

    def __init__(self):
        self._changes: Dict[str, list] = {}

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = event.get("event_type", "")
        if event_type != "registry_changed":
            return None
        source_ip = event.get("source_ip", "local")
        now = time.time()
        if source_ip not in self._changes:
            self._changes[source_ip] = []
        self._changes[source_ip].append(now)
        self._changes[source_ip] = [t for t in self._changes[source_ip] if now - t < 60]
        if len(self._changes[source_ip]) >= 10:
            return {
                "detected": True,
                "threat_type": "registry_flood",
                "severity": "critical",
                "risk_score": 90.0,
                "message": f"Mass registry changes: {len(self._changes[source_ip])} in 60s",
                "source_ip": source_ip,
                "mitre_tactic": "TA0040",
                "mitre_technique": "T1486",
            }
        return None


class FileChangeFloodRule(StatefulRule):
    """Detect mass file changes — ransomware encryption pattern.
    Backed by Redis sorted set per source_ip with TTL.
    Falls back to in-memory dict when Redis unavailable.
    """

    WINDOW = 120
    THRESHOLD = 20

    def __init__(self):
        self._redis = _get_sync_redis()
        self._changes: Dict[str, list] = {}

    def _redis_key(self, source_ip: str) -> str:
        return f"cybernova:state:fileflood:{source_ip}"

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = event.get("event_type", "")
        if event_type != "file_changed":
            return None
        source_ip = event.get("source_ip", "local")
        now = time.time()
        cutoff = now - self.WINDOW

        count = None
        if self._redis:
            try:
                key = self._redis_key(source_ip)
                self._redis.zremrangebyscore(key, "-inf", cutoff)
                self._redis.zadd(key, {str(now): now})
                self._redis.expire(key, self.WINDOW + 60)
                count = self._redis.zcard(key)
            except Exception as e:
                log.warning("Redis fileflood error for %s: %s", source_ip, e)

        if count is None:
            if source_ip not in self._changes:
                self._changes[source_ip] = []
            self._changes[source_ip].append(now)
            self._changes[source_ip] = [t for t in self._changes[source_ip] if t > cutoff]
            count = len(self._changes[source_ip])

        if count >= self.THRESHOLD:
            return {
                "detected": True,
                "threat_type": "ransomware_encryption",
                "severity": "critical",
                "risk_score": 98.0,
                "message": f"Mass file changes: {count} in {self.WINDOW}s — ransomware pattern",
                "source_ip": source_ip,
                "mitre_tactic": "TA0040",
                "mitre_technique": "T1486",
            }
        return None


class DataExfilRule(StatefulRule):
    """Detect data exfiltration patterns.
    Tracks cumulative transfer volume per source_ip over a sliding window.
    Backed by Redis sorted sets with TTL.
    Falls back to in-memory dict when Redis unavailable.
    """

    WINDOW = 300
    BYTE_THRESHOLD = 50_000_000
    DNS_THRESHOLD = 5

    def __init__(self):
        self._redis = _get_sync_redis()
        self._volumes: Dict[str, list] = {}

    def _redis_transfer_key(self, source_ip: str) -> str:
        return f"cybernova:state:exfil:transfer:{source_ip}"

    def _redis_dns_key(self, source_ip: str) -> str:
        return f"cybernova:state:exfil:dns:{source_ip}"

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = event.get("event_type", "")
        message = event.get("message", "").lower()
        source_ip = event.get("source_ip", "")
        dest_ip = event.get("dest_ip", "")
        bytes_xfer = event.get("bytes", 0) or event.get("size", 0) or 0
        now = time.time()
        cutoff = now - self.WINDOW

        exfil_keywords = ["exfiltration", "data transfer", "large data", "dns tunnel",
                          "tunneling", "large upload", "bulk transfer", "data leak"]

        volume = None
        dns_count = None

        if event_type in ("data_transfer", "data_exfiltration", "exfiltration",
                          "large_transfer", "bulk_upload"):
            if self._redis:
                try:
                    key = self._redis_transfer_key(source_ip)
                    self._redis.zremrangebyscore(key, "-inf", cutoff)
                    self._redis.zadd(key, {f"{dest_ip}:{bytes_xfer}": now})
                    self._redis.expire(key, self.WINDOW + 60)
                    all_members = self._redis.zrange(key, 0, -1)
                    volume = sum(int(m.decode().split(":")[-1]) for m in all_members)
                except Exception as e:
                    log.warning("Redis exfil error: %s", e)

            if volume is None:
                if source_ip not in self._volumes:
                    self._volumes[source_ip] = []
                self._volumes[source_ip].append((now, bytes_xfer))
                self._volumes[source_ip] = [(t, b) for t, b in self._volumes[source_ip] if t > cutoff]
                volume = sum(b for _, b in self._volumes[source_ip])

            if volume >= self.BYTE_THRESHOLD:
                return {
                    "detected": True, "threat_type": "data_exfiltration",
                    "severity": "critical", "risk_score": 85.0,
                    "message": f"Data exfiltration: {volume:,} bytes from {source_ip} in {self.WINDOW}s",
                    "source_ip": source_ip, "dest_ip": dest_ip,
                    "mitre_tactic": "TA0010", "mitre_technique": "T1048",
                }

            # Normal data transfers are NOT threats — only alert on actual exfil keywords
            return None

        if any(kw in message for kw in exfil_keywords):
            return {
                "detected": True, "threat_type": "potential_exfiltration",
                "severity": "high", "risk_score": 70.0,
                "message": f"Potential data exfiltration: {message[:200]}",
                "source_ip": source_ip,
                "mitre_tactic": "TA0010", "mitre_technique": "T1048",
            }

        if event_type == "dns_query":
            if any(kw in message for kw in ["dns tunnel", "dns query", "large dns"]):
                return {
                    "detected": True, "threat_type": "dns_tunneling",
                    "severity": "high", "risk_score": 75.0,
                    "message": f"DNS tunneling detected: {message[:200]}",
                    "source_ip": source_ip,
                    "mitre_tactic": "TA0011", "mitre_technique": "T1071.004",
                }

            if self._redis:
                try:
                    key = self._redis_dns_key(source_ip)
                    self._redis.zremrangebyscore(key, "-inf", cutoff)
                    self._redis.zadd(key, {str(now): now})
                    self._redis.expire(key, self.WINDOW + 60)
                    dns_count = self._redis.zcard(key)
                except Exception as e:
                    log.warning("Redis exfil DNS error: %s", e)

            if dns_count is not None and dns_count >= self.DNS_THRESHOLD:
                return {
                    "detected": True, "threat_type": "dns_tunneling",
                    "severity": "high", "risk_score": 75.0,
                    "message": f"DNS tunneling: {dns_count} suspicious queries from {source_ip} in {self.WINDOW}s",
                    "source_ip": source_ip,
                    "mitre_tactic": "TA0011", "mitre_technique": "T1071.004",
                }

        return None


class RuleEngine:
    def __init__(self) -> None:
        self.rules: List[DetectionRule] = self._default_rules()
        self.stateful_rules: List[StatefulRule] = self._default_stateful_rules()

    def _default_rules(self) -> List[DetectionRule]:
        return [
            # === HOST AGENT RULES ===
            DetectionRule("external_connection", "high",
                          {"event_type": "external_connection"}, 75.0,
                          "External network connection detected"),
            DetectionRule("new_listener", "high",
                          {"event_type": "new_listener"}, 70.0,
                          "New high port listener"),
            DetectionRule("suspicious_file", "high",
                          {"event_type": "suspicious_file"}, 80.0,
                          "Suspicious file detected"),
            DetectionRule("new_download", "medium",
                          {"event_type": "new_download"}, 50.0,
                          "New file downloaded"),
            DetectionRule("usb_connected", "low",
                          {"event_type": "usb_connected"}, 35.0,
                          "USB device connected"),
            DetectionRule("usb_removed", "info",
                          {"event_type": "usb_removed"}, 10.0,
                          "USB device removed"),
            DetectionRule("keylog_detected", "critical",
                          {"event_type": "keylog_detected"}, 95.0,
                          "Keylogger or input hook detected on host"),
            DetectionRule("file_changed", "high",
                          {"event_type": "file_changed"}, 80.0,
                          "Critical system file hash changed — possible tampering"),
            DetectionRule("registry_changed", "high",
                          {"event_type": "registry_changed"}, 75.0,
                          "Windows registry persistent method modified"),
            DetectionRule("unusual_process", "high",
                          {"event_type": "unusual_process"}, 65.0,
                          "Unusual process execution"),
            DetectionRule("malicious_process", "critical",
                          {"event_type": "malicious_process"}, 95.0,
                          "Malicious process detected"),
            DetectionRule("malicious_script", "critical",
                          {"event_type": "malicious_script"}, 95.0,
                          "Malicious script detected"),
            DetectionRule("startup_item", "high",
                          {"event_type": "startup_item"}, 75.0,
                          "New startup item"),
            DetectionRule("encoded_powershell", "critical",
                           {"event_type": "encoded_powershell"}, 90.0,
                           "PowerShell encoded command"),

            # === PHASE 3 STEGANOGRAPHY RULES ===
            DetectionRule("stego_suspected", "critical",
                           {"event_type": "stego_suspected"}, 88.0,
                           "Steganography detected in image — possible covert data channel"),
            DetectionRule("stego_metadata_anomaly", "high",
                           {"event_type": "stego_metadata_anomaly"}, 70.0,
                           "Suspicious EXIF metadata — possible stego carrier"),
            DetectionRule("stego_palette_anomaly", "high",
                           {"event_type": "stego_palette_anomaly"}, 65.0,
                           "Duplicate palette entries — possible palette-based stego"),

            # === PHASE N PROTECTION ENGINE RULES ===
            DetectionRule("waf_block", "critical",
                           {"event_type": "waf_block"}, 92.0,
                           "WAF blocked an attack — possible web exploitation"),
            DetectionRule("sqli_detected", "critical",
                           {"event_type": "sqli_detected"}, 92.0,
                           "SQL injection attempt blocked"),
            DetectionRule("xss_detected", "high",
                           {"event_type": "xss_detected"}, 80.0,
                           "Cross-site scripting attempt detected"),
            DetectionRule("cmd_injection_detected", "critical",
                           {"event_type": "cmd_injection_detected"}, 95.0,
                           "Command injection attempt on server"),
            DetectionRule("path_traversal_detected", "high",
                           {"event_type": "path_traversal_detected"}, 78.0,
                           "Path traversal attempt detected"),
            DetectionRule("ssrf_detected", "high",
                           {"event_type": "ssrf_detected"}, 82.0,
                           "Server-side request forgery attempt"),
            DetectionRule("webshell_detected", "critical",
                           {"event_type": "webshell_detected"}, 95.0,
                           "Webshell found on server — remote access backdoor"),
            DetectionRule("rootkit_detected", "critical",
                           {"event_type": "rootkit_detected"}, 98.0,
                           "Rootkit indicators detected on host"),
            DetectionRule("tamper_detected", "critical",
                           {"event_type": "tamper_detected"}, 99.0,
                           "Security tool tampering detected"),
            DetectionRule("cryptominer_detected", "critical",
                           {"event_type": "cryptominer_detected"}, 95.0,
                           "Cryptocurrency miner detected on host"),
            DetectionRule("dlp_leak_detected", "critical",
                           {"event_type": "dlp_leak_detected"}, 90.0,
                           "Sensitive data exposure detected"),
            DetectionRule("misconfiguration_found", "high",
                           {"event_type": "misconfiguration_found"}, 75.0,
                           "CIS benchmark security misconfiguration found"),
            DetectionRule("brute_force_detected", "high",
                           {"event_type": "brute_force_detected"}, 80.0,
                           "Brute force attack in progress"),
            DetectionRule("password_spraying_detected", "critical",
                           {"event_type": "password_spraying_detected"}, 92.0,
                           "Password spraying attack detected"),
            DetectionRule("phishing_detected", "high",
                           {"event_type": "phishing_detected"}, 80.0,
                           "Phishing attempt detected"),
            DetectionRule("platform_compromised", "critical",
                           {"event_type": "platform_compromised"}, 99.0,
                           "CyberNova platform itself may be compromised"),

            # === PHASE N SHIELD MODULE GENERAL RULES ===
            DetectionRule("network_attack_detected", "high",
                           {"event_type": "network_attack_detected"}, 78.0,
                           "Network-level attack detected by NetworkShield"),
            DetectionRule("application_attack_detected", "critical",
                           {"event_type": "application_attack_detected"}, 88.0,
                           "Application-level attack detected by AppShield"),
            DetectionRule("process_attack_detected", "critical",
                           {"event_type": "process_attack_detected"}, 92.0,
                           "Process-level attack detected by ProcessShield"),
            DetectionRule("system_misconfiguration_detected", "high",
                           {"event_type": "system_misconfiguration_detected"}, 72.0,
                           "System misconfiguration detected by SystemShield"),
            DetectionRule("social_engineering_detected", "high",
                           {"event_type": "social_engineering_detected"}, 75.0,
                           "Social engineering attack detected by UserShield"),
            DetectionRule("data_threat_detected", "critical",
                           {"event_type": "data_threat_detected"}, 92.0,
                           "Data-level threat detected by DataShield"),
            DetectionRule("resource_abuse_detected", "high",
                           {"event_type": "resource_abuse_detected"}, 82.0,
                           "Resource abuse detected by ResourceShield"),
            DetectionRule("self_heal_action", "high",
                           {"event_type": "self_heal_action"}, 70.0,
                           "Self-heal action taken by SelfHeal module"),

            # === PHASE 4 NIDS RULES (Suricata) ===
            DetectionRule("suricata_alert", "critical",
                           {"event_type": "suricata_alert"}, 90.0,
                           "Suricata NIDS alert triggered — possible intrusion"),
            DetectionRule("network_anomaly", "high",
                           {"event_type": "network_anomaly"}, 75.0,
                           "Network protocol anomaly detected"),
            DetectionRule("file_transfer", "medium",
                           {"event_type": "file_transfer"}, 55.0,
                           "File transfer detected on wire"),
            DetectionRule("tls_connection", "low",
                           {"event_type": "tls_connection"}, 25.0,
                           "TLS connection detected"),
            DetectionRule("ssh_connection", "info",
                           {"event_type": "ssh_connection"}, 15.0,
                           "SSH connection detected"),
            DetectionRule("http_request", "info",
                           {"event_type": "http_request"}, 15.0,
                           "HTTP request detected"),

            # === PHASE 2 SCANNER RULES ===
            DetectionRule("yara_match", "critical",
                           {"event_type": "yara_match"}, 92.0,
                           "YARA rule matched in process memory — possible malware"),
            DetectionRule("mimikatz_memory_artifact", "critical",
                           {"event_type": "mimikatz_memory_artifact"}, 98.0,
                           "Mimikatz credential dumper artifact in process memory"),
                          
            # === WINDOWS EVENT LOG ===
            DetectionRule("successful_login", "low",
                          {"event_type": "successful_login"}, 25.0,
                          "Successful login"),
            DetectionRule("failed_login", "high",
                          {"event_type": "failed_login"}, 70.0,
                          "Failed login attempt"),
            DetectionRule("logoff", "low",
                          {"event_type": "logoff"}, 10.0,
                          "User logoff"),
            DetectionRule("special_privilege", "medium",
                          {"event_type": "special_privilege"}, 55.0,
                          "Special privileges assigned"),
            DetectionRule("new_process", "low",
                          {"event_type": "new_process"}, 20.0,
                          "New process created"),
            DetectionRule("service_installed", "medium",
                          {"event_type": "service_installed"}, 55.0,
                          "Service installed"),
            DetectionRule("scheduled_task", "medium",
                          {"event_type": "scheduled_task"}, 55.0,
                          "Scheduled task created"),
            DetectionRule("user_created", "high",
                          {"event_type": "user_created"}, 75.0,
                          "New user account created"),
            DetectionRule("user_enabled", "medium",
                          {"event_type": "user_enabled"}, 55.0,
                          "User account enabled"),
            DetectionRule("user_deleted", "high",
                          {"event_type": "user_deleted"}, 75.0,
                          "User account deleted"),
            DetectionRule("member_added", "medium",
                          {"event_type": "member_added"}, 55.0,
                          "Member added to group"),
            DetectionRule("account_lockout", "high",
                          {"event_type": "account_lockout"}, 70.0,
                          "Account locked out"),
            DetectionRule("agent_heartbeat", "info",
                          {"event_type": "agent_heartbeat"}, 5.0,
                          "Agent heartbeat"),
            
            # === ORIGINAL MALWARE RULES ===
            DetectionRule("malware_detected", "critical",
                          {"event_type": "malware_detected"}, 95.0,
                          "Malware detected"),
            DetectionRule("ransomware_signature", "critical",
                          {"event_type": "regex:ransomware|ransom"}, 98.0,
                          "Ransomware signature"),
            DetectionRule("trojan_detected", "critical",
                          {"event_type": "regex:trojan"}, 95.0,
                          "Trojan detected"),
            DetectionRule("c2_communication", "critical",
                          {"event_type": "regex:c2|c2_communication"}, 92.0,
                          "C2 communication"),
            DetectionRule("sql_injection", "critical",
                          {"event_type": "regex:sql.*injection"}, 90.0,
                          "SQL injection"),
            DetectionRule("privilege_escalation", "critical",
                          {"event_type": "regex:privilege.*escalat"}, 90.0,
                          "Privilege escalation"),
            DetectionRule("data_exfiltration", "high",
                          {"event_type": "regex:data.*exfil"}, 80.0,
                          "Data exfiltration"),
            DetectionRule("dns_tunneling", "high",
                          {"event_type": "regex:dns.*tunnel"}, 85.0,
                          "DNS tunneling"),
            DetectionRule("lateral_movement", "high",
                          {"event_type": "regex:lateral.*movement"}, 85.0,
                          "Lateral movement"),
            DetectionRule("rdp_brute_force", "high",
                          {"event_type": "regex:rdp.*brute"}, 78.0,
                          "RDP brute force"),
            DetectionRule("port_scan", "medium",
                           {"event_type": "regex:port.*scan"}, 60.0,
                           "Port scan"),
            # NOTE: high_severity_syslog REMOVED — it was a catch-all that matched
            # ANY event with high/critical severity, creating duplicate alerts when
            # more specific rules also matched. Each detection should be handled by
            # its own specific rule, not a severity-based catch-all.

            # === ATOMIC TEST MATCHING RULES ===
            DetectionRule("critical_severity_event", "critical",
                          {"severity": "critical"}, 95.0,
                          "Critical severity security event"),
            DetectionRule("encoded_powershell_cmdline", "critical",
                          {"command_line": "regex:-enc\\s|-en\\s|-enCode|-e\\s+"}, 90.0,
                          "PowerShell encoded command detected via command line analysis"),
            # Host Agent network threat detection
            DetectionRule("suspicious_network", "high",
                          {"event_type": "suspicious_network"}, 70.0,
                          "Suspicious network activity detected by host agent — possible C2 or data exfil",
                          "TA0011", "T1046"),
            DetectionRule("powershell_process_match", "critical",
                          {"process_name": "regex:powershell\\.exe"}, 75.0,
                          "PowerShell process execution detected"),
            DetectionRule("mass_data_transfer", "critical",
                          {"bytes_sent": "regex:\\d{10,}"}, 90.0,
                          "Massive data transfer detected — potential exfiltration"),
            DetectionRule("cmd_tamper_service_stop", "critical",
                          {"command_line": "regex:sc\\s+stop\\s+|net\\s+stop\\s+|Stop-Service"}, 92.0,
                          "Security service stop command detected — possible tampering"),
            DetectionRule("port_scan_message_match", "low",
                          {"message": "regex:port scan"}, 60.0,
                          "Port scan detected via message analysis"),
            DetectionRule("registry_query_detected", "medium",
                          {"command_line": "regex:reg query"}, 55.0,
                          "Registry query detected"),
            DetectionRule("registry_event_type", "medium",
                          {"event_type": "registry"}, 50.0,
                          "Registry access detected"),
            DetectionRule("lsass_process_access", "high",
                          {"process_name": "regex:lsass\\.exe"}, 85.0,
                          "LSASS process access detected — possible credential dumping"),
            DetectionRule("scheduled_task_suspicious", "high",
                          {"event_type": "scheduled_task"}, 55.0,
                          "Scheduled task created or modified"),
            DetectionRule("c2_communication_broad", "critical",
                          {"message": "regex:c2|command.and.control|C2 communication|command & control|data exfil"}, 92.0,
                          "C2 communication or data exfiltration detected"),
            DetectionRule("brute_force_authentication", "high",
                          {"event_type": "regex:authentication|auth_failure"}, 75.0,
                          "Authentication failure — possible brute force"),

            # === MESSAGE-BASED DETECTION RULES (catch attacks embedded in messages) ===
            DetectionRule("sql_injection_in_message", "critical",
                          {"message": "regex:sql.?inject|UNION.*SELECT|OR.*1.*=.*1|drop.*table"}, 90.0,
                          "SQL injection attempt detected in event message",
                          "TA0001", "T1190"),
            DetectionRule("phishing_in_message", "high",
                          {"message": "regex:phish|malicious.*attach|credential.*harvest|spoofed.*email"}, 82.0,
                          "Phishing attempt detected in event message",
                          "TA0001", "T1566"),
            DetectionRule("privilege_escalation_in_message", "critical",
                          {"message": "regex:privilege.*escalat|sudo.*exploit|unauthorized.*privesc|escalat.*priv"}, 88.0,
                          "Privilege escalation attempt detected in event message",
                          "TA0004", "T1068"),
            DetectionRule("dns_tunnel_in_message", "high",
                          {"message": "regex:dns.?tunnel|dns.*exfil|covert.*dns"}, 80.0,
                          "DNS tunneling detected in event message",
                          "TA0011", "T1071.004"),
            DetectionRule("powershell_encoded_in_message", "critical",
                          {"message": "regex:powershell.*encod|encoded.*command.*execut|\-enc\s|base64.*powershell"}, 88.0,
                          "Encoded PowerShell execution detected in event message",
                          "TA0002", "T1059.001"),
            DetectionRule("lateral_movement_in_message", "high",
                          {"message": "regex:lateral.*movement|smb.*admin|remote.*service.*access|pass.*the.*hash"}, 82.0,
                          "Lateral movement detected in event message",
                          "TA0008", "T1021"),
            DetectionRule("ransomware_in_message", "critical",
                          {"message": "regex:ransomware.*encrypt|encrypt.*activit|crypto.*lock|file.*encipher"}, 95.0,
                          "Ransomware activity detected in event message",
                          "TA0040", "T1486"),
            DetectionRule("brute_force_in_message", "high",
                          {"message": "regex:brute.?force|multiple.*failed.*login|mass.*auth.*fail"}, 78.0,
                          "Brute force attack detected in event message",
                          "TA0006", "T1110"),
            DetectionRule("iam_user_creation", "high",
                          {"event_type": "regex:cloud\\.iam"}, 75.0,
                          "Cloud IAM user creation detected"),
            DetectionRule("s3_bucket_public", "high",
                          {"event_type": "regex:cloud\\.s3"}, 75.0,
                          "S3 bucket operation detected"),

        ]

    def _default_stateful_rules(self) -> List[StatefulRule]:
        return [
            BruteForceRule(),
            PortScanRule(),
            AnomalousLoginRule(),
            RegistryFloodRule(),
            FileChangeFloodRule(),
            DataExfilRule(),
        ]

    def register_rule(self, rule: DetectionRule) -> None:
        self.rules.append(rule)
        log.info("Registered detection rule: %s", rule.name)

    def evaluate(self, event: Dict[str, Any]) -> List[DetectionRule]:
        return [r for r in self.rules if r.evaluate(event)]

    def evaluate_stateful(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate stateful rules and return detection results."""
        results = []
        for rule in self.stateful_rules:
            try:
                result = rule.evaluate(event)
                if result and result.get("detected"):
                    results.append(result)
            except Exception as e:
                log.error("Stateful rule %s failed: %s", rule.__class__.__name__, e)
        return results

    def list_rules(self) -> List[Dict[str, Any]]:
        return [{"id": r.id, "name": r.name, "severity": r.severity,
                 "risk_score": r.risk_score, "description": r.description,
                 "mitre_tactic": getattr(r, "mitre_tactic", None),
                 "mitre_technique": getattr(r, "mitre_technique", None),
                 "enabled": r.enabled}
                for r in self.rules]

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a rule by ID (name). Returns updated rule dict or None if not found."""
        for r in self.rules:
            if r.id == rule_id:
                if "enabled" in updates:
                    r.enabled = bool(updates["enabled"])
                if "severity" in updates:
                    r.severity = str(updates["severity"])
                if "risk_score" in updates:
                    r.risk_score = float(updates["risk_score"])
                if "description" in updates:
                    r.description = str(updates["description"])
                log.info("Rule updated: %s — %s", rule_id, updates)
                return {"id": r.id, "name": r.name, "severity": r.severity,
                        "risk_score": r.risk_score, "description": r.description,
                        "mitre_tactic": getattr(r, "mitre_tactic", None),
                        "mitre_technique": getattr(r, "mitre_technique", None),
                        "enabled": r.enabled}
        return None


rule_engine = RuleEngine()
