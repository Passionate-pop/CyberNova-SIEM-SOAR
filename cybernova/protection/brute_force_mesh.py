"""
Brute Force Mesh — distributed brute force detection that correlates
failed login attempts across multiple agents and sources.
Detects credential stuffing, password spraying, and targeted brute force.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.protection.brute_force_mesh")

BF_WINDOW = 300  # 5 minute sliding window
BF_THRESHOLD_IP = 10  # Failed attempts from single IP
BF_THRESHOLD_USER = 5  # Failed attempts for single user
BF_THRESHOLD_GLOBAL = 50  # Total failed across all sources
BF_SPRAY_THRESHOLD = 20  # Unique users from single IP = password spraying

# In-memory tracking (shared across enrichment calls via singleton)
class BFTracker:
    def __init__(self):
        self._ip_fails: Dict[str, List[float]] = defaultdict(list)
        self._user_fails: Dict[str, List[float]] = defaultdict(list)
        self._global_fails: List[float] = []
        self._ip_users: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))

    def _prune(self, now: float):
        cutoff = now - BF_WINDOW
        for ip in list(self._ip_fails.keys()):
            self._ip_fails[ip] = [t for t in self._ip_fails[ip] if t > cutoff]
            if not self._ip_fails[ip]:
                del self._ip_fails[ip]
        for user in list(self._user_fails.keys()):
            self._user_fails[user] = [t for t in self._user_fails[user] if t > cutoff]
            if not self._user_fails[user]:
                del self._user_fails[user]
        self._global_fails = [t for t in self._global_fails if t > cutoff]
        for ip in list(self._ip_users.keys()):
            for user in list(self._ip_users[ip].keys()):
                self._ip_users[ip][user] = [t for t in self._ip_users[ip][user] if t > cutoff]
                if not self._ip_users[ip][user]:
                    del self._ip_users[ip][user]

    def record_success(self, source_ip: str, user: str) -> None:
        """Record a successful login — clears tracked failures for this user/IP."""
        now = time.time()
        if source_ip in self._ip_fails:
            self._ip_fails[source_ip] = [t for t in self._ip_fails[source_ip] if t > now]
        if user in self._user_fails:
            self._user_fails[user] = [t for t in self._user_fails[user] if t > now]

    def record_failure(self, source_ip: str, user: str) -> Dict[str, Any]:
        now = time.time()
        self._ip_fails[source_ip].append(now)
        self._user_fails[user].append(now)
        self._global_fails.append(now)
        self._ip_users[source_ip][user].append(now)
        self._prune(now)

        ip_count = len(self._ip_fails.get(source_ip, []))
        user_count = len(self._user_fails.get(user, []))
        global_count = len(self._global_fails)
        unique_users_from_ip = len(self._ip_users.get(source_ip, {}))

        findings = []

        if ip_count >= BF_THRESHOLD_IP:
            findings.append({
                "type": "brute_force_ip",
                "severity": "high",
                "risk_score": 80.0,
                "message": f"Brute force from {source_ip}: {ip_count} failures in {BF_WINDOW}s",
                "source_ip": source_ip, "attempts": ip_count, "window": BF_WINDOW,
            })

        if user_count >= BF_THRESHOLD_USER:
            findings.append({
                "type": "brute_force_user",
                "severity": "high",
                "risk_score": 75.0,
                "message": f"Brute force on user '{user}': {user_count} failures in {BF_WINDOW}s",
                "user": user, "attempts": user_count, "window": BF_WINDOW,
            })

        if global_count >= BF_THRESHOLD_GLOBAL:
            findings.append({
                "type": "global_brute_force_wave",
                "severity": "critical",
                "risk_score": 90.0,
                "message": f"Global brute force wave: {global_count} failures in {BF_WINDOW}s",
                "attempts": global_count, "window": BF_WINDOW,
            })

        if unique_users_from_ip >= BF_SPRAY_THRESHOLD:
            findings.append({
                "type": "password_spraying",
                "severity": "critical",
                "risk_score": 92.0,
                "message": f"Password spraying from {source_ip}: {unique_users_from_ip} unique users",
                "source_ip": source_ip, "unique_users": unique_users_from_ip, "window": BF_WINDOW,
            })

        return {
            "analysis_complete": True,
            "brute_force_detected": len(findings) > 0,
            "max_risk_score": max((f.get("risk_score", 0) for f in findings), default=0.0),
            "finding_count": len(findings),
            "findings": findings,
        }


_bf_tracker = BFTracker()


def analyze_event(event: dict) -> Optional[Dict[str, Any]]:
    event_type = event.get("event_type", "")
    if event_type not in ("failed_login", "authentication_failure", "ssh_failed",
                           "login_failure", "rdp_failed"):
        return None
    source_ip = event.get("source_ip", event.get("extra_data", {}).get("src_ip", ""))
    user = event.get("user", event.get("extra_data", {}).get("user", "unknown"))
    if not source_ip:
        return None
    return _bf_tracker.record_failure(source_ip, user)


brute_force_mesh = _bf_tracker
