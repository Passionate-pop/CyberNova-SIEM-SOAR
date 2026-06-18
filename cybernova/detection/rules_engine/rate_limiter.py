"""
CyberNova — Rate-Limited Detection Rules
Tracks auth failures per IP/user over sliding time windows.
Enables detection of brute force, credential stuffing, and spraying attacks.
Backed by Redis for horizontal scaling, with in-memory fallback.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

log = logging.getLogger("cybernova.detection.ratelimit")

_REDIS_KEY_PREFIX = "cybernova:ratelimit:"
_REDIS_TTL_SECONDS = 600  # 10 min max for any key


@dataclass
class AuthAttempt:
    ip: str
    user: str
    timestamp: datetime
    success: bool


@dataclass
class RateLimitKey:
    ip: str
    user: str

    def __hash__(self) -> int:
        return hash((self.ip, self.user))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RateLimitKey):
            return False
        return self.ip == other.ip and self.user == other.user


class RateLimitTrackerRedis:
    """
    Redis-backed sliding window rate limiter for authentication attempts.
    Tracks: failed/success auth attempts per (IP, user) pair.
    Falls back gracefully to in-memory when Redis is unavailable.
    """

    def __init__(self, window_seconds: int = 300, max_failures: int = 5, tracker_name: str = "default"):
        self.window_seconds = window_seconds
        self.max_failures = max_failures
        self.tracker_name = tracker_name
        # In-memory fallback
        self._fallback: Dict[RateLimitKey, List[AuthAttempt]] = defaultdict(list)

    def _mem_key(self, ip: str, user: str) -> str:
        return f"{_REDIS_KEY_PREFIX}{self.tracker_name}:{ip}:{user}"

    async def _get_redis_async(self):
        try:
            from cybernova.database.redis import get_redis
            return await get_redis()
        except ImportError:
            return None
        except Exception as e:
            log.warning("Redis unavailable for rate limiter: %s", e)
            return None

    async def record_attempt(self, ip: str, user: str, success: bool) -> None:
        """Record an authentication attempt (async — prefers Redis)."""
        redis = await self._get_redis_async()
        if redis:
            try:
                now = datetime.now(timezone.utc).timestamp()
                entry = json.dumps({"ip": ip, "user": user, "ts": now, "success": success})
                key = self._mem_key(ip, user)
                await redis.zadd(key, {entry: now})
                await redis.zremrangebyscore(key, 0, now - self.window_seconds)
                await redis.expire(key, _REDIS_TTL_SECONDS)
                return
            except Exception as e:
                log.warning("Redis record_attempt failed, using fallback: %s", e)

        # In-memory fallback
        key = RateLimitKey(ip=ip, user=user)
        now = datetime.now(timezone.utc)
        self._fallback[key].append(AuthAttempt(ip=ip, user=user, timestamp=now, success=success))
        self._prune_old(key, now)

    def _prune_old(self, key: RateLimitKey, now: datetime) -> None:
        """Remove attempts outside the sliding window (in-memory fallback)."""
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._fallback[key] = [
            a for a in self._fallback[key] if a.timestamp > cutoff
        ]
        if not self._fallback[key]:
            del self._fallback[key]

    async def _get_attempts(self, ip: str, user: str) -> List[Dict[str, Any]]:
        """Get all attempts within the window."""
        redis = await self._get_redis_async()
        if redis:
            try:
                now = datetime.now(timezone.utc).timestamp()
                key = self._mem_key(ip, user)
                entries = await redis.zrangebyscore(key, now - self.window_seconds, now)
                return [json.loads(e) for e in entries]
            except Exception as e:
                log.warning("Redis get_attempts failed, using fallback: %s", e)

        # In-memory fallback
        key = RateLimitKey(ip=ip, user=user)
        now_dt = datetime.now(timezone.utc)
        self._prune_old(key, now_dt)
        return [
            {"ip": a.ip, "user": a.user, "ts": a.timestamp.timestamp(), "success": a.success}
            for a in self._fallback.get(key, [])
        ]

    async def get_failed_count(self, ip: str, user: str) -> int:
        """Count failed auth attempts in the window."""
        attempts = await self._get_attempts(ip, user)
        return sum(1 for a in attempts if not a.get("success"))

    async def get_total_count(self, ip: str, user: str) -> int:
        """Count all auth attempts in the window."""
        attempts = await self._get_attempts(ip, user)
        return len(attempts)

    async def is_brute_force(self, ip: str, user: str) -> bool:
        """Detect if auth failure rate exceeds threshold."""
        failed = await self.get_failed_count(ip, user)
        return failed >= self.max_failures

    async def check_credential_stuffing(self, ip: str) -> int:
        """Count unique users targeted by an IP (credential stuffing pattern)."""
        redis = await self._get_redis_async()
        if redis:
            try:
                pattern = f"{_REDIS_KEY_PREFIX}{self.tracker_name}:{ip}:*"
                cursor = 0
                users = set()
                while True:
                    cursor, keys = await redis.scan(cursor, match=pattern, count=100)
                    for key in keys:
                        user = key.split(":")[-1]
                        if not await self._is_key_expired(redis, key):
                            users.add(user)
                    if cursor == 0:
                        break
                return len(users)
            except Exception as e:
                log.warning("Rate limiter Redis scan (unique IPs) failed: %s", e)

        # In-memory fallback
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        unique_users = set()
        for key, attempts in list(self._fallback.items()):
            if key.ip == ip:
                recent = [a for a in attempts if a.timestamp > cutoff]
                if recent:
                    unique_users.add(key.user)
        return len(unique_users)

    async def check_password_spray(self, user: str) -> int:
        """Count unique IPs attacking a single user (password spray pattern)."""
        now_ts = datetime.now(timezone.utc).timestamp()
        redis = await self._get_redis_async()
        if redis:
            try:
                pattern = f"{_REDIS_KEY_PREFIX}{self.tracker_name}:*:{user}"
                cursor = 0
                ips = set()
                while True:
                    cursor, keys = await redis.scan(cursor, match=pattern, count=100)
                    for key in keys:
                        ip = key.split(":")[-2]
                        entries = await redis.zrangebyscore(key, now_ts - self.window_seconds, now_ts)
                        if entries:
                            ips.add(ip)
                    if cursor == 0:
                        break
                return len(ips)
            except Exception as e:
                log.warning("Rate limiter Redis scan (password spray) failed: %s", e)

        # In-memory fallback
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        unique_ips = set()
        for key, attempts in list(self._fallback.items()):
            if key.user == user:
                recent = [a for a in attempts if a.timestamp > cutoff]
                if recent:
                    unique_ips.add(key.ip)
        return len(unique_ips)

    async def _is_key_expired(self, redis, key: str) -> bool:
        """Check if a Redis key has data within the window."""
        try:
            ttl = await redis.ttl(key)
            return ttl < 0
        except Exception as e:
            log.warning("Rate limiter TTL check failed: %s", e)
            return True

    async def get_threat_level(self, ip: str, user: str) -> str:
        """Return threat level based on behavior patterns."""
        failed = await self.get_failed_count(ip, user)
        total = await self.get_total_count(ip, user)
        if failed >= self.max_failures:
            return "critical"
        if failed >= self.max_failures - 2:
            return "high"
        if total >= 3:
            return "medium"
        if total >= 1:
            return "low"
        return "none"


# In-memory fallback RateLimitTracker (sync, for non-async contexts)
class RateLimitTracker:
    """
    In-memory sliding window rate limiter for authentication attempts.
    Used as fallback when Redis is unavailable.
    """

    def __init__(self, window_seconds: int = 300, max_failures: int = 5):
        self.window_seconds = window_seconds
        self.max_failures = max_failures
        self._attempts: Dict[RateLimitKey, List[AuthAttempt]] = defaultdict(list)

    def record_attempt(self, ip: str, user: str, success: bool) -> None:
        """Record an authentication attempt."""
        key = RateLimitKey(ip=ip, user=user)
        now = datetime.now(timezone.utc)
        self._attempts[key].append(AuthAttempt(ip=ip, user=user, timestamp=now, success=success))
        self._prune_old(key, now)

    def _prune_old(self, key: RateLimitKey, now: datetime) -> None:
        """Remove attempts outside the sliding window."""
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._attempts[key] = [
            a for a in self._attempts[key] if a.timestamp > cutoff
        ]
        if not self._attempts[key]:
            del self._attempts[key]

    def get_failed_count(self, ip: str, user: str) -> int:
        """Count failed auth attempts in the window."""
        key = RateLimitKey(ip=ip, user=user)
        now = datetime.now(timezone.utc)
        self._prune_old(key, now)
        attempts = self._attempts.get(key, [])
        return sum(1 for a in attempts if not a.success)

    def get_total_count(self, ip: str, user: str) -> int:
        """Count all auth attempts in the window."""
        key = RateLimitKey(ip=ip, user=user)
        now = datetime.now(timezone.utc)
        self._prune_old(key, now)
        return len(self._attempts.get(key, []))

    def get_success_count(self, ip: str, user: str) -> int:
        """Count successful auth attempts in the window."""
        key = RateLimitKey(ip=ip, user=user)
        now = datetime.now(timezone.utc)
        self._prune_old(key, now)
        return sum(1 for a in self._attempts.get(key, []) if a.success)

    def is_brute_force(self, ip: str, user: str) -> bool:
        """Detect if auth failure rate exceeds threshold."""
        return self.get_failed_count(ip, user) >= self.max_failures

    def check_credential_stuffing(self, ip: str) -> int:
        """Count unique users targeted by an IP (credential stuffing pattern)."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        count = 0
        for key, attempts in list(self._attempts.items()):
            if key.ip == ip:
                recent = [a for a in attempts if a.timestamp > cutoff]
                if recent:
                    count += 1
        return count

    def check_password_spray(self, user: str) -> int:
        """Count unique IPs attacking a single user (password spray pattern)."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        unique_ips: set = set()
        for key, attempts in list(self._attempts.items()):
            if key.user == user:
                recent = [a for a in attempts if a.timestamp > cutoff]
                if recent:
                    unique_ips.add(key.ip)
        return len(unique_ips)

    def get_threat_level(self, ip: str, user: str) -> str:
        """Return threat level based on behavior patterns."""
        failed = self.get_failed_count(ip, user)
        total = self.get_total_count(ip, user)
        if failed >= self.max_failures:
            return "critical"
        if failed >= self.max_failures - 2:
            return "high"
        if total >= 3:
            return "medium"
        if total >= 1:
            return "low"
        return "none"


# Synchronous rate limit tracker (legacy, in-memory only — used by BruteForceRule)
_sync_auth_tracker = RateLimitTracker(window_seconds=300, max_failures=5)
_sync_ip_based_tracker = RateLimitTracker(window_seconds=60, max_failures=10)


def record_auth_event_sync(
    event_type: str,
    source_ip: str,
    user: str,
    success: bool,
) -> Dict[str, Any]:
    """Synchronous version of record_auth_event — uses in-memory tracking.
    Kept for backward compatibility with BruteForceRule.evaluate()."""
    result: Dict[str, Any] = {
        "ip": source_ip, "user": user, "event_type": event_type,
        "detected": False, "threat_type": None, "severity": "none",
        "risk_score": 0, "failed_count": 0, "total_count": 0, "message": "",
    }
    if not source_ip or source_ip.startswith(("10.", "172.", "192.", "127.", "0.")):
        return result
    _sync_auth_tracker.record_attempt(source_ip, user, success)
    _sync_ip_based_tracker.record_attempt(source_ip, user, success)
    failed = _sync_auth_tracker.get_failed_count(source_ip, user)
    total = _sync_auth_tracker.get_total_count(source_ip, user)
    threat_level = _sync_auth_tracker.get_threat_level(source_ip, user)
    result["failed_count"] = failed
    result["total_count"] = total
    result["severity"] = threat_level
    if _sync_auth_tracker.is_brute_force(source_ip, user):
        result["detected"] = True
        result["threat_type"] = "brute_force"
        result["risk_score"] = 75.0 + min(failed * 2, 20)
        result["message"] = (
            f"Brute force detected: {failed} failed logins to user '{user}' "
            f"from IP {source_ip} in {300}s window"
        )
        log.warning("BRUTE FORCE: %s from %s targeting %s (%d attempts)",
                    event_type, source_ip, user, failed)
    ip_target_count = _sync_auth_tracker.check_credential_stuffing(source_ip)
    if ip_target_count >= 5:
        result["detected"] = True
        result["threat_type"] = "credential_stuffing"
        result["severity"] = "high"
        result["risk_score"] = 70.0
        result["message"] = (
            f"Credential stuffing detected: IP {source_ip} targeting "
            f"{ip_target_count} different users"
        )
        log.warning("CRED STUFFING: %s from %s targeting %d users",
                    source_ip, ip_target_count)
    user_target_count = _sync_auth_tracker.check_password_spray(user)
    if user_target_count >= 3:
        result["detected"] = True
        result["threat_type"] = "password_spray"
        result["severity"] = "high"
        result["risk_score"] = 65.0
        result["message"] = (
            f"Password spray detected: user '{user}' targeted by "
            f"{user_target_count} different IPs"
        )
        log.warning("PASSWORD SPRAY: user %s targeted by %d IPs",
                    user, user_target_count)
    if not success and failed >= _sync_auth_tracker.max_failures:
        result["detected"] = True
        result["threat_type"] = "auth_failure_threshold"
        result["risk_score"] = 60.0
        result["message"] = (
            f"Auth failure threshold reached: {failed} failures for user '{user}' "
            f"from IP {source_ip}"
        )
    return result


# Global rate limit tracker instances — use Redis-backed for horizontal scaling
_auth_tracker = RateLimitTrackerRedis(window_seconds=300, max_failures=5, tracker_name="auth")
_ip_based_tracker = RateLimitTrackerRedis(window_seconds=60, max_failures=10, tracker_name="ip")


async def record_auth_event(
    event_type: str,
    source_ip: str,
    user: str,
    success: bool,
) -> Dict[str, Any]:
    """
    Record an auth event and return detection results.
    Call this for every authentication-related event.
    Uses Redis-backed tracker for horizontal scaling.
    """
    result: Dict[str, Any] = {
        "ip": source_ip,
        "user": user,
        "event_type": event_type,
        "detected": False,
        "threat_type": None,
        "severity": "none",
        "risk_score": 0,
        "failed_count": 0,
        "total_count": 0,
        "message": "",
    }

    if not source_ip or source_ip.startswith(("10.", "172.", "192.", "127.", "0.")):
        return result

    # Record the attempt
    await _auth_tracker.record_attempt(source_ip, user, success)
    await _ip_based_tracker.record_attempt(source_ip, user, success)

    failed = await _auth_tracker.get_failed_count(source_ip, user)
    total = await _auth_tracker.get_total_count(source_ip, user)
    threat_level = await _auth_tracker.get_threat_level(source_ip, user)

    result["failed_count"] = failed
    result["total_count"] = total
    result["severity"] = threat_level

    # Brute force: N+ failed logins to same user from same IP
    if await _auth_tracker.is_brute_force(source_ip, user):
        result["detected"] = True
        result["threat_type"] = "brute_force"
        result["risk_score"] = 75.0 + min(failed * 2, 20)
        result["message"] = (
            f"Brute force detected: {failed} failed logins to user '{user}' "
            f"from IP {source_ip} in {300}s window"
        )
        log.warning("BRUTE FORCE: %s from %s targeting %s (%d attempts)",
                    event_type, source_ip, user, failed)

    # Credential stuffing: 1 IP targeting many users
    ip_target_count = await _auth_tracker.check_credential_stuffing(source_ip)
    if ip_target_count >= 5:
        result["detected"] = True
        result["threat_type"] = "credential_stuffing"
        result["severity"] = "high"
        result["risk_score"] = 70.0
        result["message"] = (
            f"Credential stuffing detected: IP {source_ip} targeting "
            f"{ip_target_count} different users"
        )
        log.warning("CRED STUFFING: %s from %s targeting %d users",
                    source_ip, ip_target_count)

    # Password spray: many IPs targeting 1 user
    user_target_count = await _auth_tracker.check_password_spray(user)
    if user_target_count >= 3:
        result["detected"] = True
        result["threat_type"] = "password_spray"
        result["severity"] = "high"
        result["risk_score"] = 65.0
        result["message"] = (
            f"Password spray detected: user '{user}' targeted by "
            f"{user_target_count} different IPs"
        )
        log.warning("PASSWORD SPRAY: user %s targeted by %d IPs",
                    user, user_target_count)

    # Impossible travel: success after many failures from different IPs
    # (would need GeoIP + history tracking - basic version)
    if not success and failed >= _auth_tracker.max_failures:
        result["detected"] = True
        result["threat_type"] = "auth_failure_threshold"
        result["risk_score"] = 60.0
        result["message"] = (
            f"Auth failure threshold reached: {failed} failures for user '{user}' "
            f"from IP {source_ip}"
        )

    return result
