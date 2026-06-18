"""
CyberNova — Session Manager
Server-side session tracking with Redis. Concurrent session limits.
Forced logout capability for users and tenants.
Graceful degradation to in-memory store when Redis is unavailable.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from cybernova.database.redis import get_redis
from cybernova.core.utils.helpers import new_id

log = logging.getLogger("cybernova.auth.session")

SESSION_TTL = 86400
MAX_CONCURRENT_SESSIONS = 5
SESSION_PREFIX = "session:"
USER_SESSIONS_PREFIX = "user_sessions:"
TENANT_USER_SESSIONS_PREFIX = "tenant_sessions:"


@dataclass
class SessionRecord:
    session_id: str
    user_id: str
    tenant_id: str
    username: str
    roles: List[str] = field(default_factory=list)
    ip_address: str = ""
    user_agent: str = ""
    created_at: float = 0.0
    last_activity: float = 0.0
    expires_at: float = 0.0
    is_active: bool = True


def _now() -> float:
    return time.time()


def _session_key(session_id: str) -> str:
    return f"{SESSION_PREFIX}{session_id}"


def _user_sessions_key(tenant_id: str, user_id: str) -> str:
    return f"{USER_SESSIONS_PREFIX}{tenant_id}:{user_id}"


def _tenant_key(tenant_id: str) -> str:
    return f"{TENANT_USER_SESSIONS_PREFIX}{tenant_id}"


class InMemorySessionStore:
    """Fallback in-memory store when Redis is unavailable."""

    def __init__(self):
        self._sessions: Dict[str, SessionRecord] = {}
        self._user_sessions: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()

    async def set(self, session: SessionRecord, ttl: int) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session
            ukey = _user_sessions_key(session.tenant_id, session.user_id)
            if ukey not in self._user_sessions:
                self._user_sessions[ukey] = set()
            self._user_sessions[ukey].add(session.session_id)

    async def get(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def delete(self, session_id: str) -> bool:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if session:
                ukey = _user_sessions_key(session.tenant_id, session.user_id)
                if ukey in self._user_sessions:
                    self._user_sessions[ukey].discard(session_id)
                return True
            return False

    async def get_user_sessions(self, tenant_id: str, user_id: str) -> List[SessionRecord]:
        async with self._lock:
            ukey = _user_sessions_key(tenant_id, user_id)
            session_ids = self._user_sessions.get(ukey, set())
            return [self._sessions[sid] for sid in session_ids if sid in self._sessions]

    async def delete_user_sessions(self, tenant_id: str, user_id: str) -> int:
        async with self._lock:
            ukey = _user_sessions_key(tenant_id, user_id)
            session_ids = self._user_sessions.pop(ukey, set())
            count = 0
            for sid in session_ids:
                if sid in self._sessions:
                    self._sessions[sid].is_active = False
                    count += 1
            return count

    async def cleanup_expired(self) -> int:
        async with self._lock:
            now = _now()
            expired = [sid for sid, s in self._sessions.items() if s.expires_at <= now]
            for sid in expired:
                s = self._sessions.pop(sid, None)
                if s:
                    ukey = _user_sessions_key(s.tenant_id, s.user_id)
                    if ukey in self._user_sessions:
                        self._user_sessions[ukey].discard(sid)
            return len(expired)


class SessionManager:
    """
    Server-side session management with Redis.
    Falls back to in-memory store when Redis is unavailable.
    Enforces concurrent session limits and supports forced logout.
    """

    def __init__(self):
        self._memory = InMemorySessionStore()
        self._redis = None
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def _get_redis(self):
        if self._redis is None:
            try:
                self._redis = await get_redis()
            except Exception:
                log.debug("Redis not available for session manager, using in-memory store")
        return self._redis

    def _record_to_dict(self, session: SessionRecord) -> Dict[str, Any]:
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "tenant_id": session.tenant_id,
            "username": session.username,
            "roles": json.dumps(session.roles),
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "created_at": str(session.created_at),
            "last_activity": str(session.last_activity),
            "expires_at": str(session.expires_at),
            "is_active": "1" if session.is_active else "0",
        }

    def _dict_to_record(self, data: Dict[str, Any]) -> Optional[SessionRecord]:
        try:
            return SessionRecord(
                session_id=data.get("session_id", ""),
                user_id=data.get("user_id", ""),
                tenant_id=data.get("tenant_id", ""),
                username=data.get("username", ""),
                roles=json.loads(data.get("roles", "[]")),
                ip_address=data.get("ip_address", ""),
                user_agent=data.get("user_agent", ""),
                created_at=float(data.get("created_at", 0)),
                last_activity=float(data.get("last_activity", 0)),
                expires_at=float(data.get("expires_at", 0)),
                is_active=data.get("is_active", "0") == "1",
            )
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            log.warning("Failed to decode session record: %s", e)
            return None

    async def create_session(
        self,
        user_id: str,
        tenant_id: str,
        username: str,
        roles: Optional[List[str]] = None,
        ip_address: str = "",
        user_agent: str = "",
        ttl: int = SESSION_TTL,
        max_concurrent: int = MAX_CONCURRENT_SESSIONS,
    ) -> SessionRecord:
        """Create a new session. Enforces concurrent session limit."""
        now = _now()
        session = SessionRecord(
            session_id=new_id(),
            user_id=user_id,
            tenant_id=tenant_id,
            username=username,
            roles=roles or [],
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            last_activity=now,
            expires_at=now + ttl,
            is_active=True,
        )

        redis = await self._get_redis()
        if redis:
            try:
                ukey = _user_sessions_key(tenant_id, user_id)
                current = await redis.scard(ukey)
                if current >= max_concurrent:
                    oldest = await redis.sort(
                        ukey, by=f"{SESSION_PREFIX}*->created_at",
                        get=f"{SESSION_PREFIX}*->session_id",
                        alpha=True, start=0, num=1,
                    )
                    if oldest:
                        await self.revoke_session(oldest[0])

                await redis.hset(_session_key(session.session_id), mapping=self._record_to_dict(session))
                await redis.expire(_session_key(session.session_id), ttl)
                await redis.sadd(ukey, session.session_id)
                await redis.expire(ukey, ttl)
                log.info("Session created: user=%s session=%s", user_id, session.session_id[:8])
                return session
            except Exception as e:
                log.warning("Redis session create failed, falling back to memory: %s", e)
                self._redis = None

        current_user_sessions = await self._memory.get_user_sessions(tenant_id, user_id)
        if len(current_user_sessions) >= max_concurrent:
            oldest = min(current_user_sessions, key=lambda s: s.created_at)
            await self._memory.delete(oldest.session_id)

        await self._memory.set(session, ttl)
        log.info("Session created (memory): user=%s session=%s", user_id, session.session_id[:8])
        return session

    async def get_session(self, session_id: str) -> Optional[SessionRecord]:
        """Retrieve session by ID."""
        redis = await self._get_redis()
        if redis:
            try:
                data = await redis.hgetall(_session_key(session_id))
                if data:
                    record = self._dict_to_record(data)
                    if record and record.is_active:
                        return record
                return None
            except Exception as e:
                log.warning("Redis session get failed: %s", e)
                self._redis = None

        return await self._memory.get(session_id)

    async def validate_session(self, session_id: str) -> bool:
        """Check if a session is active and not expired."""
        session = await self.get_session(session_id)
        if not session:
            return False
        if not session.is_active:
            return False
        if session.expires_at <= _now():
            return False
        return True

    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a specific session (forced logout)."""
        redis = await self._get_redis()
        if redis:
            try:
                data = await redis.hgetall(_session_key(session_id))
                if data:
                    tenant_id = data.get("tenant_id", "")
                    user_id = data.get("user_id", "")
                    await redis.delete(_session_key(session_id))
                    if tenant_id and user_id:
                        ukey = _user_sessions_key(tenant_id, user_id)
                        await redis.srem(ukey, session_id)
                    log.info("Session revoked: %s", session_id[:8])
                    return True
                return False
            except Exception as e:
                log.warning("Redis session revoke failed: %s", e)
                self._redis = None

        return await self._memory.delete(session_id)

    async def revoke_user_sessions(self, tenant_id: str, user_id: str) -> int:
        """Revoke all sessions for a user (force logout everywhere)."""
        count = 0
        redis = await self._get_redis()
        if redis:
            try:
                ukey = _user_sessions_key(tenant_id, user_id)
                session_ids = await redis.smembers(ukey)
                for sid in session_ids:
                    await redis.delete(_session_key(sid))
                await redis.delete(ukey)
                count = len(session_ids)
                if count:
                    log.info("All sessions revoked: user=%s count=%d", user_id, count)
                return count
            except Exception as e:
                log.warning("Redis revoke user sessions failed: %s", e)
                self._redis = None

        return await self._memory.delete_user_sessions(tenant_id, user_id)

    async def revoke_tenant_sessions(self, tenant_id: str) -> int:
        """Revoke all sessions for a tenant (admin force logout)."""
        redis = await self._get_redis()
        if redis:
            try:
                tkey = _tenant_key(tenant_id)
                session_ids = await redis.smembers(tkey)
                for sid in session_ids:
                    await redis.delete(_session_key(sid))
                await redis.delete(tkey)
                log.info("All tenant sessions revoked: tenant=%s count=%d", tenant_id, len(session_ids))
                return len(session_ids)
            except Exception as e:
                log.warning("Redis revoke tenant sessions failed: %s", e)
                self._redis = None

        return 0

    async def list_user_sessions(
        self, tenant_id: str, user_id: str,
    ) -> List[Dict[str, Any]]:
        """List active sessions for a user."""
        redis = await self._get_redis()
        if redis:
            try:
                ukey = _user_sessions_key(tenant_id, user_id)
                session_ids = await redis.smembers(ukey)
                result = []
                for sid in sorted(session_ids):
                    data = await redis.hgetall(_session_key(sid))
                    if data:
                        record = self._dict_to_record(data)
                        if record:
                            result.append(self._record_to_output(record))
                return result
            except Exception as e:
                log.warning("Redis list user sessions failed: %s", e)
                self._redis = None

        sessions = await self._memory.get_user_sessions(tenant_id, user_id)
        return [self._record_to_output(s) for s in sessions]

    async def list_tenant_sessions(
        self, tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """List all active sessions for a tenant (admin view)."""
        redis = await self._get_redis()
        if redis:
            try:
                tkey = _tenant_key(tenant_id)
                session_ids = await redis.smembers(tkey)
                result = []
                for sid in sorted(session_ids):
                    data = await redis.hgetall(_session_key(sid))
                    if data:
                        record = self._dict_to_record(data)
                        if record:
                            result.append(self._record_to_output(record))
                return result
            except Exception as e:
                log.warning("Redis list tenant sessions failed: %s", e)
                self._redis = None

        return []

    def _record_to_output(self, record: SessionRecord) -> Dict[str, Any]:
        return {
            "session_id": record.session_id,
            "user_id": record.user_id,
            "username": record.username,
            "roles": record.roles,
            "ip_address": record.ip_address,
            "user_agent": record.user_agent,
            "created_at": datetime.fromtimestamp(record.created_at, tz=timezone.utc).isoformat(),
            "last_activity": datetime.fromtimestamp(record.last_activity, tz=timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(record.expires_at, tz=timezone.utc).isoformat(),
            "is_active": record.is_active,
        }

    async def start(self, interval: int = 3600) -> None:
        """Start background cleanup of expired sessions."""
        self._running = True
        self._task = asyncio.create_task(self._cleanup_loop(interval))
        log.info("Session manager cleanup started (interval: %ds)", interval)

    async def stop(self) -> None:
        """Stop background cleanup."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Session manager stopped")

    async def _cleanup_loop(self, interval: int) -> None:
        while self._running:
            try:
                count = await self._memory.cleanup_expired()
                if count:
                    log.debug("Cleaned up %d expired sessions from memory", count)
            except Exception as e:
                log.warning("Session cleanup error: %s", e)
            await asyncio.sleep(interval)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "memory_session_count": len(self._memory._sessions),
            "redis_connected": self._redis is not None,
            "is_running": self._running,
            "default_ttl": SESSION_TTL,
            "default_max_concurrent": MAX_CONCURRENT_SESSIONS,
        }


session_manager = SessionManager()
