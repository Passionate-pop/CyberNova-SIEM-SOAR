"""
CyberNova — Leader Election for HA Pipeline Replicas
Uses Redis atomic SET NX with TTL for distributed leader election.
Falls back to local (always leader) when Redis is unavailable.
"""
import asyncio
import logging
import os
import random  # nosec - used for election jitter, not security
from datetime import datetime, timezone
from typing import Optional

from cybernova.database.redis import get_redis

log = logging.getLogger("cybernova.ha.leader")

LEADER_KEY = "cybernova:ha:leader"
LEADER_TTL = 30  # seconds — lease duration
HEARTBEAT_INTERVAL = 5  # seconds — how often to renew
HEALTH_CHECK_INTERVAL = 10  # seconds — how often followers check leader health


class LeaderElection:
    """
    Distributed leader election using Redis SET NX.
    - One replica acquires the leader lock
    - Leader renews the lock with heartbeat
    - Other replicas are followers that monitor leader health
    - On leader failure, followers compete for the lock
    - Falls back to local mode (always leader) when Redis is unavailable
    """

    def __init__(self, instance_id: Optional[str] = None):
        self.instance_id = instance_id or (
            f"instance-{os.getpid()}-{datetime.now(timezone.utc).strftime('%H%M%S')}"
            f"-{random.randint(1000,9999)}"  # nosec
        )
        self._redis = None
        self._is_leader = False
        self._running = False
        self._leader_heartbeat_task: Optional[asyncio.Task] = None
        self._follower_watch_task: Optional[asyncio.Task] = None
        self._on_leadership_gained: Optional[callable] = None
        self._on_leadership_lost: Optional[callable] = None
        self._local_mode = False

    async def start(self) -> None:
        """Start leader election. Attempts to become leader immediately."""
        self._redis = await get_redis()
        if not self._redis:
            log.warning("Redis unavailable — running in local mode (always leader)")
            self._local_mode = True
            self._is_leader = True
            return

        self._running = True
        # Try to become leader immediately
        await self._try_acquire_lock()
        # Start background tasks
        self._leader_heartbeat_task = asyncio.create_task(self._leader_heartbeat_loop())
        self._follower_watch_task = asyncio.create_task(self._follower_watch_loop())
        log.info("LeaderElection started (instance: %s, leader: %s)", self.instance_id, self._is_leader)

    async def stop(self) -> None:
        """Stop leader election and release lock."""
        self._running = False
        if self._leader_heartbeat_task and not self._leader_heartbeat_task.done():
            self._leader_heartbeat_task.cancel()
        if self._follower_watch_task and not self._follower_watch_task.done():
            self._follower_watch_task.cancel()
        if self._redis and self._is_leader:
            try:
                await self._redis.delete(LEADER_KEY)
                log.info("Released leader lock")
            except Exception as e:
                log.warning("Failed to release leader lock: %s", e)
        self._is_leader = False
        log.info("LeaderElection stopped")

    async def _try_acquire_lock(self) -> bool:
        """Try to acquire the leader lock via SET NX with TTL."""
        if self._local_mode:
            self._is_leader = True
            return True
        try:
            acquired = await self._redis.set(
                LEADER_KEY, self.instance_id,
                nx=True, ex=LEADER_TTL
            )
            if acquired:
                was_leader = self._is_leader
                self._is_leader = True
                log.info("Became leader (instance: %s)", self.instance_id)
                if not was_leader and self._on_leadership_gained:
                    await self._on_leadership_gained()
                return True
            else:
                self._is_leader = False
                return False
        except Exception as e:
            log.error("Leader lock acquire error: %s", e)
            self._is_leader = False
            return False

    async def _renew_lock(self) -> bool:
        """Renew the leader lock TTL."""
        if self._local_mode:
            return True
        try:
            # Use Lua script for atomic check-and-renew
            renew_script = """
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("EXPIRE", KEYS[1], ARGV[2])
            end
            return 0
            """
            renewed = await self._redis.eval(renew_script, 1, LEADER_KEY, self.instance_id, LEADER_TTL)
            if renewed:
                return True
            else:
                log.warning("Lost leader lock — another instance took over")
                was_leader = self._is_leader
                self._is_leader = False
                if was_leader and self._on_leadership_lost:
                    await self._on_leadership_lost()
                return False
        except Exception as e:
            log.error("Leader lock renew error: %s", e)
            return False

    async def _leader_heartbeat_loop(self) -> None:
        """Leader periodically renews the lock."""
        while self._running:
            if self._is_leader:
                if not await self._renew_lock():
                    # Leadership lost, try to re-acquire
                    await self._try_acquire_lock()
            else:
                # Not leader, try to acquire (in case leader died)
                await self._try_acquire_lock()
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def _follower_watch_loop(self) -> None:
        """Followers check if leader is alive and attempt takeover on failure."""
        while self._running:
            if not self._is_leader and not self._local_mode:
                try:
                    leader = await self._redis.get(LEADER_KEY)
                    if leader is None:
                        # Leader died, try to become leader
                        log.info("Leader lock expired — attempting takeover")
                        await self._try_acquire_lock()
                except Exception as e:
                    log.warning("Follower watch error: %s", e)
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    def on_leadership_gained(self, callback: callable) -> None:
        self._on_leadership_gained = callback

    def on_leadership_lost(self, callback: callable) -> None:
        self._on_leadership_lost = callback

    async def get_leader_status(self) -> dict:
        """Get current leader status for health checks."""
        leader_instance = self.instance_id if self._is_leader else None
        if not self._local_mode and self._redis:
            try:
                leader_instance = await self._redis.get(LEADER_KEY)
            except Exception as e:
                log.warning("Failed to get leader from Redis: %s", e)
        return {
            "instance_id": self.instance_id,
            "is_leader": self._is_leader,
            "leader_instance": leader_instance,
            "local_mode": self._local_mode,
            "running": self._running,
        }


leader_election = LeaderElection()
