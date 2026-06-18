"""
CyberNova — SOAR Execution Worker (AUTONOMOUS MODE)
Consumes response actions from stream and executes ALL action types in real time.
Supports: block_ip, isolate_host, notify_soc, collect_forensics, log_alert
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
from typing import Any, Dict
from uuid import uuid4

import redis.asyncio as aioredis

from cybernova.config.settings import get_settings
from cybernova.streaming.streams import STREAM_ACTIONS, CONSUMER_GROUPS
from cybernova.streaming.consumer import StreamConsumer
from cybernova.streaming.producer import StreamProducer
from cybernova.soar.engine import (
    BlockIPAction, LogAction, IsolateAction, NotifyAction, ForensicsAction,
    KillProcessAction, DisableUserAction, EnableUserAction,
    CreateTicketAction, SendNotificationAction, QuarantineFileAction, ResetMFAAction,
)

log = logging.getLogger("cybernova.streaming.soar_worker")

RETRY_DELAYS = [30, 60, 120]
MAX_RETRIES = 3


class SoarWorker:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self.producer = StreamProducer(redis)
        self.consumer = StreamConsumer(
            redis,
            CONSUMER_GROUPS[STREAM_ACTIONS],
            f"soar-worker-{uuid4().hex[:6]}",
            {"actions": STREAM_ACTIONS},
        )
        self._running = False
        self._tasks: set = set()

    async def start(self) -> None:
        self._running = True
        await self.consumer.ensure_groups()
        log.info("SOAR worker started")
        task = asyncio.create_task(self._run_loop())
        self._tasks.add(task)
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        log.info("SOAR worker stopped")

    async def _run_loop(self) -> None:
        while self._running:
            try:
                messages = await self.consumer.read(count=20, block_ms=5000)
                for stream, msg_id, envelope in messages:
                    try:
                        action = json.loads(envelope.get("data", "{}"))
                        action_id = envelope.get("action_id", action.get("id"))
                        tenant_id = envelope.get("tenant_id", "default")

                        if action.get("status") != "pending":
                            await self.consumer.ack(stream, msg_id)
                            continue

                        await self._execute_action(action, tenant_id, action_id)
                        await self.consumer.ack(stream, msg_id)
                    except Exception as exc:
                        log.error("SOAR execute error %s: %s", msg_id, exc)
                        await self.consumer.nack(stream, msg_id)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("SOAR worker loop error: %s", exc)
                await asyncio.sleep(5)

    async def _execute_action(
        self, action: Dict[str, Any], tenant_id: str, action_id: str
    ) -> None:
        action_type = action.get("action_type", "log")
        payload = action.get("payload", {})
        params = action.get("parameters", {})
        alert = payload.get("alert", {})

        log.info("SOAR worker executing action %s (%s)", action_id, action_type)

        try:
            if action_type == "block_ip":
                ip = alert.get("source_ip", params.get("ip", ""))
                if not ip:
                    ip = payload.get("source_ip", "")
                if not ip:
                    raise ValueError("No IP to block")
                self._execute_block_ip(ip, params)

            elif action_type == "isolate_host":
                source_ip = alert.get("source_ip", "")
                device_id = action.get("device_id", alert.get("device_id", ""))
                log.warning("🧪 SOAR worker isolating host: device=%s ip=%s action=%s", device_id, source_ip, action_id)
                isolate_action = IsolateAction()
                isolate_action.execute({
                    "id": action_id,
                    "title": "SOAR Worker Isolate",
                    "severity": "critical",
                    "source_ip": source_ip,
                    "dest_ip": source_ip,
                    "hostname": device_id,
                })

            elif action_type in ("log_alert", "scan_host"):
                log_action = LogAction()
                log_action.execute({"id": action_id, "title": action_type, "severity": "info"})

            elif action_type in ("notify_soc", "notify_admin"):
                notify_action = NotifyAction()
                notify_action.execute({
                    "id": action_id,
                    "title": alert.get("rule_name", action_type),
                    "severity": alert.get("severity", "critical"),
                    "source_ip": alert.get("source_ip", ""),
                })

            elif action_type == "collect_forensics":
                forensics_action = ForensicsAction()
                forensics_action.execute({
                    "id": action_id,
                    "title": alert.get("rule_name", action_type),
                    "severity": alert.get("severity", "critical"),
                    "source_ip": alert.get("source_ip", ""),
                    "device_id": alert.get("device_id", ""),
                })

            elif action_type == "kill_process":
                pid = params.get("pid", payload.get("pid"))
                process_name = params.get("process_name", payload.get("process_name", ""))
                device_id = action.get("device_id", alert.get("device_id", ""))
                log.warning("Kill process: device=%s pid=%s name=%s", device_id, pid, process_name)
                kill_action = KillProcessAction()
                kill_action.execute({
                    "id": action_id,
                    "pid": pid,
                    "process_name": process_name,
                    "hostname": device_id,
                    "device_id": device_id,
                    "severity": "critical",
                })

            elif action_type == "disable_user":
                username = params.get("username", params.get("user", alert.get("user", "")))
                email = params.get("email", "")
                log.warning("Disable user: %s", username)
                disable_action = DisableUserAction()
                disable_action.execute({
                    "id": action_id,
                    "username": username,
                    "email": email,
                    "severity": "critical",
                })

            elif action_type == "enable_user":
                username = params.get("username", params.get("user", alert.get("user", "")))
                email = params.get("email", "")
                enable_action = EnableUserAction()
                enable_action.execute({
                    "id": action_id,
                    "username": username,
                    "email": email,
                    "severity": "info",
                })

            elif action_type == "create_ticket":
                ticket_action = CreateTicketAction()
                ticket_action.execute({
                    "id": action_id,
                    "title": alert.get("rule_name", action_type),
                    "severity": alert.get("severity", "critical"),
                })

            elif action_type == "send_notification":
                channel = params.get("channel", "webhook")
                notify_action = SendNotificationAction(channel=channel)
                notify_action.execute({
                    "id": action_id,
                    "title": alert.get("rule_name", action_type),
                    "severity": alert.get("severity", "info"),
                })

            elif action_type == "quarantine_file":
                file_path = params.get("file_path", payload.get("file_path", ""))
                sha256 = params.get("sha256", "")
                device_id = action.get("device_id", alert.get("device_id", ""))
                log.warning("Quarantine file: device=%s path=%s", device_id, file_path)
                quarantine_action = QuarantineFileAction()
                quarantine_action.execute({
                    "id": action_id,
                    "file_path": file_path,
                    "sha256": sha256,
                    "hostname": device_id,
                    "severity": "critical",
                })

            elif action_type == "reset_mfa":
                username = params.get("username", params.get("user", alert.get("user", "")))
                email = params.get("email", "")
                log.warning("Reset MFA: user=%s", username)
                mfa_action = ResetMFAAction()
                mfa_action.execute({
                    "id": action_id,
                    "username": username,
                    "email": email,
                    "severity": "critical",
                })

            else:
                engine = self._get_soar_engine()
                engine.trigger({
                    "id": action_id,
                    "title": alert.get("rule_name", action_type),
                    "severity": alert.get("severity", "critical"),
                    "confirmed": True,
                    "risk_score": alert.get("risk_score", 120),
                    "source_ip": alert.get("source_ip", ""),
                    "dest_ip": alert.get("dest_ip", ""),
                })

            log.info("SOAR action %s completed", action_id)

        except Exception as exc:
            log.error("SOAR action %s failed: %s", action_id, exc)
            raise

    def _execute_block_ip(self, ip: str, params: Dict[str, Any]) -> None:
        block_action = BlockIPAction()
        incident = {
            "id": "",
            "title": "SOAR Worker Block",
            "severity": "critical",
            "source_ip": ip,
            "dest_ip": ip,
        }
        success = block_action.execute(incident)
        if success:
            log.warning("🚀 IP %s BLOCKED by SOAR worker", ip)
        else:
            log.error("⛔ Failed to block IP %s by SOAR worker", ip)

    @staticmethod
    def _get_soar_engine():
        from cybernova.soar.engine import get_engine
        return get_engine()


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s [%(levelname)s] %(message)s")

    settings = get_settings()
    redis = aioredis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        password=settings.redis_password or None,
        protocol=2,  # RESP2 — works with --requirepass
        decode_responses=True,
    )

    try:
        await redis.ping()
    except Exception as exc:
        log.error("Cannot connect to Redis: %s", exc)
        sys.exit(1)

    worker = SoarWorker(redis)

    loop = asyncio.get_event_loop()
    # Signals not supported on Windows (add_signal_handler raises NotImplementedError)
    if sys.platform != "win32":
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    else:
        log.info("Signal handlers skipped (Windows)")

    await worker.start()


if __name__ == "__main__":
    asyncio.run(main())
