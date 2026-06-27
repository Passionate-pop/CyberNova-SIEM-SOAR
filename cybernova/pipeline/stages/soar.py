"""
CyberNova — SOAR Stage (AUTONOMOUS MODE)
Executes automated response actions for high/critical alerts.
Also auto-resolves stale incidents (24h with no updates).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
import json as _json
from cybernova.core.utils.helpers import new_id
from sqlalchemy import text

log = logging.getLogger("cybernova.pipeline.stage.soar")


class SOARStage(PipelineStage):
    """Triggers automated response actions for eligible alerts."""

    def __init__(self):
        super().__init__("soar")
        self._remediate_semaphore = asyncio.Semaphore(10)
        self._soar_commands: list = []
        self._soar_blocked_ips: list = []
        self._last_auto_resolve_check: float = 0
        self._flush_lock = asyncio.Lock()

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        alerts = envelope.payload.get("alerts", [])
        tenant_id = envelope.tenant_id

        soar_actions = []
        for alert in alerts:
            severity = alert.get("severity", "")
            risk_score = alert.get("risk_score", 0)
            rule_name = alert.get("rule_name", "")

            # Critical: auto-block with high confidence (risk >= 50 — lowered from 80)
            # High: auto-block if risk >= 40 (lowered from 70), otherwise alert admin
            # Medium: alert admin if risk >= 50 (lowered from 60)
            target_ip = alert.get("source_ip", "") or alert.get("device_id", "")
            if severity == "critical" and risk_score >= 50:
                action = self._determine_action(rule_name, severity)
                if action:
                    soar_actions.append({
                        "alert_id": alert["id"],
                        "action": action,
                        "target": target_ip,
                        "tenant_id": tenant_id,
                        "severity": severity,
                        "rule_name": rule_name,
                        "alert": alert,
                    })
                log.warning("SOAR: critical alert %s (risk=%s) -> %s on %s", rule_name, risk_score, action or "none", target_ip)
            elif severity == "high" and risk_score >= 40:
                # High severity with decent confidence: auto-block
                action = self._determine_action(rule_name, severity)
                if action:
                    soar_actions.append({
                        "alert_id": alert["id"],
                        "action": action,
                        "target": target_ip,
                        "tenant_id": tenant_id,
                        "severity": severity,
                        "rule_name": rule_name,
                        "alert": alert,
                    })
                if action:
                    log.warning("SOAR: high alert %s (risk=%s) -> %s on %s", rule_name, risk_score, action, target_ip)
            elif severity == "high":
                # High severity but lower confidence: alert admin with notify action
                soar_actions.append({
                    "alert_id": alert["id"],
                    "action": "alert_admin",
                    "target": alert.get("source_ip", "") or alert.get("device_id", ""),
                    "tenant_id": tenant_id,
                    "severity": severity,
                    "rule_name": rule_name,
                    "alert": alert,
                })
                log.warning("SOAR: high alert %s (risk=%s) -> admin notification", rule_name, risk_score)
            elif severity == "medium" and risk_score >= 50:
                # Medium severity with higher risk: alert admin
                soar_actions.append({
                    "alert_id": alert["id"],
                    "action": "alert_admin",
                    "target": alert.get("source_ip", "") or alert.get("device_id", ""),
                    "tenant_id": tenant_id,
                    "severity": severity,
                    "rule_name": rule_name,
                    "alert": alert,
                })
                log.warning("SOAR: medium alert %s (risk=%s) -> admin notification", rule_name, risk_score)

        if soar_actions:
            async with self._remediate_semaphore:
                for action in soar_actions:
                    try:
                        await self._execute_action(action)
                    except Exception as e:
                        log.error("SOAR action failed: %s", e)
            await self._flush_soar_actions()

        # Auto-resolve stale incidents every 30 minutes
        await self._auto_resolve_stale_incidents()

        envelope.stage = "notification"
        return envelope

    async def _auto_resolve_stale_incidents(self) -> None:
        """Auto-resolve incidents that have been open for 24+ hours with no updates."""
        import time
        now = time.time()
        if now - self._last_auto_resolve_check < 1800:  # Every 30 minutes
            return
        self._last_auto_resolve_check = now

        try:
            from cybernova.database.postgres.session import get_db_session
            from cybernova.database.postgres.models import Incident
            from sqlalchemy import select, and_
            from datetime import datetime, timezone, timedelta

            async for db in get_db_session():
                cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
                result = await db.execute(
                    select(Incident).where(
                        and_(
                            Incident.status.in_(["new", "in_progress"]),
                            Incident.updated_at < cutoff,
                        )
                    )
                )
                stale = result.scalars().all()
                for incident in stale:
                    incident.status = "resolved"
                    log.warning(
                        "🔄 Auto-resolved stale incident %s (%s) — no updates for 24h+",
                        incident.id, incident.title,
                    )
                if stale:
                    await db.commit()
                    log.info("Auto-resolved %d stale incidents", len(stale))
                break
        except Exception as e:
            log.warning("Auto-resolve check failed: %s", e)

    def _determine_action(self, rule_name: str, severity: str) -> Optional[str]:
        if severity == "critical":
            if any(kw in rule_name.lower() for kw in ("ransomware", "malware", "rootkit", "webshell")):
                return "isolate"
            if any(kw in rule_name.lower() for kw in ("brute_force", "credential", "password_spray")):
                return "block_ip"
            if any(kw in rule_name.lower() for kw in ("exfil", "data_leak", "dlp", "data_exfil")):
                return "block_ip"
            return "block_ip"
        # High severity: auto-block source IP (thresholds already applied in caller)
        if severity == "high":
            return "block_ip"
        return None

    async def _execute_action(self, action: Dict[str, Any]) -> None:
        action_type = action["action"]
        target = action["target"]
        tenant_id = action["tenant_id"]
        alert_id = action["alert_id"]

        if action_type == "isolate" and target:
            log.warning("SOAR: isolate device %s for tenant %s", target, tenant_id)
            self._soar_commands.append({
                "tenant_id": tenant_id,
                "device_id": target,
                "action": "isolate",
                "payload": _json.dumps({"alert_id": alert_id, "source": "soar"}),
            })

        elif action_type == "block_ip" and target:
            log.warning("SOAR: block IP %s for tenant %s", target, tenant_id)
            self._soar_blocked_ips.append({
                "tenant_id": tenant_id,
                "ip_address": target,
                "reason": f"SOAR auto-block from alert {alert_id}",
                "blocked_by": "soar_engine",
            })

        elif action_type == "alert_admin":
            log.info("SOAR: admin alert for alert %s, rule=%s, tenant=%s", alert_id, action.get("rule_name", ""), tenant_id)
            # Admin alerts are logged + broadcast via WebSocket only — no DB write to device_commands

    async def _flush_soar_actions(self) -> None:
        # Atomically swap lists under lock to prevent race condition
        async with self._flush_lock:
            if not self._soar_commands and not self._soar_blocked_ips:
                return
            commands = list(self._soar_commands)
            blocked_ips = list(self._soar_blocked_ips)
            self._soar_commands.clear()
            self._soar_blocked_ips.clear()

        from cybernova.database.postgres.session import get_db_session
        import json as _json
        async for db in get_db_session():
            try:
                for cmd in commands:
                    try:
                        await db.execute(
                            text("""
                                INSERT INTO device_commands (id, tenant_id, device_id, action, payload, status, created_at)
                                VALUES (:id, :tenant_id, :device_id, :action, :payload, 'pending', NOW())
                            """),
                            {
                                "id": new_id(),
                                "tenant_id": cmd["tenant_id"],
                                "device_id": cmd["device_id"],
                                "action": cmd["action"],
                                "payload": _json.dumps(cmd["payload"]) if isinstance(cmd["payload"], dict) else cmd["payload"],
                            },
                        )
                    except Exception as cmd_err:
                        log.warning("SOAR device_command insert skipped (device may not exist): %s", cmd_err)
                for ip_entry in blocked_ips:
                    await db.execute(
                        text("""
                            INSERT INTO blocked_ips (id, tenant_id, ip_address, reason, blocked_by, created_at, expires_at)
                            VALUES (:id, :tenant_id, :ip_address, :reason, :blocked_by, NOW(), NOW() + INTERVAL '1 hour')
                            ON CONFLICT (tenant_id, ip_address) DO UPDATE SET reason = EXCLUDED.reason
                        """),
                        {
                            "id": new_id(),
                            "tenant_id": ip_entry["tenant_id"],
                            "ip_address": ip_entry["ip_address"],
                            "reason": ip_entry["reason"],
                            "blocked_by": ip_entry["blocked_by"],
                        },
                    )
                await db.commit()
                log.info("SOAR flushed: %d commands, %d blocked IPs",
                         len(commands), len(blocked_ips))
            except Exception as e:
                log.error("SOAR batch flush failed: %s", e)
                await db.rollback()
            break


soar_stage = SOARStage()
