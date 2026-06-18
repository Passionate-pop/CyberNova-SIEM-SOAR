"""
On-call routing. P1 → PagerDuty + Opsgenie. P2 → email.
Integrates with SLO breach callbacks + pipeline health monitoring.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cybernova.monitoring.slo import SLOBreach, slo_engine

log = logging.getLogger("cybernova.alerting.oncall")

PD_ROUTING_KEY = os.environ.get("CYBERNOVA_PAGERDUTY_KEY", "")
OG_API_KEY = os.environ.get("CYBERNOVA_OPSGENIE_KEY", "")


def classify_breach(breach: SLOBreach) -> str:
    """Classify an SLO breach as P1 (page) or P2 (email).

    P1 — Critical infrastructure failure:
      * Detection or alert stage success rate below SLO threshold
      * Detection or alert stage P99 latency breach (may indicate stage hung)

    P2 — Performance degradation:
      * Any other stage latency or throughput SLO violation
    """
    stage = breach.stage
    for v in breach.violations:
        if stage in ("detection", "alert") and "success_rate" in v:
            return "P1"
        if stage in ("detection", "alert") and "p99_latency" in v:
            return "P1"
    return "P2"


class OnCallRouter:
    """Routes infrastructure-health alerts to on-call channels by severity.

    P1 → PagerDuty + Opsgenie (pages, with 5-minute cooldown)
    P2 → email notification to on-call alias
    """

    def __init__(
        self,
        oncall_email: str = "",
        p1_cooldown: int = 300,
        health_check_interval: int = 60,
    ) -> None:
        self._oncall_email = oncall_email
        self._p1_cooldown = p1_cooldown
        self._health_interval = health_check_interval
        self._last_p1: Optional[datetime] = None
        self._pipeline_was_running: Optional[bool] = None
        self._health_task: Optional[asyncio.Task] = None
        self._pd_enabled = bool(PD_ROUTING_KEY)
        self._og_enabled = bool(OG_API_KEY)

    # lifecycle

    def register(self) -> None:
        """Register the SLO breach callback so every SLO violation is routed."""
        slo_engine.on_breach(self._handle_breach)
        log.info(
            "OnCallRouter registered | pagerduty=%s opsgenie=%s email=%s",
            self._pd_enabled, self._og_enabled, bool(self._oncall_email),
        )

    def start_periodic_health_check(self) -> None:
        """Launch the background pipeline-health monitoring loop."""
        if self._health_task is not None:
            return
        self._health_task = asyncio.create_task(self._health_loop())

    async def stop(self) -> None:
        """Cancel the health-check loop."""
        if self._health_task is not None:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
            self._health_task = None

    async def _health_loop(self) -> None:
        """Periodically check whether the pipeline is running and healthy."""
        while True:
            try:
                await self._check_pipeline_health()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Pipeline health check error: %s", exc)
            await asyncio.sleep(self._health_interval)

    async def _check_pipeline_health(self) -> None:
        """Detect pipeline-down condition and route a P1 alert on transition."""
        try:
            from cybernova.pipeline.unified_pipeline import unified_pipeline
            running = unified_pipeline._running
        except Exception:
            return

        prev = self._pipeline_was_running
        self._pipeline_was_running = running

        if prev is None:
            return
        if prev is True and running is False:
            log.warning("Pipeline transitioned to DOWN — routing P1 alert")
            self._route_p1_alert(
                title="Pipeline Down",
                summary="Pipeline orchestrator is no longer running",
                details={"running": False, "previous_state": "running"},
            )

    # slo breach handler

    def _handle_breach(self, breach: SLOBreach) -> None:
        severity = classify_breach(breach)
        log.info(
            "SLO breach [%s] stage=%s violations=%s",
            severity, breach.stage, breach.violations,
        )
        if severity == "P1":
            self._route_p1_breach(breach)
        else:
            self._route_p2_breach(breach)

    # p1 routing

    def _route_p1_breach(self, breach: SLOBreach) -> None:
        now = datetime.now(timezone.utc)
        if self._last_p1 is not None:
            elapsed = (now - self._last_p1).total_seconds()
            if elapsed < self._p1_cooldown:
                log.info("P1 suppressed (cooldown %ds)", self._p1_cooldown - int(elapsed))
                return
        self._last_p1 = now

        self._route_p1_alert(
            title=f"SLO Breach: {breach.stage}",
            summary="[P1] {} — {}".format(
                breach.stage, "; ".join(breach.violations),
            ),
            details=breach.snapshot,
        )

    def _route_p1_alert(
        self,
        title: str,
        summary: str,
        details: Dict[str, Any],
    ) -> None:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        incident: Dict[str, Any] = {
            "id": f"p1-{now_ts}",
            "title": title,
            "severity": "critical",
            "description": summary,
            "risk_score": 100,
            "source_ip": "",
            "dest_ip": "",
            "user": "system",
        }

        if self._pd_enabled:
            try:
                from cybernova.response.actions.pagerduty_trigger import (
                    execute_pagerduty_trigger,
                )
                result = execute_pagerduty_trigger(incident)
                log.info("PagerDuty P1 alert sent: %s", result.get("dedup_key", ""))
            except Exception as exc:
                log.error("PagerDuty P1 trigger failed: %s", exc)

        if self._og_enabled:
            try:
                from cybernova.response.actions.opsgenie_trigger import (
                    execute_opsgenie_trigger,
                )
                result = execute_opsgenie_trigger(incident)
                log.info("Opsgenie P1 alert sent: %s", result.get("alias", ""))
            except Exception as exc:
                log.error("Opsgenie P1 trigger failed: %s", exc)

        if not self._pd_enabled and not self._og_enabled:
            log.info("P1 alert (no pager configured): %s — %s", title, summary)

    # p2 routing

    def _route_p2_breach(self, breach: SLOBreach) -> None:
        if not self._oncall_email:
            log.debug("P2 skipped — no oncall email configured")
            return

        subject = "[P2] SLO Warning — {}".format(breach.stage)
        body_lines = [
            "CyberNova SLO Warning",
            "",
            f"  Stage:      {breach.stage}",
            f"  Timestamp:  {breach.timestamp}",
            "  Violations:",
        ]
        for v in breach.violations:
            body_lines.append(f"    - {v}")
        body_lines.append("")
        body_lines.append("  Snapshot:")
        for k, v in breach.snapshot.items():
            body_lines.append(f"    {k}: {v}")

        incident: Dict[str, Any] = {
            "id": "p2-{}".format(int(datetime.now(timezone.utc).timestamp())),
            "title": subject,
            "severity": "high",
            "description": "\n".join(body_lines),
            "risk_score": 50,
            "source_ip": "",
            "dest_ip": "",
            "user": "system",
            "to": self._oncall_email,
        }

        try:
            from cybernova.response.actions.email_alert import execute_email_alert
            result = execute_email_alert(incident)
            log.info("P2 email sent: %s", result)
        except Exception as exc:
            log.error("P2 email failed: %s", exc)


oncall_router = OnCallRouter()
