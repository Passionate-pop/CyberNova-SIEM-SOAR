"""
CyberNova — Detection Stage
Evaluates enriched events against ALL rule engines:
1. Static RuleEngine (hardcoded rules + Sigma + Cloud + K8s)
2. DSL DetectionRulesEngine (DB-stored tenant-specific rules)
3. Stateful rules (rate limiting, behavioral)
Produces unified Alert objects with MITRE ATT&CK mappings.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from cybernova.pipeline.bus import PipelineEnvelope
from cybernova.pipeline.stages.base import PipelineStage
from cybernova.detection.rules_engine.rules import rule_engine
from cybernova.detection.rules_engine.rules_dsl import detection_rules_engine
from cybernova.core.utils.helpers import new_id, utcnow
from cybernova.protection.process_shield import process_shield
from cybernova.protection.network_shield import network_shield
from cybernova.monitoring.metrics import metrics

log = logging.getLogger("cybernova.pipeline.stage.detector")


class DetectionStage(PipelineStage):
    """Unified detection: static rules + DSL rules + stateful rules."""

    def __init__(self):
        super().__init__("detection")
        self._dsl_initialized = False

    # Event types that should NEVER trigger alerts — these are system noise
    SKIP_EVENT_TYPES = frozenset({
        "agent_heartbeat", "heartbeat", "keepalive", "ping",
        "agent_status", "telemetry", "health_check",
    })

    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        enriched = envelope.payload.get("enriched_data", {})
        normalized = envelope.payload.get("normalized_data", {})
        if not enriched and not normalized:
            log.warning("Detection: no event data for %s", envelope.event_id)
            return envelope

        # Filter out system noise events — prevents false positive alerts
        event_type = enriched.get("event_type", normalized.get("event_type", ""))
        if event_type in self.SKIP_EVENT_TYPES:
            log.debug("Detection: skipping noise event type=%s id=%s", event_type, envelope.event_id)
            envelope.stage = "correlation"
            envelope.payload.setdefault("alerts", [])
            return envelope

        # Merge enriched + normalized for full context
        raw = envelope.payload.get("raw_data", {}) or {}
        extra_fields = {k: v for k, v in raw.items()
                        if k not in ("event_type", "severity", "source_ip", "dest_ip",
                                     "protocol", "user", "message", "risk_score",
                                     "source_port", "dest_port", "device_id",
                                     "hostname", "ip_address")}
        event_data = {
            "event_type": enriched.get("event_type", normalized.get("event_type", "")),
            "severity": enriched.get("severity", normalized.get("severity", "info")),
            "source_ip": enriched.get("source_ip", normalized.get("source_ip", "")),
            "dest_ip": enriched.get("dest_ip", normalized.get("dest_ip", "")),
            "protocol": enriched.get("protocol", normalized.get("protocol", "")),
            "user": enriched.get("user", normalized.get("user", "")),
            "message": enriched.get("message", normalized.get("message", "")),
            "risk_score": enriched.get("risk_score", 0.0),
            "source_port": enriched.get("source_port", 0),
            "dest_port": enriched.get("dest_port", 0),
            "id": envelope.event_id,
            "extra": extra_fields,
            "extra_data": extra_fields,
        }

        triggered_alerts: List[Dict[str, Any]] = []

        # Stage 1: Static RuleEngine (stateless rules)
        triggered_static = await self.run_in_executor(rule_engine.evaluate, event_data)
        for rule in triggered_static:
            alert = self._build_alert(
                envelope, rule.name, rule.severity, rule.risk_score,
                f"{rule.description}: {event_data.get('message', '')[:200]}",
                mitre_tactic=getattr(rule, "mitre_tactic", None),
                mitre_technique=getattr(rule, "mitre_technique", None),
            )
            triggered_alerts.append(alert)
            metrics.increment("detection_rule_hits_total", tags={"rule": rule.name})

        # Stage 2: Stateful rules (rate limiting, behavioral)
        stateful_results = await self.run_in_executor(rule_engine.evaluate_stateful, event_data)
        for result in stateful_results:
            if result and result.get("detected"):
                rule_name_s = result.get("threat_type", "stateful_detection")
                alert = self._build_alert(
                    envelope,
                    rule_name_s,
                    result.get("severity", "high"),
                    result.get("risk_score", 50.0),
                    result.get("message", "Stateful detection triggered"),
                    mitre_tactic=result.get("mitre_tactic"),
                    mitre_technique=result.get("mitre_technique"),
                )
                triggered_alerts.append(alert)
                metrics.increment("detection_rule_hits_total", tags={"rule": rule_name_s})

        # Stage 3: DSL RulesEngine (DB-stored, tenant-specific)
        tenant_id = envelope.tenant_id
        try:
            await self._ensure_dsl_rules(tenant_id)
            dsl_matched = await detection_rules_engine.evaluate(event_data, tenant_id)
            for dsl_rule in dsl_matched:
                alert = self._build_alert(
                    envelope,
                    dsl_rule.name,
                    dsl_rule.severity,
                    dsl_rule.risk_score,
                    f"{dsl_rule.description}: {event_data.get('message', '')[:200]}",
                )
                triggered_alerts.append(alert)
                metrics.increment("detection_rule_hits_total", tags={"rule": dsl_rule.name})
        except Exception as e:
            log.warning("DSL rule evaluation failed for tenant %s: %s", tenant_id, e)

        # Stage 4: ProcessShield — advanced process-based threat detection
        try:
            ps_result = process_shield.analyze_event(event_data)
            if ps_result.get("threat_detected"):
                for finding in ps_result.get("findings", []):
                    alert = self._build_alert(
                        envelope,
                        finding.get("type", "process_shield_detection"),
                        "critical" if finding.get("risk_score", 0) >= 90 else (
                            "high" if finding.get("risk_score", 0) >= 70 else "medium"
                        ),
                        finding.get("risk_score", 80.0),
                        finding.get("message", "ProcessShield detection triggered"),
                        mitre_tactic="TA0005",
                        mitre_technique="T1055",
                    )
                    triggered_alerts.append(alert)
                    metrics.increment("detection_rule_hits_total", tags={"rule": finding.get("type", "process_shield")})
        except Exception as e:
            log.warning("ProcessShield evaluation error: %s", e)

        # Stage 5: NetworkShield — advanced network-based threat detection
        try:
            ns_result = network_shield.analyze_event(event_data)
            if ns_result.get("threat_detected"):
                for finding in ns_result.get("findings", []):
                    alert = self._build_alert(
                        envelope,
                        finding.get("type", "network_shield_detection"),
                        "critical" if finding.get("risk_score", 0) >= 90 else (
                            "high" if finding.get("risk_score", 0) >= 70 else "medium"
                        ),
                        finding.get("risk_score", 80.0),
                        finding.get("message", "NetworkShield detection triggered"),
                        mitre_tactic="TA0011",
                        mitre_technique="T1046",
                    )
                    triggered_alerts.append(alert)
                    metrics.increment("detection_rule_hits_total", tags={"rule": finding.get("type", "network_shield")})
        except Exception as e:
            log.warning("NetworkShield evaluation error: %s", e)

        # Apply alert suppression (dedup + suppression rules)
        try:
            from cybernova.suppression.engine import suppression_engine
            filtered_alerts = []
            for alert in triggered_alerts:
                match = await suppression_engine.evaluate({
                    "rule_name": alert.get("rule_name", ""),
                    "source_ip": alert.get("source_ip", ""),
                    "severity": alert.get("severity", "info"),
                    "risk_score": alert.get("risk_score", 0),
                    "event_type": alert.get("event_type", ""),
                    "description": alert.get("description", ""),
                }, envelope.tenant_id)
                if not match.suppressed:
                    filtered_alerts.append(alert)
                else:
                    log.debug("Alert '%s' suppressed: %s", alert.get("rule_name"), match.reason)
            triggered_alerts = filtered_alerts
        except Exception as e:
            log.warning("Suppression evaluation error: %s", e)

        existing_alerts = envelope.payload.get("alerts", [])
        envelope.payload["alerts"] = existing_alerts + triggered_alerts
        envelope.stage = "correlation"
        return envelope

    async def _ensure_dsl_rules(self, tenant_id: str) -> None:
        if not self._dsl_initialized:
            await detection_rules_engine.load_rules(tenant_id)
            self._dsl_initialized = True
        else:
            rules = detection_rules_engine._rules.get(tenant_id)
            if not rules:
                await detection_rules_engine.load_rules(tenant_id)

    def _build_alert(
        self,
        envelope: PipelineEnvelope,
        rule_name: str,
        severity: str,
        risk_score: float,
        description: str,
        mitre_tactic: Optional[str] = None,
        mitre_technique: Optional[str] = None,
    ) -> Dict[str, Any]:
        envelope.payload.get("enriched_data", {})
        normalized = envelope.payload.get("normalized_data", {})
        return {
            "id": new_id(),
            "tenant_id": envelope.tenant_id,
            "event_id": envelope.event_id,
            "rule_name": rule_name,
            "severity": severity,
            "risk_score": risk_score,
            "description": description,
            "status": "new",
            "source_ip": normalized.get("source_ip", ""),
            "dest_ip": normalized.get("dest_ip", ""),
            "user": normalized.get("user", ""),
            "event_type": normalized.get("event_type", ""),
            "device_id": normalized.get("device_id", ""),
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "created_at": utcnow().isoformat(),
            "raw_event": normalized.get("extra_data", {}),
        }


detection_stage = DetectionStage()
