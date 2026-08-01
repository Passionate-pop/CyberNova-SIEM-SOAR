"""
CyberNova — Pipeline Worker
Consumes from Redis Streams and runs normalize → enrich → detect → correlate stages.
Can run as a single unified worker or split into per-stage workers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import redis.asyncio as aioredis

from cybernova.config.settings import get_settings
from cybernova.streaming.streams import (
    STREAM_RAW_EVENTS, STREAM_NORMALIZED, STREAM_ENRICHED,
    STREAM_ALERTS, CONSUMER_GROUPS, PROCESSOR_CONSUMER_NAME,
)
from cybernova.streaming.producer import StreamProducer
from cybernova.streaming.consumer import StreamConsumer

log = logging.getLogger("cybernova.streaming.worker")


class PipelineWorker:
    def __init__(
        self,
        redis: aioredis.Redis,
        consumer_name: Optional[str] = None,
        stage: Optional[str] = None,
    ) -> None:
        self.redis = redis
        self.producer = StreamProducer(redis)
        self.consumer_name = consumer_name or f"{PROCESSOR_CONSUMER_NAME}-{uuid4().hex[:6]}"
        self.stage = stage
        self._running = False
        self._tasks: set = set()
        self._shutdown_event = asyncio.Event()
        self._raw_batch: list = []
        self._normalized_batch: list = []
        self._alert_batch: list = []
        self._batch_size = 100
        self._flush_task: Optional[asyncio.Task] = None

    def _get_streams_for_stage(self) -> Dict[str, str]:
        if self.stage == "normalizer":
            return {"raw_events": STREAM_RAW_EVENTS}
        elif self.stage == "enrichment":
            return {"normalized": STREAM_NORMALIZED}
        elif self.stage == "detection":
            return {"enriched": STREAM_ENRICHED}
        elif self.stage == "correlation":
            return {"alerts": STREAM_ALERTS}
        return {
            "raw_events": STREAM_RAW_EVENTS,
            "normalized": STREAM_NORMALIZED,
            "enriched": STREAM_ENRICHED,
            "alerts": STREAM_ALERTS,
        }

    async def _get_consumer_group(self) -> str:
        if self.stage == "normalizer":
            return CONSUMER_GROUPS.get(STREAM_RAW_EVENTS, "normalizer_group")
        elif self.stage == "enrichment":
            return CONSUMER_GROUPS.get(STREAM_NORMALIZED, "enrichment_group")
        elif self.stage == "detection":
            return CONSUMER_GROUPS.get(STREAM_ENRICHED, "detection_group")
        elif self.stage == "correlation":
            return CONSUMER_GROUPS.get(STREAM_ALERTS, "correlation_group")
        return "unified_group"

    async def start(self) -> None:
        self._running = True
        streams = self._get_streams_for_stage()
        group = await self._get_consumer_group()
        consumer = StreamConsumer(self.redis, group, self.consumer_name, streams)
        await consumer.ensure_groups()
        self._consumer = consumer

        if self.stage:
            log.info("Starting %s worker: %s", self.stage, self.consumer_name)
        else:
            log.info("Starting unified pipeline worker: %s", self.consumer_name)

        worker_task = asyncio.create_task(self._run_loop())
        self._tasks.add(worker_task)
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def drain(self, timeout: float = 5.0) -> int:
        """Flush pending batches and stop accepting new work."""
        self._running = False
        self._shutdown_event.set()
        deadline = time.monotonic() + timeout
        event_count = len(self._raw_batch) + len(self._normalized_batch)
        alert_count = len(self._alert_batch)
        try:
            await asyncio.wait_for(self._flush_event_batches(), timeout=max(0.1, timeout * 0.4))
        except asyncio.TimeoutError:
            log.warning("Pipeline worker %s: event batch drain timed out", self.consumer_name)
        budget = max(0.1, time.monotonic() - deadline + timeout)
        try:
            await asyncio.wait_for(self._flush_alert_batches(), timeout=budget * 0.4)
        except asyncio.TimeoutError:
            log.warning("Pipeline worker %s: alert batch drain timed out", self.consumer_name)
        drained = event_count + alert_count
        if drained:
            log.info("Pipeline worker %s: drained %d items", self.consumer_name, drained)
        return drained

    async def stop(self) -> None:
        self._running = False
        self._shutdown_event.set()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        log.info("Pipeline worker %s stopped", self.consumer_name)

    async def _run_loop(self) -> None:
        cycle = 0
        while self._running:
            try:
                messages = await self._consumer.read_with_pending(count=50, block_ms=3000)

                cycle += 1
                if not messages:
                    continue

                for stream, msg_id, envelope in messages:
                    try:
                        await self._process_message(stream, envelope)
                        await self._consumer.ack(stream, msg_id)
                    except Exception as exc:
                        log.error("Error processing %s:%s — %s", stream, msg_id, exc)
                        await self._consumer.nack(stream, msg_id)

                # Flush remaining batched events at end of poll cycle
                await self._flush_event_batches()
                await self._flush_alert_batches()

            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("Worker loop error: %s", exc)
                await asyncio.sleep(5)

    async def _process_message(self, stream: str, envelope: Dict[str, Any]) -> None:
        tenant_id = envelope.get("tenant_id", "default")
        data_str = envelope.get("data", "{}")
        data = json.loads(data_str) if isinstance(data_str, str) else data_str

        if stream == STREAM_RAW_EVENTS:
            await self._process_raw_event(tenant_id, data, envelope)
        elif stream == STREAM_NORMALIZED:
            await self._process_normalized_event(tenant_id, data, envelope)
        elif stream == STREAM_ENRICHED:
            await self._process_enriched_event(tenant_id, data, envelope)
        elif stream == STREAM_ALERTS:
            await self._process_alert(tenant_id, data, envelope)
        else:
            log.warning("Unknown stream %s — envelope keys: %s", stream, list(envelope.keys()))

    async def _flush_event_batches(self) -> None:
        if not self._raw_batch and not self._normalized_batch:
            return
        from cybernova.database.postgres.models import RawEvent, NormalizedEvent
        from cybernova.database.postgres.session import get_db_session
        async for db in get_db_session():
            try:
                for raw_data in self._raw_batch:
                    db.add(RawEvent(**raw_data))
                for norm_data in self._normalized_batch:
                    db.add(NormalizedEvent(**norm_data))
                await db.commit()
                log.debug("Batch flushed: %d raw + %d normalized",
                          len(self._raw_batch), len(self._normalized_batch))
            except Exception as db_err:
                log.error("Batch flush failed: %s", db_err)
                await db.rollback()
            finally:
                self._raw_batch.clear()
                self._normalized_batch.clear()
            break

    async def _flush_alert_batches(self) -> None:
        if not self._alert_batch:
            return
        from cybernova.database.postgres.models import Alert
        from cybernova.database.postgres.session import get_db_session
        async for db in get_db_session():
            try:
                for alert_data in self._alert_batch:
                    db.add(Alert(**alert_data))
                await db.commit()
                log.debug("Batch flushed: %d alerts", len(self._alert_batch))
            except Exception as db_err:
                log.error("Alert batch flush failed: %s", db_err)
                await db.rollback()
            finally:
                self._alert_batch.clear()
            break

    async def _process_raw_event(self, tenant_id: str, event: Dict[str, Any], envelope: Dict[str, Any]) -> None:
        from cybernova.ingestion.parsers.registry import ParserRegistry
        from cybernova.security.validation.validators import normalize_severity

        raw_event_id = envelope.get("_msg_id")
        try:
            registry = ParserRegistry()
            source_type = event.get("source_type", "api")
            parsed = registry.parse(source_type, event)
            normalized = {
                "id": raw_event_id,
                "tenant_id": tenant_id,
                "event_type": parsed.get("event_type", "unknown"),
                "severity": normalize_severity(parsed.get("severity", "info")),
                "source_ip": parsed.get("source_ip", ""),
                "dest_ip": parsed.get("dest_ip", ""),
                "source_port": parsed.get("source_port", 0),
                "dest_port": parsed.get("dest_port", 0),
                "protocol": parsed.get("protocol", ""),
                "user": parsed.get("user", ""),
                "device_id": parsed.get("device_id"),
                "message": parsed.get("message", ""),
                "raw_message": event.get("raw_log", ""),
                "metadata": parsed.get("metadata", {}),
                "timestamp": parsed.get("timestamp") or envelope.get("timestamp"),
            }
            
            # ACCUMULATE FOR BATCHED DB INSERT
            self._raw_batch.append({
                "id": raw_event_id,
                "tenant_id": tenant_id,
                "source": event.get("source", "host_agent"),
                "source_type": source_type,
                "payload": event,
            })
            self._normalized_batch.append({
                "id": raw_event_id,
                "tenant_id": tenant_id,
                "raw_event_id": raw_event_id,
                "event_type": normalized["event_type"],
                "severity": normalized["severity"],
                "source_ip": normalized["source_ip"],
                "dest_ip": normalized["dest_ip"],
                "message": normalized["message"],
                "timestamp": datetime.now(timezone.utc),
                "normalized_at": datetime.now(timezone.utc),
            })
            if len(self._raw_batch) >= self._batch_size:
                await self._flush_event_batches()
            
            await self.producer.produce_normalized_event(normalized, tenant_id, raw_event_id)
            log.info("Normalized event %s → type=%s", raw_event_id, normalized["event_type"])
        except Exception as exc:
            log.error("Normalization failed for %s: %s", raw_event_id, exc)
            await self.producer.send_to_dlq(STREAM_RAW_EVENTS, raw_event_id, str(exc), event)

    async def _process_normalized_event(self, tenant_id: str, event: Dict[str, Any], envelope: Dict[str, Any]) -> None:
        from cybernova.geoip import geoip_service
        from cybernova.network.threat_intel import threat_intel_service

        normalized_event_id = envelope.get("_msg_id") or event.get("id", str(uuid4()))
        try:
            enriched = event.copy()
            source_ip = enriched.get("source_ip", "")
            dest_ip = enriched.get("dest_ip", "")

            if source_ip:
                try:
                    enriched["geo"] = await asyncio.wait_for(geoip_service.lookup(source_ip), timeout=3.0)
                except asyncio.TimeoutError:
                    log.warning("GeoIP lookup timed out for %s in worker", source_ip)
                    enriched["geo"] = {}
                try:
                    enriched["threat_intel"] = await asyncio.wait_for(threat_intel_service.lookup_ip(source_ip), timeout=3.0)
                except asyncio.TimeoutError:
                    log.warning("Threat intel lookup timed out for %s in worker", source_ip)
                    enriched["threat_intel"] = {}
            if dest_ip:
                try:
                    enriched["geo_dest"] = await asyncio.wait_for(geoip_service.lookup(dest_ip), timeout=3.0)
                except asyncio.TimeoutError:
                    log.warning("GeoIP dest lookup timed out for %s in worker", dest_ip)
                    enriched["geo_dest"] = {}

            enriched["enriched_at"] = datetime.now(timezone.utc).isoformat()
            enriched["enrichment_sources"] = ["geoip", "threat_intel"]
            await self.producer.produce_enriched_event(enriched, tenant_id, normalized_event_id)
            log.debug("Enriched event %s", normalized_event_id)
        except Exception as exc:
            log.error("Enrichment failed for %s: %s", normalized_event_id, exc)
            await self.producer.send_to_dlq(STREAM_NORMALIZED, normalized_event_id, str(exc), event)

    async def _process_enriched_event(self, tenant_id: str, event: Dict[str, Any], envelope: Dict[str, Any]) -> None:
        """Detection stage — NON-BIASED: every event passes through ALL detection rules
        regardless of threat intel reputation. Threat intel only ADDS risk, never suppresses detection.
        A compromised clean IP must still be inspected for malicious behavior."""
        from cybernova.detection.rules_engine.rules import rule_engine
        from cybernova.response.notifications.notification_service import notification_service, SeverityLevel

        enriched_event_id = envelope.get("_msg_id") or event.get("id", str(uuid4()))
        threat_intel = event.get("threat_intel", {})
        risk_score = event.get("risk_score", 0)
        alert_reason = ""

        # ── NON-BIASED: threat intel only ADDS risk, never skips inspection ──
        # A previously-clean IP that is now compromised MUST still be detected.
        if threat_intel and not threat_intel.get("is_safe"):
            vt_malicious = threat_intel.get("is_malicious", False)
            abuse_confidence = threat_intel.get("abuse_confidence_score", 0)
            otx_pulses = threat_intel.get("otx_pulses", 0)
            if vt_malicious:
                alert_reason = "VirusTotal flagged as malicious"
                risk_score = max(risk_score, 80)
            elif abuse_confidence > 70:
                alert_reason = f"AbuseIPDB confidence: {abuse_confidence}%"
                risk_score = max(risk_score, 75)
            elif otx_pulses >= 3:
                alert_reason = f"OTX pulses: {otx_pulses}"
                risk_score = max(risk_score, 70)

        # ALL events pass through detection rules — no filtering, no bias
        try:
            triggered = rule_engine.evaluate(event)
            for rule in triggered:
                final_risk = max(rule.risk_score, risk_score) if risk_score > 0 else rule.risk_score
                
                severity = rule.severity
                if final_risk >= 85:
                    severity = "critical"
                elif final_risk >= 70:
                    severity = "high"
                elif final_risk >= 50:
                    severity = "medium"
                else:
                    severity = "low"
                
                alert = {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "rule_name": rule.name,
                    "severity": severity,
                    "risk_score": final_risk,
                    "description": f"{rule.description}: {event.get('message', '')[:200]}",
                    "event_id": enriched_event_id,
                    "source_ip": event.get("source_ip", ""),
                    "dest_ip": event.get("dest_ip", ""),
                    "user": event.get("user", ""),
                    "device_id": event.get("device_id", ""),
                    "event_type": event.get("event_type", ""),
                    "status": "new",
                    "threat_intel": threat_intel,
                    "geo": event.get("geo", {}),
                    "enrichment_sources": event.get("enrichment_sources", []),
                    "raw_event": event,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "alert_reason": alert_reason,
                }
                
                extra_data = {
                    "threat_intel": threat_intel,
                    "geo": event.get("geo", {}),
                    "enrichment_sources": event.get("enrichment_sources", []),
                    "raw_event": {k: v for k, v in event.items() if k not in ("geo", "threat_intel")},
                    "alert_reason": alert_reason,
                    "source_ip": event.get("source_ip", ""),
                    "dest_ip": event.get("dest_ip", ""),
                    "user": event.get("user", ""),
                    "event_type": event.get("event_type", ""),
                }
                self._alert_batch.append({
                    "id": alert["id"],
                    "tenant_id": tenant_id,
                    "rule_name": rule.name,
                    "severity": severity,
                    "risk_score": final_risk,
                    "description": alert["description"],
                    "status": "new",
                    "extra_data": extra_data,
                })
                if len(self._alert_batch) >= self._batch_size:
                    await self._flush_alert_batches()
                
                level = notification_service.get_severity_level(severity)
                if level in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
                    await notification_service.send_notification(alert)
                
                if level == SeverityLevel.CRITICAL:
                    await notification_service.execute_auto_action(alert)
                
                await self.producer.produce_alert(alert, tenant_id)
                log.info("Alert created: %s [%s]", rule.name, alert["id"])

            stateful = rule_engine.evaluate_stateful(event)
            for result in stateful:
                stateful_risk = result.get("risk_score", 60.0)
                
                stateful_severity = result.get("severity", "medium")
                if stateful_risk >= 85:
                    stateful_severity = "critical"
                elif stateful_risk >= 70:
                    stateful_severity = "high"
                elif stateful_risk >= 50:
                    stateful_severity = "medium"
                else:
                    stateful_severity = "low"
                
                alert = {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "rule_name": result.get("threat_type", "stateful"),
                    "severity": stateful_severity,
                    "risk_score": stateful_risk,
                    "description": result.get("message", ""),
                    "event_id": enriched_event_id,
                    "source_ip": result.get("source_ip", event.get("source_ip", "")),
                    "dest_ip": event.get("dest_ip", ""),
                    "user": event.get("user", ""),
                    "device_id": result.get("device_id", event.get("device_id", "")),
                    "event_type": event.get("event_type", ""),
                    "status": "new",
                    "threat_intel": threat_intel,
                    "geo": event.get("geo", {}),
                    "raw_event": event,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "alert_reason": "Stateful detection",
                }
                
                extra_data = {
                    "threat_intel": threat_intel,
                    "geo": event.get("geo", {}),
                    "enrichment_sources": event.get("enrichment_sources", []),
                    "raw_event": {k: v for k, v in event.items() if k not in ("geo", "threat_intel")},
                    "alert_reason": "Stateful detection",
                    "source_ip": result.get("source_ip", event.get("source_ip", "")),
                    "dest_ip": event.get("dest_ip", ""),
                    "user": event.get("user", ""),
                    "event_type": event.get("event_type", ""),
                }
                self._alert_batch.append({
                    "id": alert["id"],
                    "tenant_id": tenant_id,
                    "rule_name": result.get("threat_type", "stateful"),
                    "severity": stateful_severity,
                    "risk_score": stateful_risk,
                    "description": result.get("message", ""),
                    "status": "new",
                    "extra_data": extra_data,
                })
                if len(self._alert_batch) >= self._batch_size:
                    await self._flush_alert_batches()
                
                level = notification_service.get_severity_level(stateful_severity)
                if level in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
                    await notification_service.send_notification(alert)
                
                if level == SeverityLevel.CRITICAL:
                    await notification_service.execute_auto_action(alert)
                
                await self.producer.produce_alert(alert, tenant_id)
        except Exception as exc:
            log.error("Detection failed for %s: %s", enriched_event_id, exc)
            await self.producer.send_to_dlq(STREAM_ENRICHED, enriched_event_id, str(exc), event)

    async def _save_alert_to_db(self, alert: Dict[str, Any]) -> Optional[str]:
        """Persist an alert dict directly to the alerts table.
        Returns the alert id on success, None on failure.
        Uses upsert (merge) to handle re-processed messages from stream."""
        from cybernova.database.postgres.models import Alert
        from cybernova.database.postgres.session import get_db_session
        async for db in get_db_session():
            try:
                alert_id = alert.get("id", str(uuid4()))

                # Check if already exists (prevents PK violation on re-process)
                existing = await db.get(Alert, alert_id)
                if existing:
                    log.debug("Alert already exists in DB: %s", alert_id)
                    return alert_id

                now = datetime.now(timezone.utc)
                # alert dict from stream has threat_intel/geo/raw_event at top level
                # reconstruct extra_data from those top-level fields
                extra_data = alert.get("extra_data") or {
                    "threat_intel": alert.get("threat_intel", {}),
                    "geo": alert.get("geo", {}),
                    "enrichment_sources": alert.get("enrichment_sources", []),
                    "alert_reason": alert.get("alert_reason", ""),
                }

                record = Alert(
                    id=alert_id,
                    tenant_id=alert.get("tenant_id", "default"),
                    rule_name=alert.get("rule_name", "unknown"),
                    severity=alert.get("severity", "medium"),
                    risk_score=alert.get("risk_score", 0.0),
                    description=alert.get("description", ""),
                    status=alert.get("status", "new"),
                    source_ip=alert.get("source_ip", ""),
                    dest_ip=alert.get("dest_ip", ""),
                    user=alert.get("user", ""),
                    event_type=alert.get("event_type", ""),
                    event_id=alert.get("event_id", ""),
                    device_id=alert.get("device_id", ""),
                    extra_data=extra_data,
                    raw_event=alert.get("raw_event", None),
                    created_at=now,
                    updated_at=now,
                )
                db.add(record)
                await db.commit()
                log.debug("Alert saved to DB: %s [%s]", alert.get("rule_name"), alert_id)
                return alert_id
            except Exception as exc:
                log.error("Failed to save alert to DB: %s", exc)
                await db.rollback()
                return None

    async def _process_alert(self, tenant_id: str, alert: Dict[str, Any], envelope: Dict[str, Any]) -> None:
        from cybernova.detection.correlation_engine.correlation_service import correlation_service
        from cybernova.response.policy_engine.playbooks import match_playbook
        from cybernova.response.automation.engine import playbook_engine

        try:
            # ── Persist alert to DB FIRST (bypasses detection worker's broken batch flush) ──
            alert_id = await self._save_alert_to_db(alert)
            if alert_id:
                alert["id"] = alert_id

            # ── Correlate alerts → incidents ──
            incidents = await correlation_service.correlate_alerts([alert], tenant_id)
            for incident in incidents:
                # incident may be an ORM object or dict; normalize to dict for produce
                if hasattr(incident, "id"):
                    incident_dict = {
                        "id": incident.id,
                        "tenant_id": getattr(incident, "tenant_id", tenant_id),
                        "title": getattr(incident, "title", ""),
                        "severity": getattr(incident, "severity", "medium"),
                        "status": getattr(incident, "status", "new"),
                        "risk_score": getattr(incident, "risk_score", 0.0),
                        "description": getattr(incident, "description", ""),
                        "created_at": getattr(incident, "created_at", datetime.now(timezone.utc)).isoformat() if hasattr(getattr(incident, "created_at", None), "isoformat") else str(getattr(incident, "created_at", "")),
                    }
                else:
                    incident_dict = incident
                await self.producer.produce_incident(incident_dict, tenant_id)
                log.info("Incident created: %s", incident_dict.get("id"))

            context = {
                "alert": alert,
                "tenant_id": tenant_id,
            }
            execution_ids = await playbook_engine.match_and_trigger(context)
            if execution_ids:
                log.info("Playbook engine triggered %d executions for alert %s", len(execution_ids), alert.get("id"))

            playbooks = match_playbook({
                "severity": alert.get("severity"),
                "risk_score": alert.get("risk_score", 0),
                "rule_name": alert.get("rule_name", ""),
            })
            for playbook in playbooks:
                for action_def in playbook.get("actions", []):
                    action = {
                        "id": str(uuid4()),
                        "tenant_id": tenant_id,
                        "alert_id": alert.get("id"),
                        "playbook_id": playbook.get("id"),
                        "device_id": alert.get("device_id", ""),
                        "action_type": action_def.get("type", "webhook"),
                        "parameters": action_def.get("params", {}),
                        "webhook_url": action_def.get("webhook_url"),
                        "payload": {
                            "alert": alert,
                            "playbook": playbook.get("name"),
                            "action_type": action_def.get("type"),
                        },
                        "status": "pending",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                    await self.producer.produce_response_action(action, tenant_id)
        except Exception as exc:
            log.error("Correlation/SOAR failed for alert %s: %s", alert.get("id"), exc)
            await self.producer.send_to_dlq(STREAM_ALERTS, alert.get("id", ""), str(exc), alert)


async def main() -> None:
    stage = None
    if len(sys.argv) > 1:
        stage = sys.argv[1]

    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )

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

    worker = PipelineWorker(redis, stage=stage)

    loop = asyncio.get_event_loop()

    async def shutdown():
        await worker.stop()
        await redis.close()

    # Signals not supported on Windows (add_signal_handler raises NotImplementedError)
    if sys.platform != "win32":
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown()))
    else:
        log.info("Signal handlers skipped (Windows)")

    await worker.start()


if __name__ == "__main__":
    asyncio.run(main())
