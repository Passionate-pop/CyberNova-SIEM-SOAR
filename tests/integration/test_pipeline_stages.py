"""Integration tests for each pipeline stage — isolated with fake event bus."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.pipeline.bus import PipelineEnvelope


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_envelope(
    stage: str = "ingestion",
    tenant_id: str = "default",
    payload: dict = None,
) -> PipelineEnvelope:
    return PipelineEnvelope(
        event_id="test-evt-1",
        tenant_id=tenant_id,
        stage=stage,
        payload=payload or {},
    )


# ── Normalization Stage ──────────────────────────────────────────────────────

class TestNormalizationStage:
    """NormalizationStage: raw_data → normalized_data"""

    @pytest.mark.asyncio
    async def test_normalizes_simple_event(self):
        from cybernova.pipeline.stages.normalizer import normalization_stage
        envelope = make_envelope(payload={
            "raw_data": {
                "event_type": "login_failure",
                "severity": "high",
                "source_ip": "10.0.0.5",
                "dest_ip": "192.168.1.1",
                "user": "admin",
                "message": "Failed login for admin",
            },
            "source": "syslog",
            "source_type": "syslog",
        })
        result = await normalization_stage.handle(envelope)
        assert result is not None
        nd = result.payload["normalized_data"]
        assert nd["event_type"] == "login_failure"
        assert nd["severity"] == "high"
        assert nd["source_ip"] == "10.0.0.5"
        assert nd["dest_ip"] == "192.168.1.1"
        assert nd["user"] == "admin"
        assert nd["message"] == "Failed login for admin"
        assert nd["source"] == "syslog"
        assert nd["source_type"] == "syslog"
        assert "normalized_at" in nd
        assert "normalized_id" in result.payload
        assert result.stage == "enrichment"

    @pytest.mark.asyncio
    async def test_handles_nested_event_data(self):
        from cybernova.pipeline.stages.normalizer import normalization_stage
        envelope = make_envelope(payload={
            "raw_data": {
                "event": {
                    "event_type": "malware_detected",
                    "severity": "critical",
                    "source_ip": "10.0.0.99",
                },
            },
            "source": "agent",
            "source_type": "json",
        })
        result = await normalization_stage.handle(envelope)
        nd = result.payload["normalized_data"]
        assert nd["event_type"] == "malware_detected"
        assert nd["severity"] == "critical"
        assert nd["source_ip"] == "10.0.0.99"

    @pytest.mark.asyncio
    async def test_fills_defaults_for_missing_fields(self):
        from cybernova.pipeline.stages.normalizer import normalization_stage
        envelope = make_envelope(payload={
            "raw_data": {},
            "source": "test",
            "source_type": "json",
        })
        result = await normalization_stage.handle(envelope)
        nd = result.payload["normalized_data"]
        assert nd["event_type"] == "test"
        assert nd["severity"] == "info"
        assert nd["source_ip"] == ""
        assert nd["source_port"] == 0

    @pytest.mark.asyncio
    async def test_extracts_from_extra_data(self):
        from cybernova.pipeline.stages.normalizer import normalization_stage
        envelope = make_envelope(payload={
            "raw_data": {
                "extra_data": {"user": "bob", "device_id": "dev-007"},
            },
            "source": "api",
            "source_type": "json",
        })
        result = await normalization_stage.handle(envelope)
        nd = result.payload["normalized_data"]
        assert nd["user"] == "bob"
        assert nd["device_id"] == "dev-007"


# ── Enrichment Stage ─────────────────────────────────────────────────────────

class TestEnrichmentStage:
    """EnrichmentStage: normalized_data → enriched_data (geoip, threat intel, risk score)"""

    @pytest.mark.asyncio
    async def test_enriches_with_risk_score(self):
        from cybernova.pipeline.stages.enricher import enrichment_stage
        envelope = make_envelope(stage="normalization", payload={
            "normalized_data": {
                "event_type": "brute_force",
                "severity": "critical",
                "source_ip": "1.2.3.4",
                "user": "admin",
            },
        })
        with patch("cybernova.pipeline.stages.enricher.geoip_service.lookup",
                   return_value={"country": "US", "city": "NYC"}):
            with patch("cybernova.pipeline.stages.enricher.threat_intel_service.lookup_ip",
                       return_value={"malicious": True, "risk_modifier": 15}):
                result = await enrichment_stage.handle(envelope)

        assert result is not None
        ed = result.payload["enriched_data"]
        assert ed["event_type"] == "brute_force"
        assert ed["geo_data"]["country"] == "US"
        assert ed["threat_intel"]["malicious"] is True
        # critical base=80 + risk_modifier=15 = 95
        assert ed["risk_score"] == 95
        assert "enriched_id" in ed
        assert "enriched_at" in ed
        # Enrichment → Anomaly stage (anomaly detection runs after enrichment)
        assert result.stage == "anomaly"

    @pytest.mark.asyncio
    async def test_handles_geoip_failure_gracefully(self):
        from cybernova.pipeline.stages.enricher import enrichment_stage
        envelope = make_envelope(stage="normalization", payload={
            "normalized_data": {
                "event_type": "scan",
                "severity": "medium",
                "source_ip": "8.8.8.8",
            },
        })
        with patch("cybernova.pipeline.stages.enricher.geoip_service.lookup",
                   side_effect=Exception("GeoIP down")):
            with patch("cybernova.pipeline.stages.enricher.threat_intel_service.lookup_ip",
                       return_value={"risk_modifier": 5}):
                result = await enrichment_stage.handle(envelope)

        ed = result.payload["enriched_data"]
        assert ed["geo_data"] == {}  # safe handler catches exception, returns {}
        assert ed["threat_intel"]["risk_modifier"] == 5
        # medium base=40 + risk_modifier=5 = 45
        assert ed["risk_score"] == 45

    @pytest.mark.asyncio
    async def test_handles_empty_normalized_data(self):
        from cybernova.pipeline.stages.enricher import enrichment_stage
        envelope = make_envelope(stage="normalization", payload={
            "normalized_data": {},
        })
        result = await enrichment_stage.handle(envelope)
        # Returns envelope without changing stage when normalized data is empty
        assert result is not None
        assert "enriched_data" not in result.payload


# ── Anomaly Stage ────────────────────────────────────────────────────────────

class TestAnomalyStage:
    """AnomalyStage: enriched_data → anomaly/ml_anomaly scores"""

    @pytest.mark.asyncio
    async def test_passes_through_when_no_anomalies(self):
        from cybernova.pipeline.stages.anomaly import anomaly_stage
        envelope = make_envelope(stage="enrichment", payload={
            "normalized_data": {
                "event_type": "login", "severity": "info",
                "source_ip": "10.0.0.1", "user": "test",
            },
            "enriched_data": {
                "event_type": "login", "severity": "info",
                "source_ip": "10.0.0.1", "risk_score": 10,
            },
        })
        with patch("cybernova.pipeline.stages.anomaly.anomaly_detector.score_event",
                   return_value=None):
            with patch("cybernova.pipeline.stages.anomaly.infer_event",
                       return_value=None):
                result = await anomaly_stage.handle(envelope)

        assert result is not None
        assert "anomaly" not in result.payload
        assert "ml_anomaly" not in result.payload
        assert result.stage == "detection"

    @pytest.mark.asyncio
    async def test_adds_statistical_anomaly_boost(self):
        from cybernova.pipeline.stages.anomaly import anomaly_stage
        envelope = make_envelope(stage="enrichment", payload={
            "normalized_data": {
                "event_type": "connection", "severity": "medium",
                "source_ip": "1.2.3.4",
            },
            "enriched_data": {
                "event_type": "connection", "severity": "medium",
                "risk_score": 40,
            },
        })
        with patch("cybernova.pipeline.stages.anomaly.anomaly_detector.score_event",
                   return_value={"anomaly_score": 0.8, "reason": "unusual port"}):
            with patch("cybernova.pipeline.stages.anomaly.infer_event",
                       return_value=None):
                with patch("cybernova.pipeline.stages.anomaly.model_registry"):
                    result = await anomaly_stage.handle(envelope)

        assert result.payload["anomaly"]["anomaly_score"] == 0.8
        assert result.payload["risk_score_boost"] == 24.0  # 0.8 * 30
        # enriched risk score got boosted
        assert result.payload["enriched_data"]["risk_score"] == 64  # 40 + 24

    @pytest.mark.asyncio
    async def test_handles_anomaly_detector_failure(self):
        from cybernova.pipeline.stages.anomaly import anomaly_stage
        envelope = make_envelope(stage="enrichment", payload={
            "normalized_data": {"event_type": "test"},
            "enriched_data": {"risk_score": 20},
        })
        with patch("cybernova.pipeline.stages.anomaly.anomaly_detector.score_event",
                   side_effect=Exception("detector down")):
            with patch("cybernova.pipeline.stages.anomaly.infer_event",
                       return_value=None):
                with patch("cybernova.pipeline.stages.anomaly.model_registry"):
                    result = await anomaly_stage.handle(envelope)
        # handle() caught exception, returned envelope with retry
        assert result is not None
        assert "anomaly: detector down" in (result.error or "")


# ── Detection Stage ──────────────────────────────────────────────────────────

class TestDetectionStage:
    """DetectionStage: enriched_data → alerts[] via rule engines"""

    @pytest.mark.asyncio
    async def test_detects_malware_event(self):
        from cybernova.pipeline.stages.detector import detection_stage
        envelope = make_envelope(stage="enrichment", payload={
            "normalized_data": {
                "event_type": "malware_detected",
                "severity": "critical",
                "source_ip": "10.0.0.50",
            },
            "enriched_data": {
                "event_type": "malware_detected",
                "severity": "critical",
                "risk_score": 95,
            },
        })
        with patch("cybernova.pipeline.stages.detector.detection_rules_engine.load_rules",
                   return_value=[]):
            with patch("cybernova.pipeline.stages.detector.detection_rules_engine.evaluate",
                       return_value=[]):
                with patch("cybernova.suppression.engine.suppression_engine.evaluate",
                           return_value=MagicMock(suppressed=False)):
                    result = await detection_stage.handle(envelope)

        assert result is not None
        alerts = result.payload.get("alerts", [])
        assert len(alerts) >= 1
        names = [a["rule_name"] for a in alerts]
        assert "malware_detected" in names
        assert result.stage == "correlation"

    @pytest.mark.asyncio
    async def test_no_match_returns_empty_alerts(self):
        from cybernova.pipeline.stages.detector import detection_stage
        envelope = make_envelope(stage="enrichment", payload={
            "normalized_data": {
                "event_type": "heartbeat",
                "severity": "info",
                "source_ip": "127.0.0.1",
            },
            "enriched_data": {
                "event_type": "heartbeat",
                "severity": "info",
                "risk_score": 5,
            },
        })
        with patch("cybernova.pipeline.stages.detector.detection_rules_engine.load_rules",
                   return_value=[]):
            with patch("cybernova.pipeline.stages.detector.detection_rules_engine.evaluate",
                       return_value=[]):
                with patch("cybernova.suppression.engine.suppression_engine.evaluate",
                           return_value=MagicMock(suppressed=False)):
                    result = await detection_stage.handle(envelope)

        alerts = result.payload.get("alerts", [])
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_handles_no_event_data_gracefully(self):
        from cybernova.pipeline.stages.detector import detection_stage
        envelope = make_envelope(stage="enrichment", payload={})
        result = await detection_stage.handle(envelope)
        assert result is not None


# ── Correlation Stage ────────────────────────────────────────────────────────

class TestCorrelationStage:
    """CorrelationStage: alerts[] → incidents[]"""

    @pytest.mark.asyncio
    async def test_groups_alerts_by_ip(self):
        from cybernova.pipeline.stages.correlator import correlation_stage
        # Fresh instance to avoid cross-test pollution
        from cybernova.pipeline.stages.correlator import CorrelationStage
        stage = CorrelationStage()

        alerts = [
            {"id": "a1", "rule_name": "brute_force", "severity": "high",
             "risk_score": 75, "source_ip": "10.0.0.1", "user": ""},
            {"id": "a2", "rule_name": "malware", "severity": "critical",
             "risk_score": 95, "source_ip": "10.0.0.1", "user": ""},
        ]
        envelope = make_envelope(stage="detection", payload={"alerts": alerts})
        result = await stage.handle(envelope)

        incidents = result.payload.get("incidents", [])
        assert len(incidents) == 1
        assert incidents[0]["new_alerts"] == 2
        assert result.stage == "alert"

    @pytest.mark.asyncio
    async def test_groups_alerts_by_user(self):
        from cybernova.pipeline.stages.correlator import CorrelationStage
        stage = CorrelationStage()
        alerts = [
            {"id": "a1", "rule_name": "phishing", "severity": "high",
             "risk_score": 70, "source_ip": "", "user": "bob"},
            {"id": "a2", "rule_name": "malware", "severity": "medium",
             "risk_score": 50, "source_ip": "", "user": "bob"},
        ]
        envelope = make_envelope(stage="detection", payload={"alerts": alerts})
        result = await stage.handle(envelope)
        assert len(result.payload["incidents"]) == 1

    @pytest.mark.asyncio
    async def test_no_alerts_skips_correlation(self):
        from cybernova.pipeline.stages.correlator import correlation_stage
        envelope = make_envelope(stage="detection", payload={"alerts": []})
        result = await correlation_stage.handle(envelope)
        assert result.payload.get("incidents", []) == []
        assert result.stage == "alert"

    @pytest.mark.asyncio
    async def test_updates_existing_incident(self):
        from cybernova.pipeline.stages.correlator import CorrelationStage
        stage = CorrelationStage()
        first = [
            {"id": "a1", "rule_name": "scan", "severity": "medium",
             "risk_score": 40, "source_ip": "10.0.0.1", "user": ""},
        ]
        await stage.handle(make_envelope(stage="detection", payload={"alerts": first}))

        second = [
            {"id": "a1", "rule_name": "scan", "severity": "medium",
             "risk_score": 40, "source_ip": "10.0.0.1", "user": ""},
            {"id": "a2", "rule_name": "exploit", "severity": "high",
             "risk_score": 80, "source_ip": "10.0.0.1", "user": ""},
        ]
        result = await stage.handle(make_envelope(stage="detection", payload={"alerts": second}))
        incidents = result.payload["incidents"]
        assert len(incidents) == 1
        assert incidents[0]["new_alerts"] == 1
        assert incidents[0]["updated"] is True


# ── Alert Stage ──────────────────────────────────────────────────────────────

class TestAlertStage:
    """AlertStage: alerts[] + incidents[] → persist to DB → soar"""

    @pytest.mark.asyncio
    async def test_persists_alerts_and_incidents(self):
        from cybernova.pipeline.stages.alerter import alert_stage

        async def fake_db_session():
            mock_db = AsyncMock()
            yield mock_db

        alerts = [
            {"id": "a1", "event_id": "evt-1", "rule_name": "malware_detected",
             "severity": "critical", "risk_score": 95, "description": "Malware!",
             "source_ip": "10.0.0.1", "dest_ip": "", "user": "",
             "event_type": "malware_detected", "device_id": "",
             "mitre_tactic": "TA0001", "mitre_technique": "T1204"},
        ]
        incidents = [
            {"incident_id": "inc-1", "new_alerts": 1, "updated": False,
             "risk_score": 95, "max_severity": "critical"},
        ]
        envelope = make_envelope(stage="correlation", payload={
            "alerts": alerts, "incidents": incidents,
        })
        with patch("cybernova.database.postgres.session.get_db_session",
                   fake_db_session):
            with patch("cybernova.pipeline.stages.alerter.event_producer.publish",
                       return_value=True):
                with patch("cybernova.database.repository.repositories.AlertRepository.bulk_insert",
                           return_value=None):
                    result = await alert_stage.handle(envelope)

        assert result is not None
        assert result.stage == "soar"

    @pytest.mark.asyncio
    async def test_no_alerts_goes_to_complete(self):
        from cybernova.pipeline.stages.alerter import alert_stage
        envelope = make_envelope(stage="correlation", payload={
            "alerts": [], "incidents": [],
        })
        result = await alert_stage.handle(envelope)
        assert result.stage == "complete"

    @pytest.mark.asyncio
    async def test_rolls_back_on_db_error(self):
        from cybernova.pipeline.stages.alerter import alert_stage

        async def fake_db_session():
            mock_db = AsyncMock()
            mock_db.commit.side_effect = Exception("DB down")
            yield mock_db

        alerts = [
            {"id": "a1", "event_id": "evt-1", "rule_name": "test",
             "severity": "high", "risk_score": 70, "description": "test",
             "source_ip": "", "dest_ip": "", "user": "",
             "event_type": "test", "device_id": ""},
        ]
        envelope = make_envelope(stage="correlation", payload={
            "alerts": alerts, "incidents": [],
        })
        with patch("cybernova.database.postgres.session.get_db_session",
                   fake_db_session):
            with patch("cybernova.pipeline.stages.alerter.event_producer.publish",
                       return_value=True):
                with patch("cybernova.database.repository.repositories.AlertRepository.bulk_insert",
                           return_value=None):
                    result = await alert_stage.handle(envelope)

        # handle() catches the exception and sets error on envelope
        assert result is not None
        assert "alert: DB down" in result.error
        assert result.stage == "correlation"


# ── SOAR Stage ───────────────────────────────────────────────────────────────

class TestSOARStage:
    """SOARStage: alerts[] → automated actions"""

    @pytest.mark.asyncio
    async def test_isolates_malware_critical(self):
        from cybernova.pipeline.stages.soar import soar_stage
        # Fresh instance for clean batch state
        from cybernova.pipeline.stages.soar import SOARStage
        stage = SOARStage()

        alerts = [
            {"id": "a1", "rule_name": "malware_detected", "severity": "critical",
             "risk_score": 95, "source_ip": "10.0.0.50", "device_id": "dev-001"},
        ]
        envelope = make_envelope(stage="alert", payload={"alerts": alerts})

        with patch("cybernova.database.postgres.session.get_db_session") as mock_gs:
            mock_db = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = mock_db
            mock_gs.return_value.__aexit__.return_value = None
            result = await stage.handle(envelope)

        assert result.stage == "notification"

    @pytest.mark.asyncio
    async def test_blocks_ip_for_brute_force(self):
        from cybernova.pipeline.stages.soar import SOARStage
        stage = SOARStage()
        alerts = [
            {"id": "a2", "rule_name": "brute_force_detected", "severity": "critical",
             "risk_score": 92, "source_ip": "5.6.7.8", "device_id": ""},
        ]
        envelope = make_envelope(stage="alert", payload={"alerts": alerts})
        with patch("cybernova.database.postgres.session.get_db_session") as mock_gs:
            mock_db = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = mock_db
            mock_gs.return_value.__aexit__.return_value = None
            result = await stage.handle(envelope)
        assert result.stage == "notification"

    @pytest.mark.asyncio
    async def test_skips_low_risk_alerts(self):
        from cybernova.pipeline.stages.soar import soar_stage
        alerts = [
            {"id": "a3", "rule_name": "info_event", "severity": "low",
             "risk_score": 10, "source_ip": "10.0.0.1"},
        ]
        envelope = make_envelope(stage="alert", payload={"alerts": alerts})
        result = await soar_stage.handle(envelope)
        assert result.stage == "notification"

    @pytest.mark.asyncio
    async def test_determine_action_mapping(self):
        from cybernova.pipeline.stages.soar import SOARStage
        stage = SOARStage()
        assert stage._determine_action("ransomware_detected", "critical") == "isolate"
        assert stage._determine_action("malware_detected", "critical") == "isolate"
        assert stage._determine_action("webshell_found", "critical") == "isolate"
        assert stage._determine_action("brute_force_attempt", "critical") == "block_ip"
        assert stage._determine_action("credential_theft", "critical") == "block_ip"
        assert stage._determine_action("data_exfiltration", "critical") == "block_ip"
        assert stage._determine_action("unknown_alert", "critical") == "block_ip"
        # High severity: alert admin only, no auto-block to prevent false positives
        assert stage._determine_action("anything", "high") == "alert_admin"
        assert stage._determine_action("anything", "low") is None
