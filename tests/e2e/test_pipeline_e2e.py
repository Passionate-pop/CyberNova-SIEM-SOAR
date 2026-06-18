"""End-to-end pipeline test: syslog → normalize → enrich → detect → correlate → alert → SOAR → read from DB."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybernova.database.repository.repositories import AlertRepository
from cybernova.pipeline.bus import PipelineEnvelope


class _CompatSession:
    """Wraps an AsyncSession to translate PostgreSQL-specific SQL to SQLite-compatible form.

    Handles:
      - NOW()        → CURRENT_TIMESTAMP
      - gen_random_uuid()::text  → fixed literal
      - ON CONFLICT (id) DO NOTHING  → removed (SQLite <3.35 compat)
    """

    def __init__(self, session: AsyncSession):
        self._session = session

    async def execute(self, statement, params=None):
        sql = statement.text if hasattr(statement, "text") else str(statement)
        sql = sql.replace("NOW()", "CURRENT_TIMESTAMP")
        sql = sql.replace("gen_random_uuid()::text", "'e2e-uuid'")
        sql = sql.replace("ON CONFLICT (id) DO NOTHING", "")
        return await self._session.execute(sa_text(sql), params)

    async def commit(self):
        await self._session.commit()

    async def rollback(self):
        await self._session.rollback()

    def add(self, obj):
        self._session.add(obj)

    async def flush(self):
        await self._session.flush()


async def _sqlite_bulk_insert(self, mappings):
    """SQLite-compatible bulk_insert for AlertRepository."""
    if not mappings:
        return
    import json as _json
    for m in mappings:
        if "tenant_id" not in m:
            m["tenant_id"] = self.tenant_id
        for k, v in m.items():
            if isinstance(v, dict):
                m[k] = _json.dumps(v)
    cols = list(mappings[0].keys())
    col_list = ", ".join(cols)
    param_list = ", ".join(f":{c}" for c in cols)
    stmt = sa_text(f"INSERT OR IGNORE INTO alerts ({col_list}) VALUES ({param_list})")
    await self.db.execute(stmt, mappings)
    await self.db.flush()


def make_mock_rule(name, severity, risk_score, description, mitre_tactic=None, mitre_technique=None):
    r = MagicMock()
    r.name = name
    r.severity = severity
    r.risk_score = risk_score
    r.description = description
    r.mitre_tactic = mitre_tactic
    r.mitre_technique = mitre_technique
    return r


@pytest.mark.asyncio
async def test_e2e_syslog_through_pipeline(db_engine):
    """Syslog event flows through all 7 stages. Alert is read from DB at end."""

    # ── 0. Clean stale data from previous test runs ─────────────────────
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession)
    async with session_factory() as cleanup_db:
        await cleanup_db.execute(sa_text("DELETE FROM alerts WHERE tenant_id = :tid"), {"tid": "tenant-acme"})
        await cleanup_db.execute(sa_text("DELETE FROM incidents WHERE tenant_id = :tid"), {"tid": "tenant-acme"})
        await cleanup_db.commit()

    # ── 1. Create envelope simulating syslog ingestion ──────────────────────
    envelope = PipelineEnvelope(
        event_id="e2e-syslog-001",
        tenant_id="tenant-acme",
        stage="normalization",
        payload={
            "raw_data": {
                "event_type": "malware_detected",
                "severity": "critical",
                "source_ip": "10.0.0.50",
                "dest_ip": "192.168.1.1",
                "user": "admin",
                "message": "Malware: Trojan.Win32.Downloader on dev-001",
                "device_id": "dev-001",
            },
            "source": "syslog",
            "source_type": "syslog",
        },
    )

    # ── 2. Set up a real SQLite session for persistence verification ────────
    async with session_factory() as raw_db:
        db = _CompatSession(raw_db)

        async def _fake_db_session():
            yield db

        # Start long-lived patches (get_db_session, bulk_insert, event_producer)
        _patcher_db = patch("cybernova.database.postgres.session.get_db_session", _fake_db_session)
        _patcher_bulk = patch.object(AlertRepository, "bulk_insert", _sqlite_bulk_insert)
        _patcher_evt = patch("cybernova.pipeline.stages.alerter.event_producer.publish", return_value=True)
        _patcher_db.start()
        _patcher_bulk.start()
        _patcher_evt.start()

        try:
            # ── Stage 1: Normalization ──────────────────────────────────────
            from cybernova.pipeline.stages.normalizer import normalization_stage

            envelope = await normalization_stage.handle(envelope)
            assert envelope.stage == "enrichment"
            nd = envelope.payload["normalized_data"]
            assert nd["event_type"] == "malware_detected"
            assert nd["severity"] == "critical"
            assert nd["source_ip"] == "10.0.0.50"
            assert nd["user"] == "admin"
            assert nd["source"] == "syslog"
            assert nd["source_type"] == "syslog"
            assert "normalized_id" in envelope.payload

            # ── Stage 2: Enrichment ─────────────────────────────────────────
            from cybernova.pipeline.stages.enricher import enrichment_stage

            with (
                patch("cybernova.pipeline.stages.enricher.geoip_service.lookup",
                      return_value={"country": "US", "city": "NYC", "org": "TestCorp"}),
                patch("cybernova.pipeline.stages.enricher.threat_intel_service.lookup_ip",
                      return_value={"malicious": True, "risk_modifier": 15}),
            ):
                envelope = await enrichment_stage.handle(envelope)

            assert envelope.stage == "anomaly"
            ed = envelope.payload["enriched_data"]
            assert ed["risk_score"] == 95  # critical(80) + risk_modifier(15)
            assert ed["geo_data"]["country"] == "US"
            assert ed["geo_data"]["city"] == "NYC"
            assert ed["threat_intel"]["malicious"] is True
            assert "enriched_id" in ed

            # ── Stage 3: Detection ──────────────────────────────────────────
            from cybernova.pipeline.stages.detector import detection_stage

            mock_malware_rule = make_mock_rule(
                "malware_detected", "critical", 95.0,
                "Malware signature matched", "TA0001", "T1204",
            )

            with (
                patch("cybernova.pipeline.stages.detector.rule_engine.evaluate",
                      return_value=[mock_malware_rule]),
                patch("cybernova.pipeline.stages.detector.rule_engine.evaluate_stateful",
                      return_value=[]),
                patch("cybernova.pipeline.stages.detector.detection_rules_engine.load_rules"),
                patch("cybernova.pipeline.stages.detector.detection_rules_engine.evaluate",
                      return_value=[]),
                patch("cybernova.suppression.engine.suppression_engine.evaluate",
                      return_value=MagicMock(suppressed=False)),
            ):
                envelope = await detection_stage.handle(envelope)

            assert envelope.stage == "correlation"
            alerts = envelope.payload["alerts"]
            assert len(alerts) >= 1
            malware_alerts = [a for a in alerts if a["rule_name"] == "malware_detected"]
            assert len(malware_alerts) >= 1
            ma = malware_alerts[0]
            assert ma["severity"] == "critical"
            assert ma["risk_score"] == 95.0
            assert ma["source_ip"] == "10.0.0.50"

            # ── Stage 4: Correlation ────────────────────────────────────────
            from cybernova.pipeline.stages.correlator import CorrelationStage

            correlator = CorrelationStage()
            envelope = await correlator.handle(envelope)

            assert envelope.stage == "alert"
            incidents = envelope.payload["incidents"]
            assert len(incidents) >= 1
            assert incidents[0]["new_alerts"] >= 1

            # ── Stage 5: Alert (persist to DB) ──────────────────────────────
            from cybernova.pipeline.stages.alerter import alert_stage

            envelope = await alert_stage.handle(envelope)
            assert envelope.stage == "soar"

            # ── Stage 6: SOAR ───────────────────────────────────────────────
            from cybernova.pipeline.stages.soar import SOARStage

            soar = SOARStage()
            envelope = await soar.handle(envelope)
            assert envelope.stage == "notification"

        finally:
            _patcher_evt.stop()
            _patcher_bulk.stop()
            _patcher_db.stop()

        # ── 3. Read alert from DB ───────────────────────────────────────────
        result = await raw_db.execute(
            sa_text("""
                SELECT id, tenant_id, event_id, rule_name, severity, risk_score,
                       source_ip, dest_ip, "user", event_type, device_id, status
                FROM alerts
                WHERE tenant_id = :tid AND event_id = :eid
            """),
            {"tid": "tenant-acme", "eid": "e2e-syslog-001"},
        )
        rows = result.fetchall()
        assert len(rows) >= 1, "No alert persisted to DB"

        alert = rows[0]
        assert alert.rule_name == "malware_detected"
        assert alert.severity == "critical"
        assert alert.risk_score == 95.0
        assert alert.source_ip == "10.0.0.50"
        assert alert.dest_ip == "192.168.1.1"
        assert alert.event_type == "malware_detected"
        assert alert.status == "new"
        assert alert.event_id == "e2e-syslog-001"

        # ── 4. Verify incident was also persisted ───────────────────────────
        result = await raw_db.execute(
            sa_text("SELECT id, title, severity, status FROM incidents WHERE tenant_id = :tid"),
            {"tid": "tenant-acme"},
        )
        inc_rows = result.fetchall()
        assert len(inc_rows) >= 1
        assert inc_rows[0].status == "new"
