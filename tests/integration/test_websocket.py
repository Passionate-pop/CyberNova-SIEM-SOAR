"""WebSocket integration test: connect WS client, push pipeline alert, verify receipt."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybernova.api.websocket import (
    ConnectionManager,
    EventType,
    WebSocketHandler,
    WebSocketMessage,
    connection_manager,
    ws_handler,
)
from cybernova.database.repository.repositories import AlertRepository
from cybernova.pipeline.bus import PipelineEnvelope


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_fake_ws():
    ws = AsyncMock()
    ws.client = MagicMock()
    ws.client.host = "127.0.0.1"
    return ws


def _make_mock_rule(name, severity, risk_score, description, mitre_tactic=None, mitre_technique=None):
    r = MagicMock()
    r.name = name
    r.severity = severity
    r.risk_score = risk_score
    r.description = description
    r.mitre_tactic = mitre_tactic
    r.mitre_technique = mitre_technique
    return r


class _CompatSession:
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

    async def flush(self):
        await self._session.flush()


async def _sqlite_bulk_insert(self, mappings):
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


# ── WebSocket Integration Tests ─────────────────────────────────────────────


class TestConnectionManager:
    """ConnectionManager: connect, disconnect, limits, broadcast."""

    @pytest.mark.asyncio
    async def test_connect_and_disconnect(self):
        ws = _make_fake_ws()
        accepted = await connection_manager.connect(ws, "tenant-acme", client_ip="127.0.0.1")
        assert accepted
        ws.accept.assert_awaited_once()
        assert connection_manager.get_connection_count() == 1
        assert connection_manager.get_tenant_ids() == ["tenant-acme"]

        await connection_manager.disconnect(ws)
        assert connection_manager.get_connection_count() == 0

    @pytest.mark.asyncio
    async def test_per_tenant_limit(self):
        ws1 = _make_fake_ws()

        with patch("cybernova.api.websocket.WS_MAX_PER_TENANT", 1):
            accepted = await connection_manager.connect(ws1, "tenant-limited", client_ip="10.0.0.1")
            assert accepted

            ws2 = _make_fake_ws()
            accepted = await connection_manager.connect(ws2, "tenant-limited", client_ip="10.0.0.2")
            assert not accepted
            ws2.close.assert_awaited_once()

        await connection_manager.disconnect(ws1)

    @pytest.mark.asyncio
    async def test_send_to_tenant_receives_message(self):
        ws = _make_fake_ws()
        await connection_manager.connect(ws, "tenant-acme", client_ip="127.0.0.1")

        msg = WebSocketMessage(
            event_type=EventType.NEW_ALERT,
            data={"alert": {"id": "a1", "rule_name": "test"}},
            tenant_id="tenant-acme",
        )
        sent = await connection_manager.send_to_tenant("tenant-acme", msg)
        assert sent == 1

        ws.send_text.assert_awaited_once()
        raw = ws.send_text.call_args[0][0]
        payload = json.loads(raw)
        assert payload["type"] == "new_alert"
        assert payload["data"]["alert"]["id"] == "a1"
        assert payload["tenant_id"] == "tenant-acme"

        await connection_manager.disconnect(ws)

    @pytest.mark.asyncio
    async def test_event_type_filtering(self):
        ws = _make_fake_ws()
        await connection_manager.connect(
            ws, "tenant-acme", client_ip="127.0.0.1",
            event_types={EventType.SYSTEM_NOTIFICATION},
        )

        alert_msg = WebSocketMessage(
            event_type=EventType.NEW_ALERT,
            data={"alert": {"id": "a1"}},
            tenant_id="tenant-acme",
        )
        sent = await connection_manager.send_to_tenant("tenant-acme", alert_msg)
        assert sent == 0
        ws.send_text.assert_not_called()

        notif_msg = WebSocketMessage(
            event_type=EventType.SYSTEM_NOTIFICATION,
            data={"message": "hello"},
            tenant_id="tenant-acme",
        )
        sent = await connection_manager.send_to_tenant("tenant-acme", notif_msg)
        assert sent == 1
        ws.send_text.assert_awaited_once()

        await connection_manager.disconnect(ws)

    @pytest.mark.asyncio
    async def test_send_to_wrong_tenant(self):
        ws = _make_fake_ws()
        await connection_manager.connect(ws, "tenant-acme", client_ip="127.0.0.1")

        msg = WebSocketMessage(
            event_type=EventType.NEW_ALERT,
            data={"alert": {"id": "a1"}},
            tenant_id="other-tenant",
        )
        sent = await connection_manager.send_to_tenant("other-tenant", msg)
        assert sent == 0

        await connection_manager.disconnect(ws)


class TestWebSocketHandler:
    """WebSocketHandler.broadcast_alert() — pipeline alert → WS message format."""

    @pytest.mark.asyncio
    async def test_broadcast_alert_to_connected_client(self):
        ws = _make_fake_ws()
        await connection_manager.connect(ws, "tenant-acme", client_ip="127.0.0.1")

        alert = {
            "id": "alert-001",
            "rule_name": "malware_detected",
            "severity": "critical",
            "risk_score": 95.0,
            "source_ip": "10.0.0.50",
            "dest_ip": "192.168.1.1",
            "user": "admin",
            "event_type": "malware_detected",
            "description": "Malware signature matched on dev-001",
            "status": "new",
            "event_id": "evt-001",
        }
        await ws_handler.broadcast_alert(alert, "tenant-acme")

        ws.send_text.assert_called_once()
        raw = ws.send_text.call_args[0][0]
        msg = json.loads(raw)
        assert msg["type"] == "new_alert"
        assert msg["event_type"] == "new_alert"
        assert msg["data"]["alert"] == alert
        assert msg["tenant_id"] == "tenant-acme"
        assert "timestamp" in msg

        await connection_manager.disconnect(ws)

    @pytest.mark.asyncio
    async def test_broadcast_alert_only_goes_to_matching_tenant(self):
        ws_acme = _make_fake_ws()
        ws_other = _make_fake_ws()
        await connection_manager.connect(ws_acme, "tenant-acme", client_ip="127.0.0.1")
        await connection_manager.connect(ws_other, "tenant-other", client_ip="127.0.0.2")

        alert = {"id": "alert-001", "rule_name": "test", "severity": "high", "risk_score": 50}
        await ws_handler.broadcast_alert(alert, "tenant-acme")

        ws_acme.send_text.assert_called_once()
        ws_other.send_text.assert_not_called()

        await connection_manager.disconnect(ws_acme)
        await connection_manager.disconnect(ws_other)

    @pytest.mark.asyncio
    async def test_broadcast_alert_no_clients(self):
        """Broadcasting when no WS is connected should not raise."""
        alert = {"id": "alert-001", "rule_name": "test", "severity": "high", "risk_score": 50}
        await ws_handler.broadcast_alert(alert, "tenant-acme")


class TestPipelineToWebSocket:
    """Full flow: pipeline stages → alert → WS broadcast → verify."""

    @pytest.mark.asyncio
    async def test_pipeline_alert_reaches_ws_client(self, db_engine):
        """
        Connect a WS client, push syslog event through pipeline stages,
        broadcast resulting alert to WS, verify client receives it.
        """
        ws = _make_fake_ws()
        await connection_manager.connect(ws, "tenant-acme", client_ip="127.0.0.1")

        session_factory = async_sessionmaker(db_engine, class_=AsyncSession)
        async with session_factory() as raw_db:
            db = _CompatSession(raw_db)

            async def _fake_db_session():
                yield db

            _patcher_db = patch("cybernova.database.postgres.session.get_db_session", _fake_db_session)
            _patcher_bulk = patch.object(AlertRepository, "bulk_insert", _sqlite_bulk_insert)
            _patcher_evt = patch("cybernova.pipeline.stages.alerter.event_producer.publish",
                                 return_value=True)
            _patcher_db.start()
            _patcher_bulk.start()
            _patcher_evt.start()

            try:
                # ── 1. Create syslog envelope ──
                envelope = PipelineEnvelope(
                    event_id="ws-test-evt",
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

                # ── 2. Normalization ──
                from cybernova.pipeline.stages.normalizer import normalization_stage
                envelope = await normalization_stage.handle(envelope)
                assert envelope.stage == "enrichment"

                # ── 3. Enrichment ──
                from cybernova.pipeline.stages.enricher import enrichment_stage
                with (
                    patch("cybernova.pipeline.stages.enricher.geoip_service.lookup",
                          return_value={"country": "US", "city": "NYC"}),
                    patch("cybernova.pipeline.stages.enricher.threat_intel_service.lookup_ip",
                          return_value={"malicious": True, "risk_modifier": 15}),
                ):
                    envelope = await enrichment_stage.handle(envelope)
                # Enrichment → Anomaly stage (anomaly detection runs between enrichment and detection)
                assert envelope.stage == "anomaly"

                # ── 4. Detection ──
                from cybernova.pipeline.stages.detector import detection_stage
                mock_rule = _make_mock_rule(
                    "malware_detected", "critical", 95.0,
                    "Malware signature matched", "TA0001", "T1204",
                )
                with (
                    patch("cybernova.pipeline.stages.detector.rule_engine.evaluate",
                          return_value=[mock_rule]),
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
                assert len(envelope.payload["alerts"]) >= 1

                # ── 5. Correlation ──
                from cybernova.pipeline.stages.correlator import CorrelationStage
                correlator = CorrelationStage()
                envelope = await correlator.handle(envelope)
                assert envelope.stage == "alert"
                assert len(envelope.payload["incidents"]) >= 1

                # ── 6. Alert stage (persist to DB) ──
                from cybernova.pipeline.stages.alerter import alert_stage
                envelope = await alert_stage.handle(envelope)
                assert envelope.stage == "soar"

                # ── 7. SOAR ──
                from cybernova.pipeline.stages.soar import SOARStage
                soar = SOARStage()
                envelope = await soar.handle(envelope)
                assert envelope.stage == "notification"

            finally:
                _patcher_db.stop()
                _patcher_bulk.stop()
                _patcher_evt.stop()

            # ── 8. Verify alert persisted to DB ──
            result = await raw_db.execute(
                sa_text("SELECT id, rule_name, severity, risk_score FROM alerts WHERE tenant_id = :tid"),
                {"tid": "tenant-acme"},
            )
            db_alerts = result.fetchall()
            assert len(db_alerts) >= 1

            # ── 9. Broadcast pipeline alert to WebSocket ──
            alerts = envelope.payload.get("alerts", [])
            assert len(alerts) >= 1
            pipeline_alert = alerts[0]

            await ws_handler.broadcast_alert(pipeline_alert, "tenant-acme")

            # ── 10. Verify WS received the alert ──
            ws.send_text.assert_called_once()
            raw = ws.send_text.call_args[0][0]
            msg = json.loads(raw)
            assert msg["type"] == "new_alert"
            assert msg["event_type"] == "new_alert"
            assert msg["tenant_id"] == "tenant-acme"
            assert msg["data"]["alert"]["id"] == pipeline_alert["id"]
            assert msg["data"]["alert"]["rule_name"] == "malware_detected"
            assert msg["data"]["alert"]["severity"] == "critical"
            assert msg["data"]["alert"]["risk_score"] == 95.0
            assert msg["data"]["alert"]["source_ip"] == "10.0.0.50"
            assert "timestamp" in msg

        await connection_manager.disconnect(ws)
