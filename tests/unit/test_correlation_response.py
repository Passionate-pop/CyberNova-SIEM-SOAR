"""Unit tests for correlation/ and response/ modules — targeting 80%+ coverage."""

from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

import pytest


# ── Correlation ───────────────────────────────────────────────────────────────


class TestCorrelationIncidentBuilder:
    def test_build_incident_creates_full_structure(self):
        from cybernova.correlation.incident_builder import IncidentBuilder
        builder = IncidentBuilder()
        alerts = [
            {"id": "a1", "rule_name": "brute_force", "severity": "high",
             "source_ip": "10.0.0.1", "risk_score": 75, "description": "BF",
             "created_at": "2024-01-01T00:00:00"},
            {"id": "a2", "rule_name": "malware", "severity": "critical",
             "source_ip": "10.0.0.1", "risk_score": 90, "description": "MW",
             "created_at": "2024-01-01T00:01:00"},
        ]
        incident = builder.build_incident(
            rule_name="brute_force_to_malware",
            rule_description="Brute force followed by malware",
            matched_alerts=alerts,
            tenant_id="t1",
        )
        assert incident["tenant_id"] == "t1"
        assert len(incident["alert_ids"]) == 2
        assert "attack_story" in incident
        assert "recommendations" in incident
        assert "affected_entities" in incident
        assert incident["severity"] == "critical"

    def test_extract_entities_is_internal(self):
        from cybernova.correlation.incident_builder import IncidentBuilder
        builder = IncidentBuilder()
        alerts = [
            {"source_ip": "1.2.3.4", "user": "admin",
             "raw_event": {"dest_ip": "5.6.7.8", "hostname": "srv-1"}},
        ]
        entities = builder._extract_affected_entities(alerts)
        assert "1.2.3.4" in entities["source_ips"]
        assert "admin" in entities["users"]
        assert "srv-1" in entities["hosts"]

    def test_get_recommendations_for_brute_force(self):
        from cybernova.correlation.incident_builder import IncidentBuilder
        builder = IncidentBuilder()
        recs = builder._get_recommendations("brute_force_detected", [])
        assert isinstance(recs, list)
        assert len(recs) > 0
        assert any("Block the source IP" in r for r in recs)

    def test_build_attack_story(self):
        from cybernova.correlation.incident_builder import IncidentBuilder
        builder = IncidentBuilder()
        alerts = [
            {"rule_name": "brute_force", "severity": "high",
             "source_ip": "10.0.0.1", "created_at": "2024-01-01T00:00:00"},
        ]
        story = builder._build_attack_story(alerts)
        assert "brute_force" in story
        assert "HIGH" in story

    def test_risk_score_calculation(self):
        from cybernova.correlation.incident_builder import IncidentBuilder
        builder = IncidentBuilder()
        score = builder._calculate_risk_score([
            {"risk_score": 50},
            {"risk_score": 80},
        ])
        assert 80 <= score <= 100

    def test_incident_builder_empty_alerts(self):
        from cybernova.correlation.incident_builder import IncidentBuilder
        builder = IncidentBuilder()
        story = builder._build_attack_story([])
        assert "No events" in story
        score = builder._calculate_risk_score([])
        assert score == 0.0


class TestCorrelationRulesEngine:
    @pytest.mark.asyncio
    async def test_load_rules_returns_defaults(self):
        from cybernova.correlation.rules_engine import CorrelationRulesEngine
        engine = CorrelationRulesEngine()
        rules = await engine.load_rules("test")
        assert len(rules) >= 6

    @pytest.mark.asyncio
    async def test_add_and_disable_rule(self):
        from cybernova.correlation.rules_engine import CorrelationRulesEngine, CorrelationRule
        engine = CorrelationRulesEngine()
        rule = CorrelationRule(
            id="test-1", name="Test Rule",
            description="test", sequence=["failed_login"],
            entity_field="source_ip", window_seconds=300,
            severity="high", enabled=True, tenant_id="test",
        )
        await engine.add_rule(rule)
        assert any(r.id == "test-1" for r in engine._rules.get("test", []))
        await engine.disable_rule("test-1", "test")
        disabled = [r for r in engine._rules.get("test", []) if r.id == "test-1"]
        assert all(not r.enabled for r in disabled)

    @pytest.mark.asyncio
    async def test_match_sequence(self):
        from cybernova.correlation.rules_engine import CorrelationRulesEngine, CorrelationRule
        engine = CorrelationRulesEngine()
        rule = CorrelationRule(
            id="bf-test", name="BF Test",
            description="brute force to success",
            sequence=["failed_login", "successful_login"],
            entity_field="source_ip", window_seconds=300,
            severity="critical", enabled=True, tenant_id="test",
        )
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        alerts = [
            {"id": "a1", "event_type": "failed_login", "rule_name": "failed_login",
             "source_ip": "10.0.0.1", "created_at": now},
            {"id": "a2", "event_type": "successful_login", "rule_name": "successful_login",
             "source_ip": "10.0.0.1", "created_at": now},
        ]
        matched, confidence = await engine.match_sequence(alerts, rule)
        assert matched is True
        assert confidence > 0


class TestCorrelationRuleFromDict:
    def test_from_dict_full(self):
        from cybernova.correlation.rules_engine import CorrelationRule
        rule = CorrelationRule.from_dict({
            "name": "test", "description": "desc", "severity": "high",
            "risk_score": 70, "sequence": ["failed_login"],
            "entity_field": "source_ip", "window_seconds": 300,
        })
        assert rule.name == "test"
        assert rule.tenant_id == "default"

    def test_from_dict_defaults(self):
        from cybernova.correlation.rules_engine import CorrelationRule
        rule = CorrelationRule.from_dict({
            "name": "minimal",
            "sequence": ["failed_login"],
        })
        assert rule.severity == "medium"


class TestEntityTracker:
    @pytest.mark.asyncio
    async def test_track_and_timeline(self):
        from cybernova.correlation.entity_tracker import EntityTracker
        redis = AsyncMock()
        redis.zadd.return_value = 1
        redis.expire.return_value = True
        redis.zrangebyscore.return_value = []
        tracker = EntityTracker(redis)
        await tracker.track_alert(
            {"id": "a1", "event_type": "failed_login",
             "source_ip": "10.0.0.1", "severity": "high"},
            entity_field="source_ip",
        )
        redis.zadd.assert_awaited()
        redis.expire.assert_awaited()

    @pytest.mark.asyncio
    async def test_get_entity_timeline(self):
        redis = AsyncMock()
        redis.zrangebyscore.return_value = []
        from cybernova.correlation.entity_tracker import EntityTracker
        tracker = EntityTracker(redis)
        timeline = await tracker.get_entity_timeline("source_ip", "10.0.0.1")
        assert isinstance(timeline, list)

    @pytest.mark.asyncio
    async def test_get_entity_count(self):
        redis = AsyncMock()
        async def fake_scan_iter(*args, **kwargs):
            for i in ():
                yield i
        redis.scan_iter = fake_scan_iter
        from cybernova.correlation.entity_tracker import EntityTracker
        tracker = EntityTracker(redis)
        count = await tracker.get_entity_count("source_ip")
        assert count == 0

    @pytest.mark.asyncio
    async def test_cleanup_old_entries(self):
        redis = AsyncMock()
        async def fake_scan_iter(*args, **kwargs):
            for i in ():
                yield i
        redis.scan_iter = fake_scan_iter
        from cybernova.correlation.entity_tracker import EntityTracker
        tracker = EntityTracker(redis)
        removed = await tracker.cleanup_old_entries()
        assert removed == 0


# ── Response / Automation ─────────────────────────────────────────────────────


class TestPlaybookEngine:
    def test_list_playbooks_empty(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        pbs = engine.list_playbooks()
        assert isinstance(pbs, list)

    def test_register_and_get_playbook(self):
        from cybernova.response.automation.engine import PlaybookEngine
        from cybernova.response.automation.models import (
            PlaybookDefinition, PlaybookTrigger,
        )
        engine = PlaybookEngine()
        pb = PlaybookDefinition(
            id="pb-test", name="Test", tenant_id="default",
            trigger=PlaybookTrigger.ALERT_CREATED,
        )
        engine.register(pb)
        assert engine.get_playbook("pb-test") is not None

    @pytest.mark.asyncio
    async def test_trigger_unregistered_returns_none(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        eid = await engine.trigger("nonexistent", {})
        assert eid is None

    @pytest.mark.asyncio
    async def test_match_and_trigger_empty(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        ids = await engine.match_and_trigger({"alert": {"severity": "critical"}})
        assert isinstance(ids, list)

    def test_list_executions(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        execs = engine.list_executions()
        assert isinstance(execs, list)

    def test_list_executions_filtered(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        execs = engine.list_executions_filtered(status="running")
        assert isinstance(execs, list)

    @pytest.mark.asyncio
    async def test_approve_nonexistent(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        result = await engine.approve("bad-id", "admin")
        assert result is False

    @pytest.mark.asyncio
    async def test_reject_nonexistent(self):
        from cybernova.response.automation.engine import PlaybookEngine
        engine = PlaybookEngine()
        result = await engine.reject("bad-id", "admin")
        assert result is False


class TestSeedDefaultPlaybooks:
    def test_seed_playbooks(self):
        from cybernova.response.automation.engine import seed_default_playbooks
        result = seed_default_playbooks()
        assert result is None

    def test_seeded_playbooks_registered(self):
        from cybernova.response.automation.engine import playbook_engine
        from cybernova.response.automation.engine import seed_default_playbooks
        seed_default_playbooks()
        pbs = playbook_engine.list_playbooks()
        names = {p.name for p in pbs}
        assert "Critical Incident Response" in names


class TestExecutionStatus:
    def test_enum_values(self):
        from cybernova.response.automation.models import ExecutionStatus
        assert ExecutionStatus.PENDING.value == "pending"
        assert ExecutionStatus.RUNNING.value == "running"
        assert ExecutionStatus.COMPLETED.value == "completed"
        assert ExecutionStatus.FAILED.value == "failed"
        assert ExecutionStatus.CANCELLED.value == "cancelled"


class TestPlaybookExecution:
    def test_playbook_execution_creation(self):
        from cybernova.response.automation.models import (
            PlaybookExecution, ExecutionStatus, StepExecution, StepType,
            PlaybookTrigger,
        )
        exec_obj = PlaybookExecution(
            id="exec-1", playbook_id="pb-1", playbook_name="Test",
            trigger=PlaybookTrigger.ALERT_CREATED, context={},
            status=ExecutionStatus.RUNNING,
            steps=[StepExecution(step_id="s1", step_name="Step 1", step_type=StepType.ACTION)],
        )
        assert exec_obj.current_step_id is None


class TestActions:
    def test_email_alert_simulated(self):
        from cybernova.response.actions.email_alert import execute_email_alert
        result = execute_email_alert({
            "to": "test@example.com",
            "title": "Test",
            "severity": "high",
        })
        assert result.get("simulated") is True

    def test_email_missing_recipient(self):
        from cybernova.response.actions.email_alert import execute_email_alert
        result = execute_email_alert({"title": "No recipient"})
        assert result.get("error") == "No recipient address"


class TestSoarEngine:
    def test_should_trigger_false_low_risk_low_severity(self):
        with patch.dict("os.environ", {"CYBERNOVA_SOAR_ACTIONS": "log"}, clear=True):
            from cybernova.soar.engine import SoarEngine
            engine = SoarEngine()
            # Confirmed but severity=low and risk_score=0 → below threshold
            result = engine.should_trigger({"confirmed": True, "severity": "low", "risk_score": 0})
            assert result is False

    def test_should_trigger_false_when_not_confirmed(self):
        with patch.dict("os.environ", {"CYBERNOVA_SOAR_ENABLED": "true", "CYBERNOVA_SOAR_ACTIONS": "log"}, clear=True):
            from cybernova.soar.engine import SoarEngine
            engine = SoarEngine()
            result = engine.should_trigger({"confirmed": False, "severity": "critical"})
            assert result is False

    def test_should_trigger_true_critical_confirmed(self):
        with patch.dict("os.environ", {"CYBERNOVA_SOAR_ENABLED": "true", "CYBERNOVA_SOAR_ACTIONS": "log"}, clear=True):
            from cybernova.soar.engine import SoarEngine
            engine = SoarEngine()
            result = engine.should_trigger({"confirmed": True, "severity": "critical", "risk_score": 50})
            assert result is True

    def test_should_trigger_true_high_risk_confirmed(self):
        with patch.dict("os.environ", {"CYBERNOVA_SOAR_ENABLED": "true", "CYBERNOVA_SOAR_ACTIONS": "log"}, clear=True):
            from cybernova.soar.engine import SoarEngine
            engine = SoarEngine()
            result = engine.should_trigger({"confirmed": True, "severity": "high", "risk_score": 120})
            assert result is True

    def test_log_action_execute(self):
        from cybernova.soar.engine import LogAction
        action = LogAction()
        result = action.execute({"id": "test-1", "title": "Test", "severity": "critical"})
        assert result is True

    def test_webhook_action_execute(self):
        from cybernova.soar.engine import WebhookAction
        action = WebhookAction(url="http://localhost:9999/test")
        with patch.object(action, "_send_async", return_value=None):
            result = action.execute({"id": "test-1", "title": "Test"})
            assert result is True

    def test_block_ip_simulation(self):
        from cybernova.soar.engine import BlockIPAction
        action = BlockIPAction(simulation_mode=True)
        result = action.execute({"source_ip": "1.2.3.4", "dest_ip": "5.6.7.8"})
        assert result is True

    def test_trigger_returns_false_when_not_confirmed(self):
        with patch.dict("os.environ", {"CYBERNOVA_SOAR_ENABLED": "true", "CYBERNOVA_SOAR_ACTIONS": "log"}, clear=True):
            from cybernova.soar.engine import SoarEngine
            engine = SoarEngine()
            result = engine.trigger({"confirmed": False, "severity": "critical"})
            assert result is False

    def test_trigger_if_returns_none_when_not_confirmed(self):
        with patch.dict("os.environ", {"CYBERNOVA_SOAR_ENABLED": "true", "CYBERNOVA_SOAR_ACTIONS": "log"}, clear=True):
            from cybernova.soar.engine import SoarEngine
            engine = SoarEngine()
            result = engine.trigger_if({"confirmed": False, "severity": "critical"})
            assert result is None


class TestMatchPlaybook:
    def test_match_by_severity(self):
        from cybernova.response.policy_engine.playbooks import match_playbook
        results = match_playbook({"severity": "critical", "risk_score": 95})
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_match_by_rule_name(self):
        from cybernova.response.policy_engine.playbooks import match_playbook
        results = match_playbook({
            "severity": "critical", "risk_score": 95,
            "rule_name": "malware_detected",
        })
        assert isinstance(results, list)

    def test_no_match_low_severity(self):
        from cybernova.response.policy_engine.playbooks import match_playbook
        results = match_playbook({"severity": "low", "risk_score": 10})
        assert isinstance(results, list)

    def test_severity_action(self):
        from cybernova.response.policy_engine.playbooks import get_severity_action
        assert get_severity_action("critical") == "automated"
        assert get_severity_action("low") == "ui_only"
