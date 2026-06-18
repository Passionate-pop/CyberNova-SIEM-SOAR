"""Tests for the SOAR engine — verifies action triggering and execution."""
from __future__ import annotations
import pytest
from cybernova.soar.engine import SoarEngine, WebhookAction, LogAction, BlockIPAction, get_engine
from cybernova.response.automation.engine import PlaybookEngine, seed_default_playbooks
from cybernova.response.automation.models import (
    PlaybookDefinition, PlaybookStep, StepType, StepConfig,
    Condition, ConditionOperator, PlaybookTrigger, ExecutionStatus, StepStatus,
)
from cybernova.response.automation.engine import playbook_engine as live_engine


def test_soar_engine_should_trigger_critical_confirmed(monkeypatch):
    monkeypatch.setenv("CYBERNOVA_SOAR_ENABLED", "true")
    engine = SoarEngine()
    incident = {"confirmed": True, "severity": "critical", "risk_score": 100}
    assert engine.should_trigger(incident) is True


def test_soar_engine_should_trigger_high_risk(monkeypatch):
    monkeypatch.setenv("CYBERNOVA_SOAR_ENABLED", "true")
    engine = SoarEngine()
    incident = {"confirmed": True, "severity": "high", "risk_score": 120}
    assert engine.should_trigger(incident) is True


def test_soar_engine_should_not_trigger_unconfirmed(monkeypatch):
    monkeypatch.setenv("CYBERNOVA_SOAR_ENABLED", "true")
    engine = SoarEngine()
    incident = {"confirmed": False, "severity": "critical", "risk_score": 100}
    assert engine.should_trigger(incident) is False


def test_soar_engine_should_not_trigger_low_risk(monkeypatch):
    monkeypatch.setenv("CYBERNOVA_SOAR_ENABLED", "true")
    engine = SoarEngine()
    incident = {"confirmed": True, "severity": "low", "risk_score": 10}
    assert engine.should_trigger(incident) is False


def test_log_action_executes():
    action = LogAction()
    result = action.execute({"id": "test-1", "title": "Test incident", "severity": "high"})
    assert result is True


def test_webhook_action_builds_payload():
    action = WebhookAction(url="http://localhost:9999/webhook")
    result = action.execute({
        "id": "inc-1",
        "title": "Test",
        "severity": "critical",
        "incident_type": "malware",
        "status": "confirmed",
        "confirmed": True,
        "source_ip": "10.0.0.1",
    })
    assert result is True


def test_block_ip_action_simulated():
    action = BlockIPAction(simulation_mode=True)
    result = action.execute({
        "id": "inc-2",
        "source_ip": "10.0.0.99",
        "dest_ip": "192.168.1.1",
        "severity": "critical",
    })
    assert result is True


@pytest.mark.asyncio
async def test_playbook_engine_condition_evaluation():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-pb-1",
        name="Test Critical Response",
        description="Test",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        conditions=[
            Condition(field="alert.severity", operator=ConditionOperator.EQ, value="critical"),
            Condition(field="alert.risk_score", operator=ConditionOperator.GTE, value=80),
        ],
        steps=[
            PlaybookStep(id="step_log", name="Log", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success=None),
        ],
    )
    engine.register(playbook)

    execution_id = await engine.trigger("test-pb-1", {
        "alert": {"severity": "critical", "risk_score": 95},
        "tenant_id": "test",
    })
    assert execution_id is not None


@pytest.mark.asyncio
async def test_playbook_engine_skips_when_conditions_not_met():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-pb-2",
        name="Test Skip",
        description="Test",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        conditions=[
            Condition(field="alert.severity", operator=ConditionOperator.EQ, value="critical"),
        ],
        steps=[
            PlaybookStep(id="step_log", name="Log", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success=None),
        ],
    )
    engine.register(playbook)

    execution_id = await engine.trigger("test-pb-2", {
        "alert": {"severity": "low", "risk_score": 10},
        "tenant_id": "test",
    })
    assert execution_id is None


def test_seed_default_playbooks():
    engine = PlaybookEngine()
    old_count = len(engine._playbooks)
    seed_default_playbooks(engine)
    new_count = len(engine._playbooks)
    assert new_count == old_count + 4


@pytest.mark.asyncio
async def test_playbook_engine_execute_dispatches_known_action():
    engine = PlaybookEngine()
    result = await engine._execute_action_step(
        PlaybookStep(id="s1", name="Test PD", type=StepType.ACTION, config=StepConfig(action_type="pagerduty_trigger")),
        {"alert": {"id": "test-1", "severity": "critical", "title": "Test"}, "tenant_id": "t1"},
    )
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_playbook_engine_match_and_trigger():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-pb-3",
        name="Test Match",
        description="Test",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        conditions=[
            Condition(field="alert.severity", operator=ConditionOperator.EQ, value="critical"),
        ],
        steps=[
            PlaybookStep(id="step_log", name="Log", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success=None),
        ],
    )
    engine.register(playbook)

    ids = await engine.match_and_trigger({
        "alert": {"severity": "critical", "risk_score": 90},
        "tenant_id": "test",
    })
    assert len(ids) == 1


# ── Playbook Status Reporting Tests ──────────────────────────────────────────


def test_execution_status_enum_values():
    assert ExecutionStatus.PENDING.value == "pending"
    assert ExecutionStatus.RUNNING.value == "running"
    assert ExecutionStatus.COMPLETED.value == "completed"
    assert ExecutionStatus.FAILED.value == "failed"
    assert ExecutionStatus.CANCELLED.value == "cancelled"


def test_get_execution_progress_returns_none_for_missing():
    engine = PlaybookEngine()
    assert engine.get_execution_progress("nonexistent") is None


def test_list_executions_filtered_empty():
    engine = PlaybookEngine()
    result = engine.list_executions_filtered(status="running")
    assert result == []


@pytest.mark.asyncio
async def test_execution_tracks_current_step_id():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-status-pb",
        name="Status Test",
        description="Test",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        steps=[
            PlaybookStep(id="s1", name="Log", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success=None),
        ],
    )
    engine.register(playbook)
    eid = await engine.trigger("test-status-pb", {"alert": {"id": "t1"}, "tenant_id": "test"})
    assert eid is not None
    import asyncio
    await asyncio.sleep(0.5)
    exec_obj = engine.get_execution(eid)
    assert exec_obj is not None
    assert exec_obj.current_step_id is None  # cleared after completion
    assert exec_obj.status == ExecutionStatus.COMPLETED


@pytest.mark.asyncio
async def test_get_execution_progress_returns_correct_counts():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-progress-pb",
        name="Progress Test",
        description="Test",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        steps=[
            PlaybookStep(id="s1", name="Log", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success=None),
        ],
    )
    engine.register(playbook)
    eid = await engine.trigger("test-progress-pb", {"alert": {"id": "t1"}, "tenant_id": "test"})
    assert eid is not None
    import asyncio
    await asyncio.sleep(0.5)
    progress = engine.get_execution_progress(eid)
    assert progress is not None
    assert progress["execution_id"] == eid
    assert progress["total_steps"] == 1
    assert progress["completed_steps"] == 1
    assert progress["progress_percentage"] == 100.0
    assert progress["status"] == "completed"


@pytest.mark.asyncio
async def test_retry_execution_fails_on_non_failed():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-retry-pb",
        name="Retry Test",
        description="Test",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        steps=[
            PlaybookStep(id="s1", name="Log", type=StepType.ACTION, config=StepConfig(action_type="log_alert"), next_on_success=None),
        ],
    )
    engine.register(playbook)
    eid = await engine.trigger("test-retry-pb", {"alert": {"id": "t1"}, "tenant_id": "test"})
    assert eid is not None
    import asyncio
    await asyncio.sleep(0.5)
    result = await engine.retry_execution(eid)
    assert result is None  # cannot retry a completed execution


@pytest.mark.asyncio
async def test_cancel_execution():
    engine = PlaybookEngine()
    playbook = PlaybookDefinition(
        id="test-cancel-pb",
        name="Cancel Test",
        description="Test with delay",
        trigger=PlaybookTrigger.ALERT_CREATED,
        enabled=True,
        priority=1,
        tenant_id="test",
        steps=[
            PlaybookStep(id="s1", name="Wait", type=StepType.DELAY, config=StepConfig(delay_seconds=30), next_on_success=None),
        ],
    )
    engine.register(playbook)
    eid = await engine.trigger("test-cancel-pb", {"alert": {"id": "t1"}, "tenant_id": "test"})
    assert eid is not None
    import asyncio
    await asyncio.sleep(0.2)
    ok = await engine.cancel_execution(eid)
    assert ok is True
    exec_obj = engine.get_execution(eid)
    assert exec_obj is not None
    assert exec_obj.status == ExecutionStatus.CANCELLED


def test_list_executions_filtered_by_status():
    engine = PlaybookEngine()
    result = engine.list_executions_filtered(status="running")
    assert isinstance(result, list)


def test_list_executions_filtered_by_playbook():
    engine = PlaybookEngine()
    result = engine.list_executions_filtered(playbook_id="nonexistent")
    assert result == []
