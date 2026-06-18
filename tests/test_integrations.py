"""Tests for external integrations (Slack, PagerDuty)."""
from __future__ import annotations
import pytest
from cybernova.integrations.slack_connector import SlackConnector
from cybernova.integrations.pagerduty_connector import PagerDutyConnector
from cybernova.response.actions.pagerduty_trigger import execute_pagerduty_trigger, _build_pd_event
from cybernova.response.actions.opsgenie_trigger import execute_opsgenie_trigger, _build_opsgenie_alert
from cybernova.response.actions.jira_create import execute_jira_create, _build_jira_issue
from cybernova.response.actions.servicenow_create import execute_servicenow_create, _build_snow_incident
from cybernova.response.actions.email_alert import execute_email_alert, _build_email

@pytest.mark.asyncio
async def test_slack_connector_builds_alert_blocks():
    connector = SlackConnector()
    await connector.initialize()
    assert connector.name == "slack"
    assert connector.version == "1.0.0"
    blocks = connector._build_blocks("alert", {
        "severity": "critical",
        "rule_name": "test_rule",
        "risk_score": 95.0,
        "source_ip": "10.0.0.1",
    })
    assert len(blocks) > 0
    assert blocks[0]["type"] == "header"


@pytest.mark.asyncio
async def test_slack_connector_incident_blocks():
    connector = SlackConnector()
    await connector.initialize()
    blocks = connector._build_blocks("incident", {
        "title": "Test incident",
        "severity": "critical",
        "status": "new",
    })
    assert len(blocks) > 0
    assert any("Incident" in str(b) for b in blocks)


@pytest.mark.asyncio
async def test_pagerduty_connector_builds_event():
    connector = PagerDutyConnector()
    await connector.initialize()
    pd_event = connector._build_event("alert", {
        "id": "alert-2",
        "rule_name": "ransomware_detected",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
    })
    assert pd_event["event_action"] == "trigger"
    assert pd_event["payload"]["severity"] == "critical"
    assert "cybernova:alert:alert-2" == pd_event["dedup_key"]


def test_pagerduty_trigger_action_builds_incident():
    result = execute_pagerduty_trigger({
        "id": "alert-3",
        "title": "test_rule",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
        "dest_ip": "",
        "user": "",
        "description": "Test incident",
    })
    assert isinstance(result, dict)
    assert result["success"] is True
    assert result.get("simulated") is True


def test_pagerduty_trigger_builds_event_structure():
    pd_event = _build_pd_event({
        "id": "alert-4",
        "title": "ransomware_detected",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
    })
    assert pd_event["event_action"] == "trigger"
    assert pd_event["payload"]["severity"] == "critical"
    assert "alert-4" in pd_event["dedup_key"]


def test_pagerduty_action_returns_dict():
    result = execute_pagerduty_trigger({})
    assert isinstance(result, dict)
    assert "success" in result


def test_opsgenie_trigger_action_builds_alert():
    result = execute_opsgenie_trigger({
        "id": "alert-5",
        "title": "test_rule",
        "severity": "critical",
        "risk_score": 95.0,
        "source_ip": "10.0.0.1",
    })
    assert isinstance(result, dict)
    assert result["success"] is True
    assert result.get("simulated") is True


def test_opsgenie_builds_alert_structure():
    alert = _build_opsgenie_alert({
        "id": "alert-6",
        "title": "ransomware_detected",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
        "description": "Ransomware detected on endpoint",
    })
    assert alert["priority"] == "P1"
    assert "ransomware" in alert["message"].lower()
    assert alert["alias"] == "cybernova:alert:alert-6"
    assert alert["details"]["risk_score"] == "98.0"


def test_opsgenie_action_returns_dict():
    result = execute_opsgenie_trigger({})
    assert isinstance(result, dict)
    assert "success" in result


def test_jira_create_action_builds_issue():
    result = execute_jira_create({
        "id": "alert-7",
        "title": "test_rule",
        "severity": "critical",
        "risk_score": 95.0,
        "source_ip": "10.0.0.1",
    })
    assert isinstance(result, dict)
    assert result["success"] is True
    assert result.get("simulated") is True


def test_jira_builds_issue_structure():
    issue = _build_jira_issue({
        "id": "alert-8",
        "title": "ransomware_detected",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
        "description": "Ransomware detected",
    })
    fields = issue["fields"]
    assert fields["project"]["key"] == "SEC"
    assert fields["priority"]["name"] == "Highest"
    assert "ransomware" in fields["summary"].lower()
    assert "cybernova" in fields["labels"]


def test_jira_action_returns_dict():
    result = execute_jira_create({})
    assert isinstance(result, dict)
    assert "success" in result


def test_servicenow_create_action_builds_incident():
    result = execute_servicenow_create({
        "id": "alert-9",
        "title": "test_rule",
        "severity": "critical",
        "risk_score": 95.0,
        "source_ip": "10.0.0.1",
    })
    assert isinstance(result, dict)
    assert result["success"] is True
    assert result.get("simulated") is True


def test_servicenow_builds_incident_structure():
    incident = _build_snow_incident({
        "id": "alert-10",
        "title": "ransomware_detected",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
        "description": "Ransomware detected",
    })
    assert incident["priority"] == "1"
    assert incident["category"] == "Security"
    assert "ransomware" in incident["short_description"].lower()
    assert "Ransomware" in incident["description"]


def test_servicenow_action_returns_dict():
    result = execute_servicenow_create({})
    assert isinstance(result, dict)
    assert "success" in result


def test_email_alert_action_simulates_when_no_smtp():
    result = execute_email_alert({
        "id": "alert-11",
        "title": "test_rule",
        "severity": "critical",
        "to": "admin@example.com",
    })
    assert isinstance(result, dict)
    assert result["success"] is True
    assert result.get("simulated") is True


def test_email_builds_structure():
    email = _build_email({
        "id": "alert-12",
        "title": "ransomware_detected",
        "severity": "critical",
        "risk_score": 98.0,
        "source_ip": "10.0.0.5",
        "description": "Ransomware detected",
    })
    assert "ransomware" in email["subject"].lower()
    assert "Ransomware" in email["body"]


def test_email_alert_missing_recipient():
    result = execute_email_alert({"id": "alert-13"})
    assert result["success"] is False
    assert "No recipient" in result.get("error", "")
