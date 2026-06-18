"""
CyberNova — Okta SSO / Auth Log Parser
Parses Okta system log events from the Okta API.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.ingestion.parsers.okta")

OKTA_EVENT_TYPES = {
    "user.session.start": "okta_login",
    "user.session.end": "okta_logout",
    "user.authentication.auth_via_radius": "okta_radius_auth",
    "user.authentication.authenticate": "okta_auth",
    "user.account.recovery": "okta_password_recovery",
    "user.account.update_password": "okta_password_change",  # nosec - event type name, not secret
    "user.mfa.factor_verify": "okta_mfa_verify",
    "user.mfa.factor_enroll": "okta_mfa_enroll",
    "user.mfa.factor_deactivate": "okta_mfa_deactivate",
    "group.user_membership.add": "okta_group_add",
    "group.user_membership.remove": "okta_group_remove",
    "user.lifecycle.create": "okta_user_created",
    "user.lifecycle.delete": "okta_user_deleted",
    "user.lifecycle.suspend": "okta_user_suspended",
    "user.lifecycle.unsuspend": "okta_user_unsuspended",
    "user.lifecycle.deactivate": "okta_user_deactivated",
    "user.lifecycle.reactivate": "okta_user_reactivated",
    "application.user_membership.add": "okta_app_assign",
    "application.user_membership.remove": "okta_app_unassign",
    "core.user_config.administrator_role.add": "okta_admin_role_add",
    "core.user_config.administrator_role.remove": "okta_admin_role_remove",
    "policy.rule.update": "okta_policy_update",
    "policy.rule.delete": "okta_policy_delete",
}

HIGH_SEVERITY_EVENTS = {
    "okta_mfa_deactivate", "okta_user_deleted", "okta_user_suspended",
    "okta_admin_role_add", "okta_admin_role_remove",
    "okta_policy_delete", "okta_password_recovery",
}

OUTCOME_MAP = {
    "SUCCESS": "success",
    "FAILURE": "failure",
    "DENY": "denied",
    "CHALLENGE": "challenge",
    "UNKNOWN": "unknown",
}


def _parse_targets(targets: list) -> list[dict]:
    results = []
    if not isinstance(targets, list):
        return results
    for t in targets:
        if isinstance(t, dict):
            results.append({
                "id": t.get("id", ""),
                "type": t.get("type", ""),
                "alternate_id": t.get("alternateId", t.get("alternate_id", "")),
                "display_name": t.get("displayName", t.get("display_name", "")),
            })
    return results


def _parse_context(context: Optional[Dict[str, Any]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not isinstance(context, dict):
        return result
    if isinstance(context.get("request"), dict):
        req = context["request"]
        result["ip"] = req.get("ipAddress", req.get("ip_address", ""))
        ua = req.get("userAgent", req.get("user_agent", ""))
        if isinstance(ua, str):
            result["user_agent"] = ua
        elif isinstance(ua, dict):
            result["user_agent"] = ua.get("rawUserAgent", ua.get("browser", ""))
    if isinstance(context.get("device"), dict):
        device = context["device"]
        result["device"] = device.get("device", "")
    return result


def parse_okta_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("Okta JSON parse failed: %s", exc)
            return {"event_type": "okta", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "okta", "severity": "info", "message": str(raw)}

    event_type_raw = raw.get("eventType", raw.get("event_type", ""))
    mapped_type = OKTA_EVENT_TYPES.get(event_type_raw, f"okta_{event_type_raw.replace('.', '_')}")

    outcome = raw.get("outcome", {})
    if isinstance(outcome, dict):
        outcome_result = outcome.get("result", "")
        outcome_reason = outcome.get("reason", "")
    else:
        outcome_result = ""
        outcome_reason = ""
    mapped_outcome = OUTCOME_MAP.get(outcome_result, outcome_result.lower())

    actor = raw.get("actor", raw.get("user", {}))
    if isinstance(actor, dict):
        username = actor.get("alternateId", actor.get("email", actor.get("username", "")))
        actor_id = actor.get("id", "")
        actor_type = actor.get("type", "")
    else:
        username = ""
        actor_id = ""
        actor_type = ""

    client = raw.get("client", {})
    if isinstance(client, dict):
        ip = client.get("ipAddress", client.get("ip_address", ""))
        user_agent = client.get("userAgent", {})
        if isinstance(user_agent, dict):
            ua_str = user_agent.get("rawUserAgent", user_agent.get("browser", ""))
        else:
            ua_str = str(user_agent) if user_agent else ""
        geographical = client.get("geographical", client.get("geolocation", {}))
        if isinstance(geographical, dict):
            city = geographical.get("city", "")
            state = geographical.get("state", "")
            country = geographical.get("country", "")
        else:
            city = state = country = ""
    else:
        ip = ""
        ua_str = ""
        city = state = country = ""

    context = _parse_context({"request": client} if client else {})

    targets = _parse_targets(raw.get("target", raw.get("targets", [])))

    severity = "high" if mapped_type in HIGH_SEVERITY_EVENTS else "medium" if outcome_result == "FAILURE" else "low"

    ts = raw.get("published", raw.get("timestamp", raw.get("time", "")))
    if ts:
        try:
            dt_str = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(dt_str)
            ts = dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError) as exc:
            log.debug("Invalid Okta timestamp: %s — %s", ts, exc)

    display_message = raw.get("displayMessage", raw.get("display_message", raw.get("message", "")))

    severity = raw.get("severity", severity)

    target_info = targets[0] if targets else {}

    return {
        "event_type": mapped_type,
        "severity": severity,
        "outcome": mapped_outcome,
        "outcome_reason": outcome_reason,
        "user": username,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "source_ip": ip,
        "target": target_info.get("alternate_id", ""),
        "target_type": target_info.get("type", ""),
        "timestamp": ts,
        "message": display_message or f"Okta {mapped_type}: {username} -> {mapped_outcome}",
        "metadata": {
            "user_agent": ua_str,
            "city": city,
            "state": state,
            "country": country,
            "device": context.get("device", ""),
            "target_id": target_info.get("id", ""),
            "target_display_name": target_info.get("display_name", ""),
            "all_targets": targets,
            "event_type_raw": event_type_raw,
            "actor_id": actor_id,
        },
    }


PARSER_REGISTRY_KEY = "okta"
