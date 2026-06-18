"""
CyberNova — GitHub Audit Log Parser
Parses GitHub audit log events from the Audit Log API.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.github_audit")

HIGH_RISK_ACTIONS = {
    "repo.create", "repo.destroy", "repo.transfer",
    "repo.add_member", "repo.remove_member",
    "org.add_member", "org.remove_member",
    "org.update_member", "org.restore_member",
    "team.create", "team.destroy",
    "org.update_default_repository_permission",
    "org.oauth_app_access_deny",
    "org.oauth_app_access_approve",
    "repo.config.disable_anonymous_git_access",
    "repo.config.enable_anonymous_git_access",
    "actions.update_org_secret",
    "actions.remove_org_secret",
    "actions.create_org_secret",
    "secret_scanning.push_protection_bypass",
    "branch_protection_config.destroy",
    "branch_protection_config.create",
    "branch_protection_config.update",
    "dependabot_alerts_disable",
    "repo.archived", "repo.unarchived",
}

MEDIUM_RISK_ACTIONS = {
    "repo.push", "repo.pull_request",
    "repo.deploy_key.create", "repo.deploy_key.destroy",
    "repo.invite", "repo.add_collaborator",
    "team.add_member", "team.remove_member",
    "org.invite_member", "org.cancel_invitation",
    "webhook.create", "webhook.destroy", "webhook.update",
    "repo_secret.created", "repo_secret.removed",
    "org_secret.created", "org_secret.removed",
    "actions.update_org_variable",
    "actions.create_org_variable",
    "actions.remove_org_variable",
    "org.credential_authorization",
    "repo.add_collaborator",
}


def _classify_gh_severity(action: str) -> str:
    if action in HIGH_RISK_ACTIONS:
        return "high"
    if action in MEDIUM_RISK_ACTIONS:
        return "medium"
    sensitive_prefixes = {"org.", "repo.", "team.", "actions.", "secret_", "branch_", "dependabot_"}
    for prefix in sensitive_prefixes:
        if action.startswith(prefix):
            return "medium"
    return "low"


def _parse_gh_user(data: Dict[str, Any]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for key in ("actor", "user", "performed_via_github_app"):
        val = data.get(key, data.get(f"{key}_id", ""))
        if isinstance(val, dict):
            result["login"] = val.get("login", "")
            result["id"] = str(val.get("id", ""))
            result["type"] = val.get("type", "")
        elif isinstance(val, str) and val:
            result[key] = val
    return result


def parse_github_audit_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except (ValueError, _json.JSONDecodeError) as exc:
            log.debug("GitHub audit JSON parse failed: %s", exc)
            return {"event_type": "github_audit", "severity": "info", "message": raw}
    if not isinstance(raw, dict):
        return {"event_type": "github_audit", "severity": "info", "message": str(raw)}

    action = raw.get("action", raw.get("@type", "unknown"))
    ts_raw = raw.get("@timestamp", raw.get("timestamp", raw.get("time", raw.get("created_at", ""))))
    actor = raw.get("actor", raw.get("actor_name", raw.get("user", "")))
    repo = raw.get("repo", raw.get("repository", raw.get("repository_public", "")))
    org = raw.get("org", raw.get("organization", ""))
    user_info = _parse_gh_user(raw)

    severity = _classify_gh_severity(action)

    data = raw.get("data", raw.get("payload", {}))
    if not isinstance(data, dict):
        data = {}

    ts = ""
    if ts_raw:
        try:
            dt_str = ts_raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(dt_str)
            ts = dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError) as exc:
            log.debug("Invalid GitHub audit timestamp: %s — %s", ts_raw, exc)
            ts = ts_raw

    source_ip = raw.get("source_ip", raw.get("ip", raw.get("actor_ip", "")))

    return {
        "event_type": "github_audit",
        "severity": severity,
        "action": action,
        "user": actor,
        "actor_login": user_info.get("login", ""),
        "repository": repo,
        "organization": org,
        "source_ip": source_ip,
        "timestamp": ts,
        "message": f"GitHub: {actor} performed {action} on {repo or org or 'unknown'}",
        "metadata": {
            "actor_id": user_info.get("id", ""),
            "actor_type": user_info.get("type", ""),
            "data": data,
            "user_agent": raw.get("user_agent", raw.get("agent", "")),
            "business": raw.get("business", ""),
            "hashed_token": raw.get("hashed_token", ""),
            "token_id": raw.get("token_id", ""),
            "visibility": raw.get("visibility", ""),
        },
    }


PARSER_REGISTRY_KEY = "github_audit"
