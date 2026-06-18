from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_admin, require_audit_view
from cybernova.abac.models import (
    ABACPolicy, AttributeCondition, AttributeSource,
    Effect, Operator,
)
from cybernova.abac.engine import abac_engine

log = logging.getLogger("cybernova.abac.router")
router = APIRouter(prefix="/api/v1/abac", tags=["ABAC"])


@router.get("/policies", summary="List ABAC policies")
async def list_policies(
    enabled_only: bool = Query(False),
    user: CurrentUser = Depends(require_audit_view),
):
    return {
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "effect": p.effect.value,
                "priority": p.priority,
                "enabled": p.enabled,
                "conditions": [
                    {
                        "source": c.source.value,
                        "key": c.key,
                        "operator": c.operator.value,
                        "value": c.value,
                    }
                    for c in p.conditions
                ],
            }
            for p in abac_engine.store.list_policies(enabled_only)
        ],
    }


@router.post("/policies", summary="Create ABAC policy")
async def create_policy(
    policy_data: Dict[str, Any],
    user: CurrentUser = Depends(require_admin),
):
    conditions = []
    for c in policy_data.get("conditions", []):
        conditions.append(AttributeCondition(
            source=AttributeSource(c["source"]),
            key=c["key"],
            operator=Operator(c["operator"]),
            value=c["value"],
        ))
    policy = ABACPolicy(
        id=policy_data["id"],
        name=policy_data["name"],
        description=policy_data.get("description", ""),
        effect=Effect(policy_data["effect"]),
        conditions=conditions,
        priority=policy_data.get("priority", 0),
        enabled=policy_data.get("enabled", True),
    )
    abac_engine.store.add_policy(policy)
    return {"created": True, "policy_id": policy.id}


@router.delete("/policies/{policy_id}", summary="Delete ABAC policy")
async def delete_policy(
    policy_id: str,
    user: CurrentUser = Depends(require_admin),
):
    if abac_engine.store.remove_policy(policy_id):
        return {"deleted": True, "policy_id": policy_id}
    raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/evaluate", summary="Evaluate ABAC policies against context")
async def evaluate_policies(
    context: Dict[str, Any],
    user: CurrentUser = Depends(require_audit_view),
):
    result = abac_engine.evaluate_from_dicts(
        user_attrs=context.get("user", {}),
        resource_attrs=context.get("resource", {}),
        action_attrs=context.get("action", {}),
        env_attrs=context.get("environment", {}),
    )
    return {
        "allowed": result.allowed,
        "reason": result.reason,
        "matched_policy": {
            "id": result.matched_policy.id,
            "name": result.matched_policy.name,
            "effect": result.matched_policy.effect.value,
        } if result.matched_policy else None,
    }


@router.get("/stats", summary="ABAC engine statistics")
async def abac_stats(
    user: CurrentUser = Depends(require_audit_view),
):
    return abac_engine.get_stats()
