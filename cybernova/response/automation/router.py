"""
CyberNova — Playbook Automation Router
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import (
    require_automation_trigger, require_automation_view,
)
from cybernova.response.automation.engine import playbook_engine
from cybernova.response.automation.models import (
    PlaybookDefinition, PlaybookStep, StepType, StepConfig,
    Condition, ConditionOperator, PlaybookTrigger,
)

log = logging.getLogger("cybernova.response.automation.router")
router = APIRouter(prefix="/api/v1/automation", tags=["Playbook Automation"])


class StepModel(BaseModel):
    id: str = ""
    name: str
    type: str
    config: Dict[str, Any] = {}
    next_on_success: Optional[str] = None
    next_on_failure: Optional[str] = None
    timeout_seconds: Optional[int] = None


class ConditionModel(BaseModel):
    field: str
    operator: str
    value: Any


class CreatePlaybookRequest(BaseModel):
    name: str
    description: str = ""
    trigger: str = "alert_created"
    enabled: bool = True
    priority: int = 5
    conditions: List[ConditionModel] = []
    steps: List[StepModel] = []


class UpdatePlaybookRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    conditions: Optional[List[ConditionModel]] = None
    steps: Optional[List[StepModel]] = None


class ApproveRequest(BaseModel):
    approval_id: str
    decision: str
    reason: str = ""


@router.get("/playbooks", summary="List playbooks")
async def list_playbooks(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_automation_view),
):
    playbooks = playbook_engine.list_playbooks(tenant_id)
    return {"playbooks": [p.to_dict() for p in playbooks]}


@router.post("/playbooks", summary="Create a playbook")
async def create_playbook(
    req: CreatePlaybookRequest,
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_automation_trigger),
):
    step_id_map = {}
    steps = []
    for i, s in enumerate(req.steps):
        sid = s.id or f"step_{uuid4().hex[:8]}"
        step_id_map[i] = sid
        try:
            st = StepType(s.type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid step type: {s.type}")
        steps.append(PlaybookStep(
            id=sid,
            name=s.name,
            type=st,
            config=StepConfig(**s.config),
            next_on_success=s.next_on_success,
            next_on_failure=s.next_on_failure,
            timeout_seconds=s.timeout_seconds,
        ))

    conditions = [
        Condition(field=c.field, operator=ConditionOperator(c.operator), value=c.value)
        for c in req.conditions
    ]

    try:
        trigger = PlaybookTrigger(req.trigger)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid trigger: {req.trigger}")

    playbook = PlaybookDefinition(
        id=str(uuid4()),
        name=req.name,
        description=req.description,
        trigger=trigger,
        enabled=req.enabled,
        priority=req.priority,
        tenant_id=tenant_id,
        conditions=conditions,
        steps=steps,
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )

    playbook_engine.register(playbook)
    return playbook.to_dict()


@router.get("/playbooks/{playbook_id}", summary="Get playbook detail")
async def get_playbook(
    playbook_id: str,
    user: CurrentUser = Depends(require_automation_view),
):
    playbook = playbook_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook.to_dict()


@router.put("/playbooks/{playbook_id}", summary="Update playbook")
async def update_playbook(
    playbook_id: str,
    req: UpdatePlaybookRequest,
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_automation_trigger),
):
    playbook = playbook_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if req.name is not None:
        playbook.name = req.name
    if req.description is not None:
        playbook.description = req.description
    if req.trigger is not None:
        try:
            playbook.trigger = PlaybookTrigger(req.trigger)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid trigger: {req.trigger}")
    if req.enabled is not None:
        playbook.enabled = req.enabled
    if req.priority is not None:
        playbook.priority = req.priority
    if req.conditions is not None:
        playbook.conditions = [Condition(field=c.field, operator=ConditionOperator(c.operator), value=c.value) for c in req.conditions]
    if req.steps is not None:
        steps = []
        for s in req.steps:
            sid = s.id or f"step_{uuid4().hex[:8]}"
            steps.append(PlaybookStep(
                id=sid,
                name=s.name,
                type=StepType(s.type),
                config=StepConfig(**s.config),
                next_on_success=s.next_on_success,
                next_on_failure=s.next_on_failure,
                timeout_seconds=s.timeout_seconds,
            ))
        playbook.steps = steps

    playbook.updated_at = datetime.now(timezone.utc).isoformat()
    playbook_engine.register(playbook)
    return playbook.to_dict()


@router.delete("/playbooks/{playbook_id}", summary="Delete playbook")
async def delete_playbook(
    playbook_id: str,
    user: CurrentUser = Depends(require_automation_trigger),
):
    playbook = playbook_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    playbook_engine.unregister(playbook_id)
    return {"deleted": True, "playbook_id": playbook_id}


@router.post("/playbooks/{playbook_id}/trigger", summary="Manually trigger a playbook")
async def trigger_playbook(
    playbook_id: str,
    context: Dict[str, Any],
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_automation_trigger),
):
    context["tenant_id"] = tenant_id
    execution_id = await playbook_engine.trigger(
        playbook_id, context, PlaybookTrigger.MANUAL
    )
    if not execution_id:
        raise HTTPException(status_code=400, detail="Playbook not found, disabled, or conditions not met")
    return {"execution_id": execution_id, "status": "triggered"}


@router.get("/executions", summary="List playbook executions")
async def list_executions(
    limit: int = Query(50, le=200),
    user: CurrentUser = Depends(require_automation_view),
):
    executions = playbook_engine.list_executions(limit)
    result = []
    for e in executions:
        result.append({
            "id": e.id,
            "playbook_id": e.playbook_id,
            "playbook_name": e.playbook_name,
            "trigger": e.trigger.value if e.trigger else "",
            "status": e.status,
            "steps": [{"step_id": s.step_id, "step_name": s.step_name, "status": s.status.value} for s in e.steps],
            "created_at": e.created_at,
            "completed_at": e.completed_at,
            "error": e.error,
        })
    return {"executions": result}


@router.get("/executions/{execution_id}", summary="Get execution detail")
async def get_execution(
    execution_id: str,
    user: CurrentUser = Depends(require_automation_view),
):
    execution = playbook_engine.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    return {
        "id": execution.id,
        "playbook_id": execution.playbook_id,
        "playbook_name": execution.playbook_name,
        "trigger": execution.trigger.value if execution.trigger else "",
        "status": execution.status,
        "context": execution.context,
        "steps": [
            {
                "step_id": s.step_id,
                "step_name": s.step_name,
                "type": s.step_type.value if s.step_type else "",
                "status": s.status.value,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "result": s.result,
                "error": s.error,
            }
            for s in execution.steps
        ],
        "created_at": execution.created_at,
        "completed_at": execution.completed_at,
        "error": execution.error,
    }


@router.get("/approvals", summary="List pending approvals")
async def list_approvals(
    user: CurrentUser = Depends(require_automation_view),
):
    return {"approvals": playbook_engine.get_pending_approvals()}


@router.post("/approvals/respond", summary="Approve or reject a pending action")
async def respond_approval(
    req: ApproveRequest,
    user: CurrentUser = Depends(require_automation_trigger),
):
    if req.decision == "approve":
        ok = await playbook_engine.approve(req.approval_id, user.username)
    elif req.decision == "reject":
        ok = await playbook_engine.reject(req.approval_id, user.username, req.reason)
    else:
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'reject'")
    if not ok:
        raise HTTPException(status_code=404, detail="Approval not found or already processed")
    return {"status": req.decision, "approval_id": req.approval_id}
