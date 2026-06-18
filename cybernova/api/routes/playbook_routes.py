"""
CyberNova — Playbook Status Reporting API
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import (
    require_automation_trigger, require_automation_view,
)
from cybernova.response.automation.engine import playbook_engine
from cybernova.response.automation.models import ExecutionStatus

log = logging.getLogger("cybernova.api.routes.playbook_routes")
router = APIRouter(prefix="/api/v1/playbook-routes", tags=["Playbook Status"])


@router.get("/executions", summary="List executions with filtering and pagination")
async def list_executions(
    status: Optional[str] = Query(None, description="Filter by status: running, completed, failed, cancelled"),
    playbook_id: Optional[str] = Query(None, description="Filter by playbook ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require_automation_view),
):
    executions = playbook_engine.list_executions_filtered(
        status=status,
        playbook_id=playbook_id,
        limit=limit,
        offset=offset,
    )
    result = []
    for e in executions:
        result.append({
            "id": e.id,
            "playbook_id": e.playbook_id,
            "playbook_name": e.playbook_name,
            "trigger": e.trigger.value if e.trigger else "",
            "status": e.status.value if isinstance(e.status, ExecutionStatus) else e.status,
            "current_step_id": e.current_step_id,
            "retry_count": e.retry_count,
            "max_retries": e.max_retries,
            "error": e.error,
            "created_at": e.created_at,
            "completed_at": e.completed_at,
        })
    total = len(playbook_engine.list_executions())
    return {
        "executions": result,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/executions/{execution_id}", summary="Get full execution detail with progress")
async def get_execution_detail(
    execution_id: str,
    user: CurrentUser = Depends(require_automation_view),
):
    progress = playbook_engine.get_execution_progress(execution_id)
    if not progress:
        raise HTTPException(status_code=404, detail="Execution not found")
    return progress


@router.get("/executions/{execution_id}/steps", summary="Get step-level execution details")
async def get_execution_steps(
    execution_id: str,
    user: CurrentUser = Depends(require_automation_view),
):
    execution = playbook_engine.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    return {
        "execution_id": execution.id,
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
    }


@router.post("/executions/{execution_id}/retry", summary="Retry a failed execution")
async def retry_execution(
    execution_id: str,
    user: CurrentUser = Depends(require_automation_trigger),
):
    execution = playbook_engine.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    if execution.status != ExecutionStatus.FAILED:
        raise HTTPException(status_code=400, detail=f"Cannot retry execution with status '{execution.status.value}'")
    if execution.retry_count >= execution.max_retries:
        raise HTTPException(status_code=400, detail=f"Execution has exceeded max retries ({execution.max_retries})")
    new_id = await playbook_engine.retry_execution(execution_id)
    if not new_id:
        raise HTTPException(status_code=500, detail="Retry failed")
    return {"execution_id": new_id, "status": "retrying", "retry_count": execution.retry_count}


@router.post("/executions/{execution_id}/cancel", summary="Cancel a running execution")
async def cancel_execution(
    execution_id: str,
    user: CurrentUser = Depends(require_automation_trigger),
):
    execution = playbook_engine.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    ok = await playbook_engine.cancel_execution(execution_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Execution cannot be cancelled (not running)")
    return {"execution_id": execution_id, "status": "cancelled"}


@router.get("/executions/{execution_id}/timeline", summary="Get execution timeline")
async def get_execution_timeline(
    execution_id: str,
    user: CurrentUser = Depends(require_automation_view),
):
    execution = playbook_engine.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    timeline = []
    if execution.created_at:
        timeline.append({"event": "started", "timestamp": execution.created_at})
    for s in execution.steps:
        if s.started_at:
            timeline.append({
                "event": f"step_started: {s.step_name}",
                "step_id": s.step_id,
                "timestamp": s.started_at,
            })
        if s.completed_at:
            timeline.append({
                "event": f"step_{s.status.value}: {s.step_name}",
                "step_id": s.step_id,
                "timestamp": s.completed_at,
                "status": s.status.value,
                "error": s.error,
            })
    if execution.completed_at:
        timeline.append({"event": f"finished: {execution.status.value}", "timestamp": execution.completed_at})
    timeline.sort(key=lambda x: x["timestamp"])
    return {"execution_id": execution_id, "timeline": timeline}
