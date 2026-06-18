"""
CyberNova — Response Router
Built-in SOAR actions + external SOAR dispatch via webhook.
  POST /api/v1/response/process                  — Batch-process pending alerts
  POST /api/v1/response/execute/{action_id}      — Execute action (built-in or webhook)
  GET  /api/v1/response/actions                  — List actions
  GET  /api/v1/response/actions/{action_id}      — Debug: full action detail
  GET  /api/v1/response/playbooks                — List playbooks
  POST /api/v1/response/webhook                  — Execute pending action
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.database.repository.repositories import ResponseActionRepository
from cybernova.response.policy_engine.playbooks import PLAYBOOKS
from cybernova.response.services.automation_service import automation_service
from cybernova.schemas.response_schema import (
    ActionDetailResponse,
    ActionResponse,
)
from cybernova.security.encryption.jwt_handler import CurrentUser, get_current_user
from cybernova.api.dependencies.tenant import get_tenant_id

log = logging.getLogger("cybernova.response.router")

router = APIRouter(prefix="/api/v1/response", tags=["Response / SOAR"])


@router.post("/process", summary="Process pending alerts through SOAR")
async def process_pending(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    count = await automation_service.process_pending_alerts(db, tenant_id, limit)
    return {"actions_created": count}


@router.post("/execute/{action_id}", summary="Dispatch action (built-in or external webhook)")
async def execute_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    action = await automation_service.execute_action(action_id, db, tenant_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    return ActionResponse.model_validate(action)


@router.get("/actions", summary="List response actions")
async def list_actions(
    status: Optional[str] = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    repo = ResponseActionRepository(db, tenant_id)
    filters = {"status": status} if status else None
    actions = await repo.list_all(limit=limit, filters=filters)
    return {"actions": [ActionResponse.model_validate(a) for a in actions]}


@router.get("/actions/{action_id}", summary="Get full action detail (debug)")
async def get_action_detail(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    repo = ResponseActionRepository(db, tenant_id)
    action = await repo.get_by_id(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    return ActionDetailResponse.model_validate(action)


@router.get("/playbooks", summary="List response playbooks")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.database.postgres.models import Playbook as PlaybookModel
    from sqlalchemy import select

    result = await db.execute(
        select(PlaybookModel).where(PlaybookModel.tenant_id == tenant_id).order_by(PlaybookModel.priority)
    )
    db_playbooks = result.scalars().all()

    if not db_playbooks:
        from cybernova.core.utils.helpers import utcnow
        from sqlalchemy.exc import IntegrityError
        seed = []
        for pb in PLAYBOOKS:
            p = PlaybookModel(
                id=pb["id"],
                tenant_id=tenant_id,
                name=pb["name"],
                priority=pb.get("priority", 5),
                severity_action=pb.get("severity_action", "ui_only"),
                condition=pb.get("condition", {}),
                actions=pb.get("actions", []),
                automated=pb.get("automated", False),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            db.add(p)
            seed.append(p)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            log.debug("Playbook seed skipped — some already exist for tenant %s", tenant_id)
            # Re-query to return whatever actually exists
            result = await db.execute(
                select(PlaybookModel).where(PlaybookModel.tenant_id == tenant_id).order_by(PlaybookModel.priority)
            )
            db_playbooks = result.scalars().all()
        else:
            db_playbooks = seed

    return {
        "playbooks": [
            {
                "id": p.id,
                "name": p.name,
                "priority": p.priority,
                "severity_action": p.severity_action,
                "condition": p.condition or {},
                "actions": p.actions or [],
                "automated": p.automated,
            }
            for p in db_playbooks
        ]
    }


@router.post("/playbooks", summary="Create a new playbook")
async def create_playbook(
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.database.postgres.models import Playbook as PlaybookModel
    from cybernova.core.utils.helpers import utcnow

    playbook = PlaybookModel(
        id=body.get("id", f"pb_{int(utcnow().timestamp())}"),
        tenant_id=tenant_id,
        name=body.get("name", "Untitled Playbook"),
        priority=body.get("priority", 5),
        severity_action=body.get("severity_action", "ui_only"),
        condition=body.get("condition", {}),
        actions=body.get("actions", []),
        automated=body.get("automated", False),
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(playbook)
    await db.commit()
    return {
        "id": playbook.id,
        "name": playbook.name,
        "priority": playbook.priority,
        "severity_action": playbook.severity_action,
        "condition": playbook.condition or {},
        "actions": playbook.actions or [],
        "automated": playbook.automated,
    }


@router.put("/playbooks/{playbook_id}", summary="Update a playbook")
async def update_playbook(
    playbook_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.database.postgres.models import Playbook as PlaybookModel
    from sqlalchemy import select
    from cybernova.core.utils.helpers import utcnow

    result = await db.execute(
        select(PlaybookModel).where(PlaybookModel.id == playbook_id, PlaybookModel.tenant_id == tenant_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if "name" in body:
        playbook.name = body["name"]
    if "priority" in body:
        playbook.priority = body["priority"]
    if "severity_action" in body:
        playbook.severity_action = body["severity_action"]
    if "condition" in body:
        playbook.condition = body["condition"]
    if "actions" in body:
        playbook.actions = body["actions"]
    if "automated" in body:
        playbook.automated = body["automated"]
    playbook.updated_at = utcnow()
    await db.commit()
    return {"success": True, "id": playbook.id}


@router.delete("/playbooks/{playbook_id}", summary="Delete a playbook")
async def delete_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    from cybernova.database.postgres.models import Playbook as PlaybookModel
    from sqlalchemy import select

    result = await db.execute(
        select(PlaybookModel).where(PlaybookModel.id == playbook_id, PlaybookModel.tenant_id == tenant_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await db.delete(playbook)
    await db.commit()
    return {"success": True}


@router.post(
    "/webhook",
    summary="Dispatch a pending response action",
    description="Executes a pending SOAR action locally.",
)
async def webhook_dispatch(
    action_id: str = Query(..., description="Action ID to execute"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    action = await automation_service.execute_action(action_id, db, tenant_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    return {
        "executed": action.status in ("completed", "success"),
        "action_id": action.id,
        "status": action.status,
    }
