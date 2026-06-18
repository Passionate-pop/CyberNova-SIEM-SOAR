"""
CyberNova — DLQ Management API
View and replay failed events.
"""
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

log = logging.getLogger("cybernova.dlq")

from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser

router = APIRouter(prefix="/api/v1/admin/dlq", tags=["DLQ Management"])


class DLQEvent(BaseModel):
    original_id: str
    data: dict
    error: str
    failed_at: str


class DLQReplayResponse(BaseModel):
    success: bool
    message: str


@router.get("", response_model=List[DLQEvent], summary="Get DLQ events")
async def get_dlq_events(
    user: CurrentUser = Depends(get_current_user),
):
    """Get all events in the dead letter queue."""
    
    try:
        from cybernova.database.redis import get_redis
        redis = await get_redis()
        
        events = await redis.xrange("cybernova:dead_letter", min="0", max="+", count=100)
        
        return [
            DLQEvent(
                original_id=fields.get("original_id", ""),
                data=fields.get("data", {}),
                error=fields.get("error", ""),
                failed_at=fields.get("failed_at", ""),
            )
            for _msg_id, fields in events
        ]
    except Exception as e:
        log.warning("[DLQ] Failed to fetch DLQ events: %s", e)
        return []


@router.post("/replay", response_model=DLQReplayResponse, summary="Replay DLQ event")
async def replay_dlq_event(
    original_id: str,
    user: CurrentUser = Depends(get_current_user),
):
    """Replay a specific event from the DLQ."""
    
    try:
        from cybernova.database.redis import get_redis
        redis = await get_redis()
        
        events = await redis.xrange("cybernova:dead_letter", min="0", max="+", count=100)
        
        for msg_id, fields in events:
            if fields.get("original_id") == original_id:
                import json
                import logging
                _log = logging.getLogger("cybernova.dlq")
                raw_data = json.loads(fields.get("data", "{}"))
                _log.info("[DLQ] Replaying event %s to pipeline", original_id)

                from cybernova.pipeline.queue_manager import queue_manager, QueueName, QueuePriority
                from cybernova.config.settings import get_settings
                settings = get_settings()
                tenant_id = fields.get("tenant_id", "default")
                await queue_manager.enqueue(
                    QueueName.NORMALIZATION,
                    {
                        "event_type": "dlq_replay",
                        "data": raw_data,
                        "tenant_id": tenant_id,
                    },
                    priority=QueuePriority.HIGH,
                )
                
                await redis.xdel("cybernova:dead_letter", msg_id)
                
                return DLQReplayResponse(
                    success=True,
                    message=f"Event {original_id} replayed successfully"
                )
        
        raise HTTPException(status_code=404, detail="Event not found in DLQ")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to replay: {str(e)}")


@router.post("/clear", response_model=DLQReplayResponse, summary="Clear DLQ")
async def clear_dlq(
    user: CurrentUser = Depends(get_current_user),
):
    """Clear all events from DLQ (dangerous!)."""
    
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    try:
        from cybernova.database.redis import get_redis
        redis = await get_redis()
        
        await redis.delete("cybernova:dead_letter")
        
        return DLQReplayResponse(
            success=True,
            message="DLQ cleared successfully"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear DLQ: {str(e)}")