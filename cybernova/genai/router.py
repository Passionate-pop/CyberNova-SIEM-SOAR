from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_pipeline_view
from cybernova.genai.investigator import genai_investigator

log = logging.getLogger("cybernova.genai.router")
router = APIRouter(prefix="/api/v1/ai", tags=["GenAI SOC Assistant"])


@router.post("/triage/alert", summary="AI-powered alert triage")
async def triage_alert(
    alert: Dict[str, Any],
    user: CurrentUser = Depends(require_pipeline_view),
):
    result = await genai_investigator.triage_alert(alert)
    return result


@router.post("/investigate/incident", summary="AI-powered incident investigation")
async def investigate_incident(
    incident: Dict[str, Any],
    alerts: List[Dict[str, Any]] = [],
    user: CurrentUser = Depends(require_pipeline_view),
):
    result = await genai_investigator.investigate_incident(incident, alerts)
    return result


@router.post("/ask", summary="Ask a natural language security question")
async def ask_question(
    query: str,
    context: Optional[Dict[str, Any]] = None,
    user: CurrentUser = Depends(require_pipeline_view),
):
    if not query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    answer = await genai_investigator.natural_language_query(query, context)
    return {"query": query, "answer": answer}


@router.post("/threat-hunt/summarize", summary="AI threat hunt summary")
async def summarize_threat_hunt(
    hunt_results: Dict[str, Any],
    user: CurrentUser = Depends(require_pipeline_view),
):
    summary = await genai_investigator.summarize_threat_hunt(hunt_results)
    return {"summary": summary}


@router.post("/report", summary="Generate AI security report")
async def generate_report(
    report_type: str,
    data: Dict[str, Any],
    user: CurrentUser = Depends(require_pipeline_view),
):
    valid_types = ["executive", "incident", "threat_hunt", "compliance", "daily"]
    if report_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid type: {report_type}. Valid: {valid_types}")
    report = await genai_investigator.generate_report(report_type, data)
    return {"type": report_type, "report": report}
