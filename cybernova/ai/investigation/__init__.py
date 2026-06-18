"""
CyberNova — AI Investigation Service
AI-powered incident investigation and threat analysis.
"""
from __future__ import annotations

import logging
import asyncio
from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import Alert, Incident
from cybernova.ai.base import get_llm_provider

log = logging.getLogger("cybernova.ai.investigation")


class InvestigationService:

    async def investigate_alert(self, alert_id: str, db: AsyncSession, tenant_id: str) -> Dict[str, Any]:
        result = await db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
        )
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found", "alert_id": alert_id}

        provider = get_llm_provider()
        prompt = self._build_alert_prompt(alert)
        try:
            analysis = await asyncio.wait_for(provider.generate(prompt), timeout=15.0)
        except asyncio.TimeoutError:
            analysis = "Investigation aborted: AI provider timed out."
        except Exception:
            analysis = "Investigation failed due to AI system error."

        return {
            "alert_id": alert_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "description": alert.description or "",
            "analysis": analysis,
            "recommendations": self._extract_recommendations(analysis),
            "confidence": 0.85,
        }

    async def investigate_incident(self, incident_id: str, db: AsyncSession, tenant_id: str) -> Dict[str, Any]:
        result = await db.execute(
            select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
        )
        incident = result.scalar_one_or_none()
        if not incident:
            return {"error": "Incident not found", "incident_id": incident_id}

        provider = get_llm_provider()
        prompt = self._build_incident_prompt(incident)
        try:
            analysis = await asyncio.wait_for(provider.generate(prompt, max_tokens=1024), timeout=25.0)
        except asyncio.TimeoutError:
            analysis = "Investigation aborted: AI provider timed out. Proceed with manual triage."
        except Exception:
            analysis = "Investigation failed due to AI system error."

        return {
            "incident_id": incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "description": incident.description or "",
            "analysis": analysis,
            "confidence": 0.85,
        }

    def _build_alert_prompt(self, alert: Alert) -> str:
        return (
            f"You are a senior cybersecurity analyst. Investigate this security alert.\n\n"
            f"Alert Rule: {alert.rule_name}\n"
            f"Severity: {alert.severity}\n"
            f"Risk Score: {alert.risk_score}/100\n"
            f"Description: {alert.description or 'No description available'}\n"
            f"Device ID: {alert.device_id or 'Unknown'}\n"
            f"Alert ID: {alert.id}\n\n"
            f"Provide: (1) Root cause hypothesis, (2) Recommended immediate actions, "
            f"(3) Long-term mitigation steps. Be concise and actionable."
        )

    def _build_incident_prompt(self, incident: Incident) -> str:
        return (
            f"You are a senior cybersecurity analyst. Investigate this security incident.\n\n"
            f"Incident Title: {incident.title}\n"
            f"Severity: {incident.severity}\n"
            f"Risk Score: {incident.risk_score}/100\n"
            f"Escalation Level: {incident.escalation_level}\n"
            f"Description: {incident.description or 'No description available'}\n"
            f"Incident ID: {incident.id}\n\n"
            f"Provide: (1) Full attack narrative, (2) Root cause analysis, "
            f"(3) MITRE ATT&CK technique mapping, (4) Recommended response actions, "
            f"(5) Timeline reconstruction. Be thorough and precise."
        )

    @staticmethod
    def _extract_recommendations(analysis: str) -> list:
        lines = analysis.split(".")
        return [line.strip() for line in lines if len(line.strip()) > 10][:5]


investigation_service = InvestigationService()
