from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.genai.investigator")


class GenAISOCInvestigator:
    """
    GenAI-powered SOC assistant for alert triage, incident investigation,
    natural-language queries, and remediation recommendations.
    Uses local LLM only (Ollama/LM Studio) — $0, no paid API calls.
    """

    def __init__(self):
        self._model = None
        self._api_url = None

    async def initialize(self):
        settings = get_settings()
        self._model = getattr(settings, "embedding_model", "all-MiniLM-L6-v2")
        self._api_url = "http://localhost:11434/api/generate"
        log.info("GenAI SOC investigator initialized (local LLM only, model: %s)", self._model)

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        try:
            import aiohttp
            payload = {
                "model": self._model,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "stream": False,
                "temperature": 0.3,
                "max_tokens": 2000,
            }

            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self._api_url, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "")
                    log.warning("LLM API returned %d: %s", resp.status, await resp.text())
                    return ""
        except Exception as e:
            log.error("LLM call failed (is Ollama running on localhost:11434?): %s", e)
            return ""

    async def triage_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered alert triage: classify severity, suggest priority, recommend actions."""
        system_prompt = (
            "You are a SOC analyst AI assistant. Analyze the security alert and provide:\n"
            "1. severity_level (critical/high/medium/low/info)\n"
            "2. confidence_score (0-100)\n"
            "3. brief_analysis (2-3 sentences)\n"
            "4. recommended_actions (list of actionable steps)\n"
            "5. mitre_attack_mapping (tactic and technique if identifiable)\n"
            "Return as JSON only."
        )

        user_prompt = f"Alert details:\n{json.dumps(alert, indent=2, default=str)}"

        response = await self._call_llm(system_prompt, user_prompt)
        try:
            result = json.loads(response)
            result["alert_id"] = alert.get("id", alert.get("alert_id", "unknown"))
            return result
        except (json.JSONDecodeError, TypeError):
            return {
                "alert_id": alert.get("id", alert.get("alert_id", "unknown")),
                "severity_level": alert.get("severity", "medium"),
                "confidence_score": 50,
                "brief_analysis": "Automatic analysis unavailable (is Ollama running?)",
                "recommended_actions": ["Review alert manually"],
                "raw_response": response,
            }

    async def investigate_incident(self, incident: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """AI-powered incident investigation: root cause, timeline, impact assessment."""
        system_prompt = (
            "You are a senior incident responder AI. Analyze the security incident "
            "and associated alerts. Provide:\n"
            "1. root_cause (one sentence)\n"
            "2. incident_timeline (key events in order)\n"
            "3. impact_assessment (systems, data, users affected)\n"
            "4. containment_steps (immediate actions)\n"
            "5. remediation_plan (step-by-step)\n"
            "6. ioc_extracted (list of IPs, domains, hashes involved)\n"
            "7. severity_assessment (critical/high/medium/low)\n"
            "Be specific and actionable."
        )

        user_prompt = (
            f"Incident: {json.dumps(incident, indent=2, default=str)}\n\n"
            f"Associated Alerts ({len(alerts)}):\n"
            f"{json.dumps(alerts[:20], indent=2, default=str)}"
        )

        response = await self._call_llm(system_prompt, user_prompt)

        return {
            "incident_id": incident.get("id", "unknown"),
            "analysis": response,
            "alert_count": len(alerts),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def natural_language_query(self, query: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Natural language query about the security posture or events."""
        system_prompt = (
            "You are a cybersecurity AI assistant. Answer the analyst's question "
            "using the provided context. Be specific, cite data when possible, "
            "and suggest actionable next steps."
        )

        context_str = f"\nContext:\n{json.dumps(context, indent=2, default=str)}" if context else ""
        user_prompt = f"Question: {query}{context_str}"

        return await self._call_llm(system_prompt, user_prompt)

    async def summarize_threat_hunt(self, hunt_results: Dict[str, Any]) -> str:
        """AI-powered summary of threat hunting results."""
        system_prompt = (
            "You are a threat hunting AI. Summarize the hunting results, "
            "highlight key findings, and recommend follow-up hunts."
        )

        user_prompt = f"Hunt results:\n{json.dumps(hunt_results, indent=2, default=str)}"
        return await self._call_llm(system_prompt, user_prompt)

    async def generate_report(self, report_type: str, data: Dict[str, Any]) -> str:
        """Generate a natural language security report."""
        system_prompt = (
            f"You are a security reporting AI. Generate a {report_type} report "
            "in natural language. Include key metrics, trends, and recommendations."
        )
        user_prompt = json.dumps(data, indent=2, default=str)
        return await self._call_llm(system_prompt, user_prompt)


genai_investigator = GenAISOCInvestigator()
