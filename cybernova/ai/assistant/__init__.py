"""
CyberNova — AI Assistant Service
Interactive security assistant for SOC analysts.
"""
from __future__ import annotations

import logging
import asyncio
from typing import Any, Dict, List

from cybernova.ai.base import get_llm_provider

log = logging.getLogger("cybernova.ai.assistant")


class AssistantService:
    """Context-aware security assistant."""

    async def ask(self, question: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        provider = get_llm_provider()
        ctx = f"Context: {context}" if context else ""
        prompt = f"As a cybersecurity analyst assistant, answer: {question}. {ctx}"
        try:
            answer = await asyncio.wait_for(provider.generate(prompt, max_tokens=768), timeout=10.0)
        except asyncio.TimeoutError:
            log.warning("AI Assistant timed out. Serving fallback.")
            answer = "Sorry, the AI system is currently experiencing high latency. Investigation procedures still apply."
        except Exception as exc:
            log.error(f"AI Assistant error: {exc}")
            answer = "Error generating response."
        return {"question": question, "answer": answer}

    async def summarize_alerts(self, alerts_data: List[Dict[str, Any]]) -> str:
        provider = get_llm_provider()
        summary_input = "\n".join(
            f"- {a.get('rule_name', 'unknown')}: severity={a.get('severity', 'unknown')}, risk={a.get('risk_score', 0)}"
            for a in alerts_data[:20]
        )
        prompt = f"Summarize these security alerts and identify patterns:\n{summary_input}"
        try:
            return await asyncio.wait_for(provider.generate(prompt), timeout=15.0)
        except asyncio.TimeoutError:
            return "Alert summary unavailable due to AI timeout."


assistant_service = AssistantService()
