"""
CyberNova — AI Base: LLM Provider
Pluggable LLM interface supporting local models only (Ollama/LM Studio).
Free and open-source — no paid API calls.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List

log = logging.getLogger("cybernova.ai.base")


class LLMProvider(ABC):
    """Abstract LLM provider interface."""

    @abstractmethod
    async def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.3) -> str:
        ...

    @abstractmethod
    async def embed(self, text: str) -> List[float]:
        ...


class LocalProvider(LLMProvider):
    """Local fallback provider (no external API calls)."""

    async def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.3) -> str:
        analysis = []
        prompt_lower = prompt.lower()
        if "brute" in prompt_lower or "auth" in prompt_lower:
            analysis.append("Account lockout policy review recommended.")
        if "malware" in prompt_lower:
            analysis.append("Host isolation and forensic imaging recommended.")
        if "exfil" in prompt_lower or "transfer" in prompt_lower:
            analysis.append("DLP policy enforcement recommended.")
        if not analysis:
            analysis.append("Standard investigation procedures apply.")
        return " ".join(analysis)

    async def embed(self, text: str) -> List[float]:
        import hashlib
        h = hashlib.sha256(text.encode()).digest()
        return [b / 255.0 for b in h[:384]] + [0.0] * max(0, 384 - len(h))


def get_llm_provider() -> LLMProvider:
    return LocalProvider()
