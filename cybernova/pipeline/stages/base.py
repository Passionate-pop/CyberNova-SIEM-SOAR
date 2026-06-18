"""
CyberNova — Base Pipeline Stage
Every pipeline stage extends this class with a consistent lifecycle.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from cybernova.pipeline.bus import PipelineEnvelope

log = logging.getLogger("cybernova.pipeline.stage")


class PipelineStage(ABC):
    """Base class for all pipeline processing stages."""

    def __init__(self, name: str):
        self.name = name
        self._next_stage: Optional[str] = None

    @abstractmethod
    async def process(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        ...

    def set_next(self, stage: str) -> None:
        self._next_stage = stage

    async def handle(self, envelope: PipelineEnvelope) -> Optional[PipelineEnvelope]:
        try:
            result = await self.process(envelope)
            if result is not None:
                result.previous_stage = self.name
                return result
            return None
        except Exception as e:
            log.error("Stage %s failed for event %s: %s", self.name, envelope.event_id, e)
            envelope.error = f"{self.name}: {e}"
            envelope.retry_count += 1
            if envelope.retry_count <= envelope.max_retries:
                return envelope
            return None

    async def run_in_executor(self, fn: Callable, *args: Any) -> Any:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn, *args)
