"""Tests for the pipeline — verifies queue priority and event stage handling."""
from __future__ import annotations
import pytest
from cybernova.pipeline.queue_manager import QueuePriority, QueueName
from cybernova.pipeline.stages import (
    PipelineStage, NormalizationStage, EnrichmentStage,
    DetectionStage, CorrelationStage, AlertStage, SOARStage,
)


@pytest.mark.asyncio
async def test_queue_priority_ordering():
    assert QueuePriority.CRITICAL.value < QueuePriority.HIGH.value
    assert QueuePriority.HIGH.value < QueuePriority.NORMAL.value
    assert QueuePriority.NORMAL.value < QueuePriority.LOW.value


@pytest.mark.asyncio
async def test_pipeline_stages_hierarchy():
    """Verify all stage classes extend PipelineStage."""
    assert issubclass(NormalizationStage, PipelineStage)
    assert issubclass(EnrichmentStage, PipelineStage)
    assert issubclass(DetectionStage, PipelineStage)
    assert issubclass(CorrelationStage, PipelineStage)
    assert issubclass(AlertStage, PipelineStage)
    assert issubclass(SOARStage, PipelineStage)


@pytest.mark.asyncio
async def test_pipeline_stage_names():
    """Verify stage instance names."""
    assert NormalizationStage().name == "normalization"
    assert EnrichmentStage().name == "enrichment"
    assert DetectionStage().name == "detection"
    assert CorrelationStage().name == "correlation"
    assert AlertStage().name == "alert"
    assert SOARStage().name == "soar"
