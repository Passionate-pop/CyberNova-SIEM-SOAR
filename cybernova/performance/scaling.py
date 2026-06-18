"""
CyberNova — Batch Processing & Scaling Utilities
Optimizes ingestion batching, parallel processing, and resource utilization.
"""
import asyncio
import logging
import os
from typing import Any, Callable, List, Optional, TypeVar

log = logging.getLogger("cybernova.performance.scaling")

T = TypeVar("T")
R = TypeVar("R")


def optimal_batch_size(memory_per_item_bytes: int = 1024, target_memory_mb: int = 64) -> int:
    """Calculate optimal batch size based on available memory."""
    target_bytes = target_memory_mb * 1024 * 1024
    cpu_count = os.cpu_count() or 4
    max_by_memory = max(1, target_bytes // max(memory_per_item_bytes, 1))
    max_by_cpu = cpu_count * 100
    return min(max_by_memory, max_by_cpu)


def optimal_concurrency() -> int:
    """Calculate optimal concurrency based on CPU count."""
    cpu_count = os.cpu_count() or 4
    return max(4, cpu_count * 2)


async def process_in_batches(
    items: List[T],
    processor: Callable[[List[T]], Any],
    batch_size: Optional[int] = None,
    max_concurrency: Optional[int] = None,
) -> List[Any]:
    """Process items in parallel batches with concurrency control."""
    if not items:
        return []
    
    batch_size = batch_size or optimal_batch_size()
    max_concurrency = max_concurrency or optimal_concurrency()
    
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def _process_batch(batch: List[T]) -> Any:
        async with semaphore:
            return await processor(batch)
    
    batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    tasks = [_process_batch(b) for b in batches]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            log.error("Batch %d failed: %s", i, r)
    
    return [r for r in results if not isinstance(r, Exception)]


async def throttled_map(
    items: List[T],
    handler: Callable[[T], Any],
    max_concurrency: int = 10,
) -> List[Any]:
    """Map items through an async handler with throttle."""
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def _handle(item: T) -> Any:
        async with semaphore:
            return await handler(item)
    
    tasks = [_handle(item) for item in items]
    return await asyncio.gather(*tasks, return_exceptions=True)
