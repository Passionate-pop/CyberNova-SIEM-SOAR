"""
CyberNova — Retry Framework
Exponential backoff with jitter, bounded retries, and circuit breaker awareness.
"""
from __future__ import annotations

import asyncio
import logging
import random  # nosec - used for jitter in retry delays, not security
from typing import Any, Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")

log = logging.getLogger("cybernova.core.retry")


async def retry_async(
    fn: Callable[..., Awaitable[T]],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    jitter: float = 0.1,
    retryable_exceptions: tuple = (Exception,),
    on_retry: Optional[Callable[[int, Exception], None]] = None,
    **kwargs: Any,
) -> T:
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except retryable_exceptions as e:
            last_exc = e
            if attempt < max_retries:
                delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                if jitter > 0:
                    delay *= 1 + random.random() * jitter  # nosec - non-security jitter
                if on_retry:
                    on_retry(attempt + 1, e)
                log.debug("Retry %d/%d for %s after %.2fs: %s",
                          attempt + 1, max_retries, fn.__name__, delay, e)
                await asyncio.sleep(delay)
    raise last_exc  # type: ignore


async def retry_with_timeout(
    fn: Callable[..., Awaitable[T]],
    *args: Any,
    timeout: float = 10.0,
    max_retries: int = 2,
    **kwargs: Any,
) -> T:
    def wrapped_fn():
        return asyncio.wait_for(fn(*args, **kwargs), timeout=timeout)
    return await retry_async(wrapped_fn, max_retries=max_retries, **{k: v for k, v in kwargs.items() if k in ("base_delay", "max_delay", "backoff_factor", "jitter")})
