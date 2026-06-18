"""
CyberNova — Circuit Breaker Pattern
Prevents cascade failures when external services are down.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar
from dataclasses import dataclass
from functools import wraps


log = logging.getLogger("cybernova.circuit_breaker")

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, reject requests
    HALF_OPEN = "half_open" # Testing recovery


@dataclass
class CircuitBreakerStats:
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    success_threshold: int = 3
    timeout_seconds: float = 60.0
    half_open_max_calls: int = 3


class CircuitBreaker:
    """
    Circuit breaker implementation for external service calls.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Service is failing, requests are rejected immediately
    - HALF_OPEN: Testing if service recovered, limited requests allowed
    
    All state mutations are serialized via an asyncio.Lock to prevent
    race conditions when multiple coroutines evaluate thresholds concurrently.
    """
    
    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self._half_open_calls = 0
        self._last_state_change = time.time()
        self._lock = asyncio.Lock()
    
    async def _should_allow_request(self) -> bool:
        async with self._lock:
            if self.state == CircuitState.CLOSED:
                return True
            
            if self.state == CircuitState.OPEN:
                if time.time() - self._last_state_change >= self.config.timeout_seconds:
                    self._transition_to_half_open_locked()
                    return True
                return False
            
            if self.state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
            
            return False
    
    def _transition_to_half_open_locked(self) -> None:
        """Transition to HALF_OPEN. Caller MUST hold self._lock."""
        self.state = CircuitState.HALF_OPEN
        self._half_open_calls = 0
        self._last_state_change = time.time()
        log.info(f"Circuit breaker '{self.name}' transitioned to HALF_OPEN")
    
    def _transition_to_open_locked(self) -> None:
        """Transition to OPEN. Caller MUST hold self._lock."""
        self.state = CircuitState.OPEN
        self._last_state_change = time.time()
        log.warning(f"Circuit breaker '{self.name}' transitioned to OPEN (failures: {self.stats.consecutive_failures})")
    
    def _transition_to_closed_locked(self) -> None:
        """Transition to CLOSED. Caller MUST hold self._lock."""
        self.state = CircuitState.CLOSED
        self.stats.consecutive_failures = 0
        self._half_open_calls = 0
        self._last_state_change = time.time()
        log.info(f"Circuit breaker '{self.name}' transitioned to CLOSED")
    
    async def record_success(self) -> None:
        async with self._lock:
            self.stats.total_calls += 1
            self.stats.successful_calls += 1
            self.stats.last_success_time = datetime.now(timezone.utc)
            self.stats.consecutive_successes += 1
            self.stats.consecutive_failures = 0
            
            if self.state == CircuitState.HALF_OPEN:
                if self.stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to_closed_locked()
    
    async def record_failure(self) -> None:
        async with self._lock:
            self.stats.total_calls += 1
            self.stats.failed_calls += 1
            self.stats.last_failure_time = datetime.now(timezone.utc)
            self.stats.consecutive_failures += 1
            self.stats.consecutive_successes = 0
            
            if self.state == CircuitState.CLOSED:
                if self.stats.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to_open_locked()
            elif self.state == CircuitState.HALF_OPEN:
                self._transition_to_open_locked()
    
    def record_rejection(self) -> None:
        self.stats.rejected_calls += 1
    
    async def call(
        self,
        func: Callable[..., T],
        *args,
        fallback: Optional[T] = None,
        **kwargs,
    ) -> T:
        """Execute a function with circuit breaker protection."""
        if not await self._should_allow_request():
            self.record_rejection()
            log.warning(f"Circuit breaker '{self.name}' rejected call (state: {self.state})")
            if fallback is not None:
                return fallback
            raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is OPEN")
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
                # Handle case where a sync wrapper returns a coroutine
                # (e.g. lambda: async_fn(...))
                if asyncio.iscoroutine(result):
                    result = await result
            await self.record_success()
            return result
        except Exception as e:
            await self.record_failure()
            if fallback is not None:
                log.warning(f"Circuit breaker '{self.name}' failed, using fallback: {e}")
                return fallback
            raise
    
    async def get_status(self) -> Dict[str, Any]:
        async with self._lock:
            return {
                "name": self.name,
                "state": self.state.value,
                "stats": {
                    "total_calls": self.stats.total_calls,
                    "successful_calls": self.stats.successful_calls,
                    "failed_calls": self.stats.failed_calls,
                    "rejected_calls": self.stats.rejected_calls,
                    "consecutive_failures": self.stats.consecutive_failures,
                    "last_failure_time": self.stats.last_failure_time.isoformat() if self.stats.last_failure_time else None,
                    "last_success_time": self.stats.last_success_time.isoformat() if self.stats.last_success_time else None,
                },
                "config": {
                    "failure_threshold": self.config.failure_threshold,
                    "success_threshold": self.config.success_threshold,
                    "timeout_seconds": self.config.timeout_seconds,
                },
                "uptime_seconds": time.time() - self._last_state_change,
            }
    
    async def reset(self) -> None:
        async with self._lock:
            self.state = CircuitState.CLOSED
            self.stats = CircuitBreakerStats()
            self._half_open_calls = 0
            self._last_state_change = time.time()
            log.info(f"Circuit breaker '{self.name}' reset")


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and request is rejected."""
    pass


# Global circuit breaker registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a circuit breaker by name."""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name, config)
    return _circuit_breakers[name]


def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None, fallback: Any = None):
    """Decorator to add circuit breaker to a function.

    Always returns an async wrapper because ``CircuitBreaker.call()``
    requires the event-loop lock for safe state transitions.
    """
    def decorator(func: Callable) -> Callable:
        cb = get_circuit_breaker(name, config)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await cb.call(func, *args, fallback=fallback, **kwargs)
        
        return wrapper
    
    return decorator


async def get_all_circuit_breakers_status() -> Dict[str, Dict[str, Any]]:
    """Get status of all circuit breakers."""
    result = {}
    for name, cb in _circuit_breakers.items():
        result[name] = await cb.get_status()
    return result


async def reset_all_circuit_breakers() -> None:
    """Reset all circuit breakers to closed state."""
    for cb in _circuit_breakers.values():
        await cb.reset()


circuit_breaker_registry = _circuit_breakers
