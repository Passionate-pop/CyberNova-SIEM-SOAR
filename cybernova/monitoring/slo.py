from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("cybernova.monitoring.slo")


@dataclass
class SLOConfig:
    """Per-stage SLO thresholds."""
    success_rate_pct: float = 99.9
    p99_latency_ms: float = 500.0
    min_throughput_per_min: int = 0

    def check_success_rate(self, actual: float) -> List[str]:
        violations: List[str] = []
        if actual < self.success_rate_pct:
            violations.append(
                f"success_rate {actual:.2f}% < SLO {self.success_rate_pct}%"
            )
        return violations

    def check_p99_latency(self, actual: float) -> List[str]:
        violations: List[str] = []
        if actual > self.p99_latency_ms:
            violations.append(
                f"p99_latency {actual:.1f}ms > SLO {self.p99_latency_ms}ms"
            )
        return violations

    def check_throughput(self, actual: float) -> List[str]:
        violations: List[str] = []
        if actual < self.min_throughput_per_min:
            violations.append(
                f"throughput {actual:.1f}/min < SLO {self.min_throughput_per_min}/min"
            )
        return violations


DEFAULT_STAGE_CONFIGS: Dict[str, SLOConfig] = {
    "default": SLOConfig(),
    "normalization": SLOConfig(success_rate_pct=99.9, p99_latency_ms=200.0),
    "enrichment": SLOConfig(success_rate_pct=99.5, p99_latency_ms=1000.0),
    "anomaly": SLOConfig(success_rate_pct=99.0, p99_latency_ms=2000.0),
    "detection": SLOConfig(success_rate_pct=99.5, p99_latency_ms=500.0),
    "correlation": SLOConfig(success_rate_pct=99.5, p99_latency_ms=500.0),
    "alert": SLOConfig(success_rate_pct=99.9, p99_latency_ms=300.0),
    "soar": SLOConfig(success_rate_pct=99.5, p99_latency_ms=2000.0),
}


@dataclass
class StageSLI:
    """Service Level Indicator snapshot for one stage in a time window."""
    stage: str
    total: int = 0
    successes: int = 0
    failures: int = 0
    latencies: List[float] = field(default_factory=list)
    window_start: float = field(default_factory=time.time)

    @property
    def success_rate_pct(self) -> float:
        return (self.successes / max(self.total, 1)) * 100.0

    @property
    def failure_rate_pct(self) -> float:
        return (self.failures / max(self.total, 1)) * 100.0

    @property
    def p99_latency_ms(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_lats = sorted(self.latencies)
        idx = max(0, int(__import__("math").ceil(len(sorted_lats) * 0.99)) - 1)
        return sorted_lats[idx]

    @property
    def p50_latency_ms(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_lats = sorted(self.latencies)
        idx = max(0, int(__import__("math").ceil(len(sorted_lats) * 0.50)) - 1)
        return sorted_lats[idx]

    @property
    def throughput_per_min(self) -> float:
        elapsed = time.time() - self.window_start
        return (self.total / max(elapsed, 1)) * 60.0

    def record(self, success: bool, latency_ms: float) -> None:
        self.total += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1
        self.latencies.append(latency_ms)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "total": self.total,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate_pct": round(self.success_rate_pct, 2),
            "failure_rate_pct": round(self.failure_rate_pct, 2),
            "p50_latency_ms": round(self.p50_latency_ms, 1),
            "p99_latency_ms": round(self.p99_latency_ms, 1),
            "throughput_per_min": round(self.throughput_per_min, 1),
            "window_duration_s": round(time.time() - self.window_start, 1),
        }


@dataclass
class SLOBreach:
    stage: str
    timestamp: str
    violations: List[str]
    snapshot: Dict[str, Any]
    notified: bool = False


BreachCallback = Callable[["SLOBreach"], None]


class SLOEngine:
    """Evaluates pipeline stage SLIs against SLO thresholds.

    Usage:
        slo_engine = SLOEngine(window_minutes=5)
        slo_engine.record("detection", success=True, latency_ms=42.0)
        report = slo_engine.report()
    """

    def __init__(
        self,
        window_minutes: int = 5,
        stage_configs: Optional[Dict[str, SLOConfig]] = None,
    ):
        self._window_minutes = window_minutes
        self._stage_configs = dict(DEFAULT_STAGE_CONFIGS)
        if stage_configs:
            self._stage_configs.update(stage_configs)
        self._slis: Dict[str, StageSLI] = {}
        self._breaches: List[SLOBreach] = []
        self._callbacks: List[BreachCallback] = []
        self._suppress_until: Dict[str, float] = {}

    # ── Recording ──────────────────────────────────────────────

    def record(self, stage: str, success: bool, latency_ms: float) -> None:
        """Record one stage execution result."""
        if stage not in self._slis:
            self._slis[stage] = StageSLI(stage=stage)
        sli = self._slis[stage]
        sli.record(success, latency_ms)

    def record_success(self, stage: str, latency_ms: float) -> None:
        """Shorthand: record a successful stage execution."""
        self.record(stage, success=True, latency_ms=latency_ms)

    def record_failure(self, stage: str, latency_ms: float) -> None:
        """Shorthand: record a failed stage execution."""
        self.record(stage, success=False, latency_ms=latency_ms)

    # ── Evaluation ─────────────────────────────────────────────

    def evaluate(self, stage: Optional[str] = None) -> List[SLOBreach]:
        """Check SLIs against SLOs. Returns new breaches."""
        now = datetime.now(timezone.utc).isoformat()
        new_breaches: List[SLOBreach] = []

        targets = [stage] if stage else list(self._slis.keys())
        for name in targets:
            sli = self._slis.get(name)
            if sli is None or sli.total == 0:
                continue
            config = self._stage_configs.get(name, self._stage_configs["default"])
            violations: List[str] = []
            violations.extend(config.check_success_rate(sli.success_rate_pct))
            violations.extend(config.check_p99_latency(sli.p99_latency_ms))
            violations.extend(config.check_throughput(sli.throughput_per_min))
            if not violations:
                continue
            if self._is_suppressed(name):
                continue
            breach = SLOBreach(
                stage=name,
                timestamp=now,
                violations=violations,
                snapshot=sli.snapshot(),
            )
            self._breaches.append(breach)
            new_breaches.append(breach)
            for cb in self._callbacks:
                try:
                    cb(breach)
                except Exception as e:
                    log.error("SLO breach callback error for %s: %s", name, e)

        return new_breaches

    def evaluate_all(self) -> List[SLOBreach]:
        """Evaluate all stages with data."""
        return self.evaluate()

    # ── Breach suppression ─────────────────────────────────────

    def suppress_breaches(self, stage: str, duration_s: float = 300.0) -> None:
        """Suppress breach alerts for a stage (e.g., during maintenance)."""
        self._suppress_until[stage] = time.time() + duration_s

    def _is_suppressed(self, stage: str) -> bool:
        expiry = self._suppress_until.get(stage, 0.0)
        return time.time() < expiry

    # ── Window management ──────────────────────────────────────

    def rotate_windows(self) -> Dict[str, StageSLI]:
        """Close current windows and return completed SLI snapshots.
        Starts fresh windows for all stages.
        """
        completed = {}
        for stage, sli in self._slis.items():
            if sli.total > 0:
                completed[stage] = sli
        self._slis = {}
        return completed

    def rotate(self, stage: str) -> Optional[StageSLI]:
        """Close a single stage window. Returns the completed SLI or None."""
        sli = self._slis.pop(stage, None)
        return sli if sli and sli.total > 0 else None

    # ── Callbacks ──────────────────────────────────────────────

    def on_breach(self, callback: BreachCallback) -> None:
        """Register a callback invoked on each new SLO breach."""
        self._callbacks.append(callback)

    # ── Reporting ──────────────────────────────────────────────

    def report(self) -> Dict[str, Any]:
        """Full SLO/SLI report for all stages."""
        stages: Dict[str, Any] = {}
        for name, config in self._stage_configs.items():
            sli = self._slis.get(name)
            if sli and sli.total > 0:
                snap = sli.snapshot()
                snap["slo"] = {
                    "success_rate_pct": config.success_rate_pct,
                    "p99_latency_ms": config.p99_latency_ms,
                    "min_throughput_per_min": config.min_throughput_per_min,
                }
                snap["slo_breached"] = bool(
                    config.check_success_rate(sli.success_rate_pct)
                    or config.check_p99_latency(sli.p99_latency_ms)
                    or config.check_throughput(sli.throughput_per_min)
                )
                stages[name] = snap

        recent_breaches = [
            {
                "stage": b.stage,
                "timestamp": b.timestamp,
                "violations": b.violations,
            }
            for b in self._breaches[-50:]
        ]

        return {
            "stages": stages,
            "recent_breaches": recent_breaches,
            "breach_count": len(self._breaches),
            "window_minutes": self._window_minutes,
        }


slo_engine = SLOEngine()
