from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cybernova.performance.benchmark import pipeline_benchmark
from cybernova.performance.scaling import optimal_concurrency

log = logging.getLogger("cybernova.performance.benchmark_100k")

TARGET_EPS = 100_000


class HighThroughputBenchmark:
    """
    High-throughput pipeline benchmark targeting 100k+ EPS.
    Identifies bottlenecks and provides optimization recommendations.
    """

    def __init__(self):
        self._results: List[Dict[str, Any]] = []
        self._bottlenecks: List[Dict[str, Any]] = []

    async def run_high_throughput(
        self,
        target_eps: int = TARGET_EPS,
        max_events: int = 100000,
        duration_seconds: int = 30,
    ) -> Dict[str, Any]:
        """Run high-throughput benchmark. Sweeps batch sizes to find optimal config."""
        log.info("Starting high-throughput benchmark (target: %d EPS, max events: %d, duration: %ds)",
                 target_eps, max_events, duration_seconds)

        results = []
        batch_sizes = [50, 100, 200, 500, 1000, 2000, 5000]

        for batch_size in batch_sizes:
            if batch_size > max_events:
                continue

            log.info("Benchmarking batch_size=%d...", batch_size)
            try:
                result = await pipeline_benchmark.run(
                    event_count=min(batch_size * 100, max_events),
                    batch_size=batch_size,
                )
                results.append(result)
            except Exception as e:
                log.error("Benchmark failed for batch_size=%d: %s", batch_size, e)

        self._results = results
        best = self._find_best_result(results)
        self._analyze_bottlenecks(results)

        return {
            "target_eps": target_eps,
            "achieved_eps": best.get("eps", 0),
            "best_config": {
                "batch_size": best.get("batch_size", 100),
            },
            "latency": best.get("latency_ms", {}),
            "bottlenecks": self._bottlenecks,
            "recommendations": self._generate_recommendations(results),
            "all_results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _find_best_result(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not results:
            return {}
        return max(results, key=lambda r: r.get("eps", 0))

    def _analyze_bottlenecks(self, results: List[Dict[str, Any]]):
        """Identify bottlenecks from benchmark results and system state."""
        self._bottlenecks = []

        if not results:
            return

        best = self._find_best_result(results)
        eps = best.get("eps", 0)

        if eps < 1000:
            self._bottlenecks.append({
                "severity": "critical",
                "component": "pipeline",
                "issue": f"Throughput only {eps:.0f} EPS — well below target",
                "suggestion": "Check DB connection pool size, Redis availability, pipeline stage concurrency",
            })

        if eps < 10000:
            self._bottlenecks.append({
                "severity": "high",
                "component": "throughput",
                "issue": f"Achieved {eps:.0f} EPS vs target {TARGET_EPS:,} EPS",
                "suggestion": "Increase batch size, pipeline concurrency, and DB pool",
            })

        latencies = best.get("latency_ms", {})
        p99 = latencies.get("p99", 0)
        if p99 > 1000:
            self._bottlenecks.append({
                "severity": "high",
                "component": "latency",
                "issue": f"P99 latency {p99}ms exceeds 1s target",
                "suggestion": "Optimize slow detection rules, reduce enrichment overhead",
            })

        import os
        cpu_count = os.cpu_count() or 4
        if eps > 0 and eps / cpu_count < 1000:
            self._bottlenecks.append({
                "severity": "medium",
                "component": "cpu",
                "issue": f"Only {eps/cpu_count:.0f} EPS per core — may be I/O bound",
                "suggestion": "Check for blocking I/O calls, ensure uvloop is active",
            })

        concurrency = optimal_concurrency()
        if eps > 0 and eps / concurrency < 500:
            self._bottlenecks.append({
                "severity": "low",
                "component": "concurrency",
                "issue": "Low EPS per concurrent task",
                "suggestion": "Review async task overhead, reduce context switching",
            })

    def _generate_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable optimization recommendations."""
        recommendations = []

        if not results:
            return ["Run a benchmark first to get recommendations"]

        best_batch = self._find_best_result(results).get("batch_size", 100)
        recommendations.append(f"Optimal batch size: {best_batch} (sweep more values for finer tuning)")

        if self._bottlenecks:
            for b in self._bottlenecks:
                recommendations.append(f"[{b['severity'].upper()}] {b['component']}: {b['suggestion']}")

        recommendations.extend([
            "Enable uvloop for async event loop (already set in Dockerfile CMD)",
            "Use httptools for HTTP parsing (already set in Dockerfile CMD)",
            "Increase DB pool size: db_pool_size=40, db_max_overflow=80",
            "Set pipeline concurrency to cpu_count * 2 for maximum throughput",
            "Consider Redis Cluster for high-availability event bus at scale",
        ])

        return recommendations

    def get_results(self) -> List[Dict[str, Any]]:
        return list(self._results)

    def get_bottlenecks(self) -> List[Dict[str, Any]]:
        return list(self._bottlenecks)


high_throughput_benchmark = HighThroughputBenchmark()
