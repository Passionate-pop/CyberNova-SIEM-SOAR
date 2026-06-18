"""
CyberNova — Pipeline Performance Benchmark
Measures EPS (events per second), latency percentiles, and throughput under load.
"""
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

log = logging.getLogger("cybernova.performance.benchmark")


class PipelineBenchmark:
    """
    Benchmark the pipeline by injecting realistic events and measuring throughput.
    
    Usage:
        benchmark = PipelineBenchmark()
        result = await benchmark.run(event_count=1000, batch_size=100)
        # result contains EPS, P50/P95/P99 latency, error rate
    """
    
    def __init__(self):
        self._results: List[Dict[str, Any]] = []
        self.reset_metrics()

    def reset_metrics(self):
        """Reset pipeline metrics before a benchmark run."""
        from cybernova.pipeline.unified_pipeline import unified_pipeline
        unified_pipeline._metrics = {
            "ingested": 0, "normalized": 0, "enriched": 0,
            "detected": 0, "correlated": 0, "alerted": 0,
            "soared": 0, "errors": 0, "latency_ms": [],
        }

    async def run(
        self,
        event_count: int = 1000,
        batch_size: int = 100,
        tenant_id: str = "benchmark",
        source: str = "benchmark",
    ) -> Dict[str, Any]:
        """Run a benchmark with the specified event count and batch size."""
        from cybernova.pipeline.unified_pipeline import unified_pipeline
        
        self.reset_metrics()
        events = self._generate_events(event_count)
        start = time.perf_counter()
        errors = 0
        
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            try:
                count = await unified_pipeline.ingest_batch(batch, tenant_id, source, "json")
                if count < len(batch):
                    errors += len(batch) - count
            except Exception as e:
                log.error("Benchmark batch error at offset %d: %s", i, e)
                errors += len(batch)
        
        elapsed = time.perf_counter() - start
        eps = event_count / elapsed if elapsed > 0 else 0
        
        metrics = await unified_pipeline.get_metrics()
        latencies = metrics.get("latency_ms", [])
        
        result = {
            "event_count": event_count,
            "batch_size": batch_size,
            "elapsed_seconds": round(elapsed, 3),
            "eps": round(eps, 1),
            "errors": errors,
            "error_rate": round(errors / event_count * 100, 2) if event_count > 0 else 0,
            "latency_ms": {
                "avg": round(sum(latencies) / len(latencies), 2) if latencies else 0,
                "p50": self._percentile(latencies, 50) if latencies else 0,
                "p95": self._percentile(latencies, 95) if latencies else 0,
                "p99": self._percentile(latencies, 99) if latencies else 0,
                "max": max(latencies) if latencies else 0,
                "min": min(latencies) if latencies else 0,
                "count": len(latencies),
            },
            "pipeline_metrics": {
                "ingested": metrics.get("ingested", 0),
                "normalized": metrics.get("normalized", 0),
                "enriched": metrics.get("enriched", 0),
                "detected": metrics.get("detected", 0),
                "alerted": metrics.get("alerted", 0),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        self._results.append(result)
        return result
    
    async def run_sweep(
        self,
        event_counts: List[int] = [100, 500, 1000, 5000],
        batch_sizes: List[int] = [10, 50, 100, 500, 1000],
    ) -> List[Dict[str, Any]]:
        """Run multiple benchmarks sweeping event counts and batch sizes."""
        results = []
        for count in event_counts:
            for batch in batch_sizes:
                if batch > count:
                    continue
                log.info("Benchmark: %d events, batch %d", count, batch)
                try:
                    result = await self.run(event_count=count, batch_size=batch)
                    results.append(result)
                except Exception as e:
                    log.error("Benchmark failed: %s", e)
                    results.append({
                        "event_count": count,
                        "batch_size": batch,
                        "error": str(e),
                        "error_rate": 100.0,
                    })
        self._results = results
        return results
    
    def get_results(self) -> List[Dict[str, Any]]:
        return list(self._results)
    
    def _generate_events(self, count: int) -> List[Dict[str, Any]]:
        """Generate realistic test events."""
        import random
        event_types = ["network", "process", "auth", "file", "registry", "dns"]
        severities = ["info", "low", "medium", "high", "critical"]
        protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP"]

        words = ['login', 'access', 'query', 'connect', 'transfer', 'execute', 'download', 'upload', 'modify', 'delete']
        events = []
        for i in range(count):  # nosec - benchmark test data, not security
            chosen_words = ' '.join(random.choices(words, k=3))  # nosec
            events.append({
                "event_type": random.choice(event_types),  # nosec
                "severity": random.choice(severities),  # nosec
                "source_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",  # nosec
                "dest_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",  # nosec
                "dest_port": random.choice([22, 80, 443, 3389, 8080, 8443, 53, 445, 135]),  # nosec
                "protocol": random.choice(protocols),  # nosec
                "user": f"user{random.randint(1, 100)}",  # nosec
                "message": f"Benchmark event {i}: {chosen_words}",  # nosec - no fstring escape issue
                "risk_score": round(random.uniform(0, 100), 1),  # nosec
                "bytes_sent": random.randint(0, 10_000_000),  # nosec
            })
        return events
    
    @staticmethod
    def _percentile(values: List[float], p: int) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * p / 100
        f = int(k)
        c = f + 1
        if c >= len(sorted_vals):
            return sorted_vals[-1]
        return sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f])


pipeline_benchmark = PipelineBenchmark()
