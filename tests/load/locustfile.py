"""
Locust load test for CyberNOVA pipeline.
Simulates 10K/50K/100K EPS through the ingestion API.
Measures P50/P95/P99 latency per pipeline stage.
Supports JWT authentication to bypass the WAF.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import quantiles
from typing import Any, Dict, List, Optional
from uuid import uuid4

from locust import HttpUser, between, events, task, tag
from locust.runners import MasterRunner, WorkerRunner

from tests.load.event_generator import generate_event_batch
from tests.load.configs import get_profile, PROFILES

EPS_PROFILE = os.environ.get("LOCUST_EPS_PROFILE", "10k-eps")
PIPELINE_HOST = os.environ.get("LOCUST_PIPELINE_HOST", "http://localhost:8000")
LOAD_RUN_ID = os.environ.get("LOCUST_RUN_ID", str(uuid4())[:8])
AUTH_USERNAME = os.environ.get("LOCUST_AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("LOCUST_AUTH_PASSWORD", "admin123")

# Share a single auth token across all users to avoid hammering login endpoint
import threading

_SHARED_TOKEN: Optional[str] = None
_SHARED_TOKEN_LOCK = threading.Lock()

log = logging.getLogger("cybernova.loadtest")


@dataclass
class StageLatencyBucket:
    stage: str
    latencies_ms: List[float] = field(default_factory=list)

    def record(self, latency_ms: float) -> None:
        self.latencies_ms.append(latency_ms)

    def percentiles(self) -> Dict[str, float]:
        if len(self.latencies_ms) < 10:
            return {"p50": 0, "p95": 0, "p99": 0, "count": len(self.latencies_ms)}
        q = quantiles(self.latencies_ms, n=100)
        return {
            "p50": round(q[49], 2),
            "p95": round(q[94], 2),
            "p99": round(q[98], 2),
            "count": len(self.latencies_ms),
        }


_stage_buckets: Dict[str, StageLatencyBucket] = {}
_total_events: int = 0
_total_errors: int = 0


def _get_bucket(stage: str) -> StageLatencyBucket:
    if stage not in _stage_buckets:
        _stage_buckets[stage] = StageLatencyBucket(stage=stage)
    return _stage_buckets[stage]


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    log.info("Load test run_id=%s profile=%s host=%s", LOAD_RUN_ID, EPS_PROFILE, PIPELINE_HOST)
    if isinstance(environment.runner, MasterRunner):
        log.info("Master node — workers will report stats")
    elif isinstance(environment.runner, WorkerRunner):
        log.info("Worker node started")


@events.quit.add_listener
def on_locust_quit(environment=None, **kwargs):
    log.info("Load test finished. Total events: %d, Errors: %d", _total_events, _total_errors)
    for bucket in _stage_buckets.values():
        p = bucket.percentiles()
        log.info(
            "Stage=%-15s count=%-8d p50=%-8.2f p95=%-8.2f p99=%-8.2f",
            bucket.stage, p["count"], p["p50"], p["p95"], p["p99"],
        )


class PipelineStageUser(HttpUser):
    host = PIPELINE_HOST
    wait_time = between(0.008, 0.012)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = get_profile(EPS_PROFILE)
        self._seq = 0
        self._token: Optional[str] = None

    def _acquire_token_sync(self):
        """Acquire a shared auth token synchronously (only first user, others reuse)."""
        global _SHARED_TOKEN
        if _SHARED_TOKEN is not None:
            self._token = _SHARED_TOKEN
            return True

        with _SHARED_TOKEN_LOCK:
            if _SHARED_TOKEN is not None:
                self._token = _SHARED_TOKEN
                return True

            if not AUTH_PASSWORD:
                log.warning("No LOCUST_AUTH_PASSWORD set — requests may be blocked by WAF")
                return False

            import httpx
            try:
                resp = httpx.post(
                    f"{PIPELINE_HOST}/api/v1/auth/login",
                    json={"username": AUTH_USERNAME, "password": AUTH_PASSWORD},
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get("access_token") or data.get("token")
                    _SHARED_TOKEN = token
                    self._token = token
                    log.info("Authenticated successfully with shared token")
                    return True
                else:
                    log.error("Login failed: HTTP %d: %s", resp.status_code, resp.text[:200])
                    return False
            except Exception as e:
                log.error("Login exception: %s", e)
                return False

    def on_start(self):
        """Acquire shared token synchronously on startup."""
        self._acquire_token_sync()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _send_batch(self, batch: List[Dict[str, Any]]) -> int:
        global _total_events, _total_errors
        payload = {
            "source": "load_test",
            "source_type": f"locust_{EPS_PROFILE}",
            "events": batch,
        }
        start = time.perf_counter()
        with self.client.post(
            "/api/v1/ingest/",
            json=payload,
            headers=self._headers(),
            name="ingest_batch",
            catch_response=True,
        ) as resp:
            elapsed = (time.perf_counter() - start) * 1000
            _get_bucket("ingestion").record(elapsed)
            if resp.status_code == 200:
                data = resp.json()
                accepted = data.get("accepted", 0)
                _total_events += accepted
                resp.success()
                return accepted
            else:
                _total_errors += len(batch)
                resp.failure(f"HTTP {resp.status_code}: {resp.text[:100]}")
                return 0

    @task
    @tag("ingest")
    def ingest_events(self):
        batch = generate_event_batch(LOAD_RUN_ID, self._seq, self.profile.batch_size)
        self._seq += self.profile.batch_size
        self._send_batch(batch)

    @task
    @tag("metrics")
    def check_pipeline_metrics(self):
        with self.client.get(
            "/metrics",
            headers=self._headers(),
            name="pipeline_metrics",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")
