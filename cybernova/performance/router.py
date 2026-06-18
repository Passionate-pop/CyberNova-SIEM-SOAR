"""
CyberNova — Performance Router
Endpoints for benchmarks, tuning, and performance monitoring.
"""
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_pipeline_manage, require_pipeline_view

from cybernova.performance.benchmark import pipeline_benchmark
from cybernova.performance.benchmark_100k import high_throughput_benchmark
from cybernova.performance.tuner import performance_tuner

log = logging.getLogger("cybernova.performance.router")
router = APIRouter(prefix="/api/v1/performance", tags=["Performance"])


class BenchmarkRequest(BaseModel):
    event_count: int = 1000
    batch_size: int = 100


@router.post("/benchmark/run", summary="Run pipeline benchmark")
async def run_benchmark(
    req: BenchmarkRequest = BenchmarkRequest(),
    user: CurrentUser = Depends(require_pipeline_manage),
):
    if req.event_count < 1 or req.event_count > 100000:
        raise HTTPException(status_code=400, detail="event_count must be between 1 and 100000")
    if req.batch_size < 1 or req.batch_size > 10000:
        raise HTTPException(status_code=400, detail="batch_size must be between 1 and 10000")
    result = await pipeline_benchmark.run(req.event_count, req.batch_size)
    return result


@router.post("/benchmark/sweep", summary="Run benchmark sweep across configurations")
async def run_benchmark_sweep(
    user: CurrentUser = Depends(require_pipeline_manage),
):
    results = await pipeline_benchmark.run_sweep()
    return {"results": results, "count": len(results)}


@router.get("/benchmark/results", summary="Get benchmark results")
async def get_benchmark_results(
    user: CurrentUser = Depends(require_pipeline_view),
):
    return {"results": pipeline_benchmark.get_results()}


@router.get("/config", summary="Get current performance configuration")
async def get_config(
    user: CurrentUser = Depends(require_pipeline_view),
):
    return {
        "current": performance_tuner.get_config(),
        "best_known": performance_tuner.get_best_config(),
        "best_eps": performance_tuner.get_best_eps(),
    }


@router.post("/config", summary="Apply performance configuration")
async def apply_config(
    config: Dict[str, Any],
    user: CurrentUser = Depends(require_pipeline_manage),
):
    await performance_tuner.apply_config(config)
    return {"applied": True, "config": performance_tuner.get_config()}


@router.post("/auto-tune", summary="Auto-tune performance based on benchmarks")
async def auto_tune(
    user: CurrentUser = Depends(require_pipeline_manage),
):
    results = pipeline_benchmark.get_results()
    recommendations = await performance_tuner.auto_tune(results)
    return {"recommendations": recommendations}


@router.post("/benchmark/100k", summary="Run 100k+ EPS high-throughput benchmark")
async def run_high_throughput_benchmark(
    target_eps: int = Query(100000, description="Target events per second"),
    max_events: int = Query(100000, description="Maximum events to generate"),
    user: CurrentUser = Depends(require_pipeline_manage),
):
    result = await high_throughput_benchmark.run_high_throughput(
        target_eps=target_eps, max_events=max_events,
    )
    return result


@router.get("/benchmark/bottlenecks", summary="Get identified bottlenecks")
async def get_bottlenecks(
    user: CurrentUser = Depends(require_pipeline_view),
):
    return {
        "bottlenecks": high_throughput_benchmark.get_bottlenecks(),
        "results": high_throughput_benchmark.get_results(),
    }


@router.get("/stats", summary="System performance stats")
async def performance_stats(
    user: CurrentUser = Depends(require_pipeline_view),
):
    from cybernova.pipeline.unified_pipeline import unified_pipeline
    metrics = await unified_pipeline.get_metrics()
    return {
        "pipeline": metrics,
        "config": performance_tuner.get_config(),
        "best_eps": performance_tuner.get_best_eps(),
    }
