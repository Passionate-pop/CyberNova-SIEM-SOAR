from __future__ import annotations

import pytest
from cybernova.monitoring.slo import (
    DEFAULT_STAGE_CONFIGS,
    SLOBreach,
    SLOConfig,
    SLOEngine,
    StageSLI,
    slo_engine,
)


def test_stage_sli_defaults():
    sli = StageSLI(stage="test")
    assert sli.total == 0
    assert sli.successes == 0
    assert sli.failures == 0
    assert sli.success_rate_pct == 0.0
    assert sli.p99_latency_ms == 0.0
    assert sli.p50_latency_ms == 0.0
    assert sli.throughput_per_min >= 0


def test_stage_sli_record_success():
    sli = StageSLI(stage="test")
    sli.record(success=True, latency_ms=10.0)
    assert sli.total == 1
    assert sli.successes == 1
    assert sli.success_rate_pct == 100.0


def test_stage_sli_record_failure():
    sli = StageSLI(stage="test")
    sli.record(success=False, latency_ms=5.0)
    assert sli.total == 1
    assert sli.failures == 1
    assert sli.success_rate_pct == 0.0


def test_stage_sli_mixed_records():
    sli = StageSLI(stage="test")
    sli.record(success=True, latency_ms=10.0)
    sli.record(success=True, latency_ms=20.0)
    sli.record(success=False, latency_ms=5.0)
    assert sli.total == 3
    assert sli.successes == 2
    assert sli.failures == 1
    assert sli.success_rate_pct == pytest.approx(66.666, rel=0.01)


def test_p99_latency():
    sli = StageSLI(stage="test")
    lats = list(range(1, 101))
    for l in lats:
        sli.record(success=True, latency_ms=float(l))
    # P99 of 1..100 should be 99 (0-indexed position 98 = value 99)
    assert sli.p99_latency_ms == 99.0


def test_p50_latency():
    sli = StageSLI(stage="test")
    for l in range(1, 101):
        sli.record(success=True, latency_ms=float(l))
    assert sli.p50_latency_ms == 50.0


def test_p99_empty():
    sli = StageSLI(stage="test")
    assert sli.p99_latency_ms == 0.0


def test_p99_single_value():
    sli = StageSLI(stage="test")
    sli.record(success=True, latency_ms=42.0)
    assert sli.p99_latency_ms == 42.0


def test_snapshot_contains_all_fields():
    sli = StageSLI(stage="test")
    sli.record(success=True, latency_ms=10.0)
    snap = sli.snapshot()
    for field in ("stage", "total", "successes", "failures", "success_rate_pct",
                  "p50_latency_ms", "p99_latency_ms", "throughput_per_min",
                  "window_duration_s"):
        assert field in snap, f"missing {field}"


def test_slo_config_defaults():
    cfg = SLOConfig()
    assert cfg.success_rate_pct == 99.9
    assert cfg.p99_latency_ms == 500.0
    assert cfg.min_throughput_per_min == 0


def test_slo_config_check_success_rate():
    cfg = SLOConfig(success_rate_pct=99.0)
    assert cfg.check_success_rate(99.5) == []
    assert len(cfg.check_success_rate(98.5)) == 1


def test_slo_config_check_p99():
    cfg = SLOConfig(p99_latency_ms=500.0)
    assert cfg.check_p99_latency(100.0) == []
    assert len(cfg.check_p99_latency(600.0)) == 1


def test_slo_config_check_throughput():
    cfg = SLOConfig(min_throughput_per_min=100)
    assert cfg.check_throughput(200.0) == []
    assert len(cfg.check_throughput(50.0)) == 1


def test_default_stage_configs_have_all_pipeline_stages():
    for stage in ("normalization", "enrichment", "anomaly", "detection",
                  "correlation", "alert", "soar", "default"):
        assert stage in DEFAULT_STAGE_CONFIGS, f"missing {stage} config"


def test_slo_engine_record_and_evaluate():
    engine = SLOEngine(window_minutes=60)
    engine.record("detection", success=True, latency_ms=10.0)
    engine.record("detection", success=True, latency_ms=20.0)
    engine.record("detection", success=False, latency_ms=5.0)
    breaches = engine.evaluate("detection")
    # 2/3 = 66.7% success rate, SLO is 99.5% → breach
    assert len(breaches) == 1
    assert breaches[0].stage == "detection"
    assert any("success_rate" in v for v in breaches[0].violations)


def test_slo_engine_no_breach_when_healthy():
    engine = SLOEngine(window_minutes=60)
    for _ in range(100):
        engine.record("normalization", success=True, latency_ms=10.0)
    breaches = engine.evaluate("normalization")
    assert len(breaches) == 0


def test_slo_engine_evaluate_all():
    engine = SLOEngine(window_minutes=60)
    engine.record("detection", success=True, latency_ms=10.0)
    engine.record("detection", success=False, latency_ms=5.0)
    engine.record("normalization", success=True, latency_ms=1.0)
    breaches = engine.evaluate_all()
    assert len(breaches) >= 1


def test_record_success_shorthand():
    engine = SLOEngine(window_minutes=60)
    engine.record_success("test", latency_ms=15.0)
    assert engine._slis["test"].successes == 1
    assert engine._slis["test"].failures == 0


def test_record_failure_shorthand():
    engine = SLOEngine(window_minutes=60)
    engine.record_failure("test", latency_ms=15.0)
    assert engine._slis["test"].failures == 1
    assert engine._slis["test"].successes == 0


def test_rotate_windows():
    engine = SLOEngine(window_minutes=60)
    engine.record("test", success=True, latency_ms=10.0)
    engine.record("test", success=True, latency_ms=20.0)
    completed = engine.rotate_windows()
    assert "test" in completed
    assert completed["test"].total == 2
    assert engine._slis == {}
    assert engine.report()["stages"] == {}


def test_rotate_single_stage():
    engine = SLOEngine(window_minutes=60)
    engine.record("test", success=True, latency_ms=10.0)
    completed = engine.rotate("test")
    assert completed is not None
    assert completed.total == 1
    assert engine.rotate("test") is None


def test_breach_suppression():
    engine = SLOEngine(window_minutes=60)
    engine.record("detection", success=False, latency_ms=5.0)
    engine.suppress_breaches("detection", duration_s=3600)
    breaches = engine.evaluate("detection")
    assert len(breaches) == 0


def test_on_breach_callback_fired():
    engine = SLOEngine(window_minutes=60)
    fired: list = []

    def cb(breach: SLOBreach):
        fired.append(breach)

    engine.on_breach(cb)
    engine.record("detection", success=False, latency_ms=5.0)
    engine.evaluate("detection")
    assert len(fired) == 1
    assert fired[0].stage == "detection"


def test_report_structure():
    engine = SLOEngine(window_minutes=5)
    engine.record("detection", success=True, latency_ms=10.0)
    report = engine.report()
    assert "stages" in report
    assert "recent_breaches" in report
    assert "breach_count" in report
    assert "window_minutes" in report
    assert report["window_minutes"] == 5


def test_report_includes_slo_breached_flag():
    engine = SLOEngine(window_minutes=60)
    engine.record("detection", success=False, latency_ms=5.0)
    report = engine.report()
    stages = report["stages"]
    assert "detection" in stages
    assert stages["detection"]["slo_breached"] is True


def test_singleton_exists():
    assert slo_engine is not None
    assert isinstance(slo_engine, SLOEngine)


def test_breach_has_stage_and_violations():
    engine = SLOEngine(window_minutes=60)
    engine.record("detection", success=False, latency_ms=5000.0)
    breaches = engine.evaluate("detection")
    assert len(breaches) >= 1
    b = breaches[0]
    assert b.stage == "detection"
    assert len(b.violations) >= 1
    assert b.notified is False
    assert b.timestamp is not None
