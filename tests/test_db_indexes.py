"""Tests for database composite indexes — verifies __table_args__ are declared."""

from sqlalchemy import Index

from cybernova.database.postgres.models import Alert, NormalizedEvent, RawEvent


def _find_index(model, name: str) -> Index:
    for arg in model.__table_args__:
        if isinstance(arg, Index) and arg.name == name:
            return arg
    raise AssertionError(f"Index {name} not found on {model.__name__}")


def test_alert_has_composite_index_on_tenant_created_severity():
    idx = _find_index(Alert, "ix_alerts_tenant_created_severity")
    cols = [c.name for c in idx.columns]
    assert cols == ["tenant_id", "created_at", "severity"]


def test_normalized_event_has_composite_index_on_tenant_normalized():
    idx = _find_index(NormalizedEvent, "ix_normalized_events_tenant_normalized")
    cols = [c.name for c in idx.columns]
    assert cols == ["tenant_id", "normalized_at"]


def test_raw_event_has_composite_index_on_tenant_received():
    idx = _find_index(RawEvent, "ix_raw_events_tenant_received")
    cols = [c.name for c in idx.columns]
    assert cols == ["tenant_id", "received_at"]


def test_alert_table_args_is_tuple():
    assert isinstance(Alert.__table_args__, tuple)


def test_normalized_event_table_args_is_tuple():
    assert isinstance(NormalizedEvent.__table_args__, tuple)


def test_raw_event_table_args_is_tuple():
    assert isinstance(RawEvent.__table_args__, tuple)


def test_db_index_analyze_script_imports():
    from tests.analyze_queries import QUERIES, run_query, print_report
    assert len(QUERIES) == 8
    assert callable(run_query)
    assert callable(print_report)
