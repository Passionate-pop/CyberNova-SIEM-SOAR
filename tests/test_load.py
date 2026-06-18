"""Tests for the load testing suite utilities (event generator, configs)."""

from tests.load.event_generator import generate_load_event, generate_event_batch
from tests.load.configs import PROFILES, get_profile, PROFILE_LABELS


def test_load_event_generates_valid_structure():
    event = generate_load_event("test-run-1", 1)
    assert "_load_test" in event
    assert event["_load_test"]["run_id"] == "test-run-1"
    assert event["_load_test"]["sequence"] == 1
    assert "sent_at" in event["_load_test"]
    assert "event_id" in event
    assert "event_type" in event
    assert "severity" in event
    assert "source_ip" in event
    assert "dest_ip" in event


def test_load_event_generates_differs_by_sequence():
    e1 = generate_load_event("test-run", 1)
    e2 = generate_load_event("test-run", 2)
    assert e1["_load_test"]["sequence"] != e2["_load_test"]["sequence"]


def test_generate_event_batch_returns_correct_count():
    batch = generate_event_batch("test-batch", 0, 100)
    assert len(batch) == 100
    for i, event in enumerate(batch):
        assert event["_load_test"]["sequence"] == i


def test_generate_event_batch_severity_distribution():
    batch = generate_event_batch("test-sev", 0, 1000)
    severities = [e["severity"] for e in batch]
    assert "info" in severities
    assert "critical" in severities
    assert "high" in severities


def test_profiles_defined():
    assert len(PROFILES) > 0
    assert all(p.label for p in PROFILES)
    assert all(p.target_eps > 0 for p in PROFILES)
    assert all(p.num_users > 0 for p in PROFILES)


def test_get_profile_returns_matching():
    p = get_profile("10k-eps")
    assert p.target_eps == 10_000
    assert p.num_users == 100


def test_get_profile_fallback_to_default():
    p = get_profile("nonexistent")
    assert p.label == "10k-eps"


def test_profile_labels_match():
    for label in PROFILE_LABELS:
        p = get_profile(label)
        assert p.label == label
