"""
EPS profile presets for load testing.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class EpsProfile:
    label: str
    target_eps: int
    num_users: int
    spawn_rate: int
    batch_size: int
    min_wait_ms: int
    max_wait_ms: int
    run_time_sec: int = 300


PROFILES: List[EpsProfile] = [
    EpsProfile(
        label="10k-eps",
        target_eps=10_000,
        num_users=100,
        spawn_rate=10,
        batch_size=100,
        min_wait_ms=9,
        max_wait_ms=11,
    ),
    EpsProfile(
        label="50k-eps",
        target_eps=50_000,
        num_users=500,
        spawn_rate=50,
        batch_size=100,
        min_wait_ms=9,
        max_wait_ms=11,
    ),
    EpsProfile(
        label="100k-eps",
        target_eps=100_000,
        num_users=1000,
        spawn_rate=100,
        batch_size=100,
        min_wait_ms=9,
        max_wait_ms=11,
    ),
    EpsProfile(
        label="soak-10k-1h",
        target_eps=10_000,
        num_users=100,
        spawn_rate=10,
        batch_size=100,
        min_wait_ms=9,
        max_wait_ms=11,
        run_time_sec=3600,
    ),
]


def get_profile(label: str) -> EpsProfile:
    for p in PROFILES:
        if p.label == label:
            return p
    return PROFILES[0]


PROFILE_LABELS = [p.label for p in PROFILES]
