"""
Connection Pool Configuration Calculator
========================================
Calculates optimal PostgreSQL connection pool settings based on expected
events-per-second (EPS), batch size, and number of workers.

Formula:
  per_worker_pool = clamp(eps / 1000 + batch / 50, min=10, max=50)
  per_worker_overflow = max(5, pool_size // 2)
  max_total_per_worker = pool_size + max_overflow
  recommended_pg_max_connections = max_total_per_worker * workers + admin_buffer

Usage:
  from cybernova.database.pool_config import PoolCalculator
  calc = PoolCalculator(eps=10000, batch=100, workers=8)
  calc.print_report()
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict


@dataclass
class PoolCalculator:
    eps: int = 10_000
    batch: int = 100
    workers: int = 8
    admin_reserved: int = 10
    pool_size: int = 0
    max_overflow: int = 0

    def __post_init__(self):
        if self.pool_size == 0:
            self.pool_size = self._compute_pool_size()
        if self.max_overflow == 0:
            self.max_overflow = self._compute_overflow()

    def _compute_pool_size(self) -> int:
        raw = max(self.eps, 1000) / 1000 + max(self.batch, 1) / 50
        return max(10, min(50, math.ceil(raw)))

    def _compute_overflow(self) -> int:
        return max(5, self.pool_size // 2)

    @property
    def max_per_worker(self) -> int:
        return self.pool_size + self.max_overflow

    @property
    def total_connections(self) -> int:
        return self.max_per_worker * self.workers

    @property
    def recommended_pg_max_connections(self) -> int:
        return self.total_connections + self.admin_reserved

    def summary(self) -> Dict:
        return {
            "eps": self.eps,
            "batch": self.batch,
            "workers": self.workers,
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "max_per_worker": self.max_per_worker,
            "total_connections": self.total_connections,
            "admin_reserved": self.admin_reserved,
            "recommended_pg_max_connections": self.recommended_pg_max_connections,
        }

    def print_report(self) -> str:
        lines = [
            "=" * 60,
            "  PostgreSQL Connection Pool Calculator",
            "=" * 60,
            "  Input:",
            f"    Expected EPS:          {self.eps:>10,}",
            f"    Batch size:             {self.batch:>10}",
            f"    Worker processes:       {self.workers:>10}",
            "",
            "  Per-Worker Pool:",
            f"    pool_size:              {self.pool_size:>10}",
            f"    max_overflow:           {self.max_overflow:>10}",
            f"    max_per_worker:         {self.max_per_worker:>10}",
            "",
            "  Aggregate:",
            f"    total_connections:      {self.total_connections:>10,}",
            f"    admin_reserved:         {self.admin_reserved:>10}",
            f"    recommended max_conn:   {self.recommended_pg_max_connections:>10}",
            "",
            "  Formulas:",
            "    pool_size = clamp(eps/1000 + batch/50, min=10, max=50)",
            "    max_overflow = max(5, pool_size // 2)",
            f"    At 10K EPS + batch 100: pool={max(10, min(50, math.ceil(10000/1000 + 100/50)))}",
            f"    At 50K EPS + batch 100: pool={max(10, min(50, math.ceil(50000/1000 + 100/50)))}",
            f"    At 100K EPS + batch 200: pool={max(10, min(50, math.ceil(100000/1000 + 200/50)))}",
            "=" * 60,
        ]
        return "\n".join(lines)


def suggest_env_vars(calc: PoolCalculator) -> str:
    """Generate docker-compose env var overrides for the given calculator."""
    return f"""# Pool config for {calc.eps} EPS / {calc.batch} batch / {calc.workers} workers
DB_EXPECTED_EPS={calc.eps}
DB_BATCH_SIZE={calc.batch}
DB_POOL_SIZE={calc.pool_size}
DB_MAX_OVERFLOW={calc.max_overflow}
POSTGRES_MAX_CONNECTIONS={calc.recommended_pg_max_connections}
"""
