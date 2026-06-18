from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

log = logging.getLogger("cybernova.detection.isolation.manager")

TENANT_RULE_QUOTA = 500
TENANT_EVAL_QUOTA_PER_MIN = 10000
TENANT_CIRCUIT_BREAKER_THRESHOLD = 20


@dataclass
class TenantRuleQuota:
    tenant_id: str
    max_rules: int = TENANT_RULE_QUOTA
    max_evaluations_per_min: int = TENANT_EVAL_QUOTA_PER_MIN
    evaluation_count: int = 0
    evaluation_window_start: float = field(default_factory=time.time)
    error_count: int = 0
    circuit_open: bool = False
    circuit_open_until: float = 0.0


class TenantIsolationManager:
    def __init__(self):
        self._tenants: Dict[str, TenantRuleQuota] = {}
        self._tenant_rule_counts: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def register_tenant(self, tenant_id: str, max_rules: int = TENANT_RULE_QUOTA) -> TenantRuleQuota:
        async with self._lock:
            if tenant_id not in self._tenants:
                self._tenants[tenant_id] = TenantRuleQuota(tenant_id=tenant_id, max_rules=max_rules)
            return self._tenants[tenant_id]

    async def check_rule_quota(self, tenant_id: str) -> bool:
        async with self._lock:
            count = self._tenant_rule_counts.get(tenant_id, 0)
            quota = self._tenants.get(tenant_id)
            max_rules = quota.max_rules if quota else TENANT_RULE_QUOTA
            if count >= max_rules:
                log.warning("Tenant %s rule quota exceeded: %d >= %d", tenant_id, count, max_rules)
                return False
            return True

    async def increment_rule_count(self, tenant_id: str) -> int:
        async with self._lock:
            self._tenant_rule_counts[tenant_id] += 1
            return self._tenant_rule_counts[tenant_id]

    async def decrement_rule_count(self, tenant_id: str) -> int:
        async with self._lock:
            self._tenant_rule_counts[tenant_id] = max(0, self._tenant_rule_counts[tenant_id] - 1)
            return self._tenant_rule_counts[tenant_id]

    async def record_evaluation(self, tenant_id: str) -> bool:
        async with self._lock:
            quota = self._tenants.get(tenant_id)
            if not quota:
                quota = TenantRuleQuota(tenant_id=tenant_id)
                self._tenants[tenant_id] = quota

            now = time.time()
            if now - quota.evaluation_window_start > 60:
                quota.evaluation_count = 0
                quota.evaluation_window_start = now

            if quota.circuit_open:
                if now >= quota.circuit_open_until:
                    quota.circuit_open = False
                    log.info("Tenant %s circuit breaker reset", tenant_id)
                else:
                    return False

            quota.evaluation_count += 1
            if quota.evaluation_count > quota.max_evaluations_per_min:
                quota.error_count += 1
                if quota.error_count >= TENANT_CIRCUIT_BREAKER_THRESHOLD:
                    quota.circuit_open = True
                    quota.circuit_open_until = now + 60
                    log.warning("Tenant %s circuit breaker opened (rate limit)", tenant_id)
                return False

            return True

    async def record_error(self, tenant_id: str) -> None:
        async with self._lock:
            quota = self._tenants.get(tenant_id)
            if quota:
                quota.error_count += 1
                if quota.error_count >= TENANT_CIRCUIT_BREAKER_THRESHOLD:
                    quota.circuit_open = True
                    quota.circuit_open_until = time.time() + 120
                    log.warning("Tenant %s circuit breaker opened (errors)", tenant_id)

    async def get_tenant_status(self, tenant_id: str) -> Dict[str, Any]:
        async with self._lock:
            quota = self._tenants.get(tenant_id)
            if not quota:
                return {"tenant_id": tenant_id, "status": "unknown"}
            return {
                "tenant_id": tenant_id,
                "max_rules": quota.max_rules,
                "current_rules": self._tenant_rule_counts.get(tenant_id, 0),
                "evaluations_this_min": quota.evaluation_count,
                "max_evaluations_per_min": quota.max_evaluations_per_min,
                "error_count": quota.error_count,
                "circuit_open": quota.circuit_open,
                "circuit_open_until": datetime.fromtimestamp(quota.circuit_open_until, tz=timezone.utc).isoformat() if quota.circuit_open else None,
            }

    async def get_all_status(self) -> List[Dict[str, Any]]:
        async with self._lock:
            return [
                {
                    "tenant_id": tid,
                    "max_rules": q.max_rules,
                    "current_rules": self._tenant_rule_counts.get(tid, 0),
                    "evaluations_this_min": q.evaluation_count,
                    "error_count": q.error_count,
                    "circuit_open": q.circuit_open,
                }
                for tid, q in self._tenants.items()
            ]


tenant_isolation = TenantIsolationManager()
