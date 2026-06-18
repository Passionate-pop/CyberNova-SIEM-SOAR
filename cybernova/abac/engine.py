from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cybernova.abac.models import (
    ABACContext, ABACEvaluationResult, ABACPolicyStore,
)

log = logging.getLogger("cybernova.abac.engine")


class ABACEngine:
    def __init__(self, store: Optional[ABACPolicyStore] = None):
        self._store = store or ABACPolicyStore()
        self._eval_count: int = 0
        self._deny_count: int = 0

    @property
    def store(self) -> ABACPolicyStore:
        return self._store

    def evaluate(
        self,
        context: ABACContext,
    ) -> ABACEvaluationResult:
        self._eval_count += 1
        for policy in self._store.list_policies(enabled_only=True):
            result = policy.evaluate(context)
            if result is True:
                return ABACEvaluationResult(
                    allowed=True,
                    matched_policy=policy,
                    reason=f"Allowed by policy '{policy.name}'",
                )
            elif result is False:
                self._deny_count += 1
                return ABACEvaluationResult(
                    allowed=False,
                    matched_policy=policy,
                    reason=f"Denied by policy '{policy.name}'",
                )
        return ABACEvaluationResult(
            allowed=True,
            reason="No matching ABAC policies — default allow",
        )

    def evaluate_from_dicts(
        self,
        user_attrs: Dict[str, Any],
        resource_attrs: Optional[Dict[str, Any]] = None,
        action_attrs: Optional[Dict[str, Any]] = None,
        env_attrs: Optional[Dict[str, Any]] = None,
    ) -> ABACEvaluationResult:
        context = ABACContext(
            user_attrs=user_attrs,
            resource_attrs=resource_attrs or {},
            action_attrs=action_attrs or {},
            env_attrs=env_attrs or {},
        )
        return self.evaluate(context)

    def get_stats(self) -> Dict[str, Any]:
        policies = self._store.list_policies()
        return {
            "total_policies": len(policies),
            "enabled_policies": sum(1 for p in policies if p.enabled),
            "evaluations": self._eval_count,
            "denials": self._deny_count,
        }


abac_engine = ABACEngine()
