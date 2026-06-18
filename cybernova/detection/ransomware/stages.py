from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.detection.ransomware.indicators import (
    ENCRYPTION_INDICATORS, EXECUTION_INDICATORS,
    POST_EXECUTION_INDICATORS, PRE_EXECUTION_INDICATORS,
    RansomwareIndicator, STAGE_NAMES,
)
from cybernova.detection.ransomware.scorer import (
    compute_chain_confidence, compute_stage_score,
)


@dataclass
class DetectionStage:
    stage: int
    name: str
    indicators_fired: List[RansomwareIndicator] = field(default_factory=list)
    score: float = 0.0
    threshold_met: bool = False
    detected_at: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


class RansomwareChain:
    def __init__(self, entity_id: str, tenant_id: str):
        self.entity_id = entity_id
        self.tenant_id = tenant_id
        self.stages: Dict[int, DetectionStage] = {
            s: DetectionStage(stage=s, name=STAGE_NAMES[s])
            for s in sorted(STAGE_NAMES.keys())
        }
        self.all_indicators: List[RansomwareIndicator] = []
        self.started_at: str = datetime.now(timezone.utc).isoformat()
        self.last_updated: str = self.started_at
        self.is_active: bool = True
        self.concluded: bool = False
        self.final_verdict: Optional[Dict[str, Any]] = None
        self._stage_indicators_map: Dict[int, List[RansomwareIndicator]] = {
            1: PRE_EXECUTION_INDICATORS,
            2: EXECUTION_INDICATORS,
            3: ENCRYPTION_INDICATORS,
            4: POST_EXECUTION_INDICATORS,
        }

    def fire_indicator(self, indicator_name: str, evidence: Optional[Dict[str, Any]] = None) -> bool:
        for stage_indicators in self._stage_indicators_map.values():
            for ind in stage_indicators:
                if ind.name == indicator_name and ind not in self.all_indicators:
                    self.all_indicators.append(ind)
                    stage = self.stages[ind.stage]
                    stage.indicators_fired.append(ind)
                    stage.detected_at = datetime.now(timezone.utc).isoformat()
                    if evidence:
                        stage.evidence[ind.name] = evidence
                    self.last_updated = datetime.now(timezone.utc).isoformat()
                    self._recompute()
                    return True
        return False

    def fire_indicators(self, indicator_names: List[str]) -> int:
        count = 0
        for name in indicator_names:
            if self.fire_indicator(name):
                count += 1
        return count

    def _recompute(self) -> None:
        for stage in self.stages.values():
            stage.score = compute_stage_score(self.all_indicators, stage.stage)
            stage.threshold_met = stage.score >= _get_threshold(stage.stage)

    def get_verdict(self) -> Dict[str, Any]:
        chain_result = compute_chain_confidence(self.all_indicators)
        self.final_verdict = {
            "entity_id": self.entity_id,
            "tenant_id": self.tenant_id,
            "chain_result": chain_result,
            "stages": {
                str(s.stage): {
                    "name": s.name,
                    "score": round(s.score, 4),
                    "threshold_met": s.threshold_met,
                    "indicators_fired": [i.name for i in s.indicators_fired],
                    "detected_at": s.detected_at,
                }
                for s in self.stages.values()
            },
            "total_indicators_fired": len(self.all_indicators),
            "duration_seconds": self._duration_seconds(),
            "started_at": self.started_at,
            "last_updated": self.last_updated,
            "concluded": self.concluded,
        }
        return self.final_verdict

    def conclude(self) -> Dict[str, Any]:
        self.is_active = False
        self.concluded = True
        return self.get_verdict()

    def _duration_seconds(self) -> float:
        try:
            start = datetime.fromisoformat(self.started_at)
            end = datetime.fromisoformat(self.last_updated)
            return (end - start).total_seconds()
        except (ValueError, TypeError):
            return 0.0


def _get_threshold(stage: int) -> float:
    from cybernova.detection.ransomware.scorer import STAGE_THRESHOLDS
    return STAGE_THRESHOLDS.get(stage, 0.5)


class RansomwareChainManager:
    def __init__(self):
        self._chains: Dict[str, RansomwareChain] = {}
        self._concluded_chains: List[RansomwareChain] = []

    def get_or_create_chain(self, entity_id: str, tenant_id: str) -> RansomwareChain:
        if entity_id not in self._chains or not self._chains[entity_id].is_active:
            self._chains[entity_id] = RansomwareChain(entity_id, tenant_id)
        return self._chains[entity_id]

    def get_chain(self, entity_id: str) -> Optional[RansomwareChain]:
        return self._chains.get(entity_id)

    def conclude_chain(self, entity_id: str) -> Optional[Dict[str, Any]]:
        chain = self._chains.get(entity_id)
        if chain and chain.is_active:
            verdict = chain.conclude()
            self._concluded_chains.append(chain)
            del self._chains[entity_id]
            return verdict
        return None

    def get_active_chains(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        chains = list(self._chains.values())
        if tenant_id:
            chains = [c for c in chains if c.tenant_id == tenant_id]
        return [c.get_verdict() for c in chains if c.is_active]

    def get_concluded_chains(self, tenant_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        chains = self._concluded_chains[-limit:]
        if tenant_id:
            chains = [c for c in chains if c.tenant_id == tenant_id]
        return [c.get_verdict() for c in chains]

    def get_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        all_chains = list(self._chains.values()) + self._concluded_chains
        if tenant_id:
            all_chains = [c for c in all_chains if c.tenant_id == tenant_id]
        if not all_chains:
            return {"total_chains": 0, "active_chains": 0, "avg_confidence": 0}
        confidences = [c.final_verdict["chain_result"]["confidence"] for c in all_chains if c.final_verdict]
        return {
            "total_chains": len(all_chains),
            "active_chains": sum(1 for c in self._chains.values() if c.is_active),
            "concluded_chains": len(self._concluded_chains),
            "avg_confidence": round(sum(confidences) / max(len(confidences), 1), 4),
            "max_confidence": round(max(confidences), 4) if confidences else 0,
        }


chain_manager = RansomwareChainManager()
