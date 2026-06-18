from __future__ import annotations

from typing import Any, Dict, List

from cybernova.detection.ransomware.indicators import (
    RansomwareIndicator, STAGE_NAMES,
)


STAGE_THRESHOLDS = {
    1: 0.4,
    2: 0.5,
    3: 0.6,
    4: 0.7,
}

STAGE_WEIGHTS = {
    1: 0.15,
    2: 0.20,
    3: 0.40,
    4: 0.25,
}

FINAL_CONFIDENCE_THRESHOLDS = [
    (0.8, "critical", "Ransomware attack confirmed"),
    (0.6, "high", "Ransomware attack highly likely"),
    (0.4, "medium", "Suspicious ransomware indicators"),
    (0.2, "low", "Minor ransomware indicators"),
    (0.0, "info", "No ransomware indicators"),
]


def compute_stage_score(indicators_fired: List[RansomwareIndicator], stage: int) -> float:
    stage_indicators = [i for i in indicators_fired if i.stage == stage]
    if not stage_indicators:
        return 0.0

    total_weight = sum(i.weight for i in stage_indicators)
    max_possible = sum(i.weight for i in _all_indicators_for_stage(stage))

    if max_possible == 0:
        return 0.0

    raw_score = min(total_weight / max_possible, 1.0)
    n_fired = len(stage_indicators)
    n_total = len(_all_indicators_for_stage(stage))

    coverage = n_fired / max(n_total, 1)
    return raw_score * 0.7 + coverage * 0.3


def compute_chain_confidence(indicators_fired: List[RansomwareIndicator]) -> Dict[str, Any]:
    stage_scores: Dict[int, float] = {}
    for stage in sorted(STAGE_NAMES.keys()):
        stage_scores[stage] = compute_stage_score(indicators_fired, stage)

    progressive_score = 0.0
    stages_fired = 0
    for stage in sorted(STAGE_NAMES.keys()):
        score = stage_scores[stage]
        if score >= STAGE_THRESHOLDS[stage]:
            stages_fired += 1
            progressive_score += score * STAGE_WEIGHTS[stage]
        else:
            progressive_score += score * STAGE_WEIGHTS[stage] * 0.3

    max_progression = sum(STAGE_WEIGHTS.values())
    confidence = min(progressive_score / max_progression, 1.0) if max_progression > 0 else 0

    if stages_fired >= 3:
        confidence = min(confidence * 1.2, 1.0)

    severity = "info"
    label = "No ransomware indicators"
    for threshold, sev, lbl in FINAL_CONFIDENCE_THRESHOLDS:
        if confidence >= threshold:
            severity = sev
            label = lbl
            break

    return {
        "confidence": round(confidence, 4),
        "severity": severity,
        "label": label,
        "stages_fired": stages_fired,
        "total_stages": len(STAGE_NAMES),
        "stage_scores": {str(k): round(v, 4) for k, v in stage_scores.items()},
        "stage_names": {str(k): v for k, v in STAGE_NAMES.items()},
        "progression": "chain_complete" if stages_fired >= 3 else (
            "encryption_stage" if stages_fired >= 2 else "early_warning"
        ),
    }


def _all_indicators_for_stage(stage: int) -> List[RansomwareIndicator]:
    from cybernova.detection.ransomware.indicators import ALL_INDICATORS
    return [i for i in ALL_INDICATORS if i.stage == stage]
