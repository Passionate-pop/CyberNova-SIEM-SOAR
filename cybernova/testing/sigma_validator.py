from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import yaml

log = logging.getLogger("cybernova.testing.sigma_validator")

REQUIRED_FIELDS = ["title", "detection", "logsource"]
RECOMMENDED_FIELDS = ["id", "level"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_LOGSOURCE_KEYS = {"category", "product", "service"}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class SigmaValidationError:
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message

    def to_dict(self) -> Dict[str, str]:
        return {"field": self.field, "message": self.message}


class SigmaValidationResult:
    def __init__(
        self,
        valid: bool,
        errors: List[SigmaValidationError],
        warnings: List[SigmaValidationError],
        rule_name: Optional[str] = None,
        severity: Optional[str] = None,
        risk_score: Optional[float] = None,
    ):
        self.valid = valid
        self.errors = errors
        self.warnings = warnings
        self.rule_name = rule_name
        self.severity = severity
        self.risk_score = risk_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
        }


def severity_to_risk_score(level: str) -> float:
    mapping = {
        "informational": 10.0,
        "low": 30.0,
        "medium": 50.0,
        "high": 75.0,
        "critical": 95.0,
    }
    return mapping.get(level, 50.0)


def severity_from_level(level: str) -> str:
    mapping = {
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get(level, "medium")


def validate_sigma_rule(raw: Dict[str, Any]) -> SigmaValidationResult:
    errors: List[SigmaValidationError] = []
    warnings: List[SigmaValidationError] = []

    for field in REQUIRED_FIELDS:
        if field not in raw or raw[field] is None:
            errors.append(SigmaValidationError(field, f"Missing required field: {field}"))

    if raw.get("title") is not None and not isinstance(raw["title"], str):
        errors.append(SigmaValidationError("title", "title must be a string"))
    if raw.get("title") is not None and len(raw["title"].strip()) == 0:
        errors.append(SigmaValidationError("title", "title must not be empty"))

    if raw.get("id") is not None and not isinstance(raw["id"], str):
        warnings.append(SigmaValidationError("id", "id should be a UUID string"))
    if raw.get("id") is not None and isinstance(raw["id"], str) and len(raw["id"]) == 0:
        warnings.append(SigmaValidationError("id", "id should not be empty"))

    level = raw.get("level", "medium")
    if level not in VALID_LEVELS:
        errors.append(SigmaValidationError("level", f"Invalid level '{level}'. Must be one of: {', '.join(sorted(VALID_LEVELS))}"))

    logsource = raw.get("logsource", {})
    if isinstance(logsource, dict):
        if not any(k in logsource for k in VALID_LOGSOURCE_KEYS):
            errors.append(SigmaValidationError("logsource", "logsource must include at least one of: category, product, service"))
    elif "logsource" not in [e.field for e in errors]:
        errors.append(SigmaValidationError("logsource", "logsource must be a mapping"))

    detection = raw.get("detection", {})
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append(SigmaValidationError("detection.condition", "detection must include a 'condition' field"))
        selections = [k for k in detection if k != "condition" and not k.startswith("_") and k != "timeframe"]
        if len(selections) == 0:
            errors.append(SigmaValidationError("detection", "detection must include at least one selection"))
        if "condition" in detection:
            condition = detection["condition"]
            if not isinstance(condition, str) or len(condition.strip()) == 0:
                errors.append(SigmaValidationError("detection.condition", "condition must be a non-empty string"))
    elif "detection" not in [e.field for e in errors]:
        errors.append(SigmaValidationError("detection", "detection must be a mapping"))

    rule_name = raw.get("title", "Untitled")
    severity = severity_from_level(level)
    risk_score = severity_to_risk_score(level)

    return SigmaValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        rule_name=rule_name,
        severity=severity,
        risk_score=risk_score,
    )


def validate_sigma_yaml(yaml_content: str) -> SigmaValidationResult:
    try:
        raw = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return SigmaValidationResult(
            valid=False,
            errors=[SigmaValidationError("yaml", f"YAML parse error: {e}")],
            warnings=[],
        )
    if not isinstance(raw, dict):
        return SigmaValidationResult(
            valid=False,
            errors=[SigmaValidationError("root", "Sigma rule must be a YAML mapping")],
            warnings=[],
        )
    return validate_sigma_rule(raw)


def get_highest_severity(severities: List[str]) -> str:
    if not severities:
        return "info"
    ordered = ["info", "low", "medium", "high", "critical"]
    max_idx = 0
    for s in severities:
        try:
            idx = ordered.index(s)
            if idx > max_idx:
                max_idx = idx
        except ValueError:
            pass
    return ordered[max_idx]
