"""
CyberNova — Sigma Rule Parser
Parses Sigma YAML detection rules into an intermediate representation.
"""
from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field as dataclass_field

log = logging.getLogger("cybernova.detection.sigma.parser")


@dataclass
class SigmaRule:
    title: str
    id: Optional[str] = None
    description: Optional[str] = None
    references: List[str] = dataclass_field(default_factory=list)
    author: Optional[str] = None
    date: Optional[str] = None
    tags: List[str] = dataclass_field(default_factory=list)
    logsource: Dict[str, str] = dataclass_field(default_factory=dict)
    detection: Dict[str, Any] = dataclass_field(default_factory=dict)
    condition: Optional[str] = None
    falsepositives: List[str] = dataclass_field(default_factory=list)
    level: str = "medium"
    mitre_tactics: List[str] = dataclass_field(default_factory=list)
    mitre_techniques: List[str] = dataclass_field(default_factory=list)

    @property
    def severity(self) -> str:
        mapping = {
            "informational": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        return mapping.get(self.level, "medium")

    @property
    def risk_score(self) -> float:
        mapping = {
            "informational": 10.0,
            "low": 30.0,
            "medium": 50.0,
            "high": 75.0,
            "critical": 95.0,
        }
        return mapping.get(self.level, 50.0)


class SigmaParser:

    SUPPORTED_MODIFIERS = {"contains", "endswith", "startswith", "re", "all", "base64", "base64offset", "wide", "utf16le"}

    def parse(self, raw: dict) -> SigmaRule:
        rule = SigmaRule(
            title=raw.get("title", "Untitled Sigma Rule"),
            id=raw.get("id"),
            description=raw.get("description"),
            references=raw.get("references", []),
            author=raw.get("author"),
            date=raw.get("date"),
            tags=raw.get("tags", []),
            logsource=raw.get("logsource", {}),
            detection=raw.get("detection", {}),
            condition=raw.get("condition"),
            falsepositives=raw.get("falsepositives", []),
            level=raw.get("level", "medium"),
        )
        for tag in rule.tags:
            tag_clean = tag.replace("attack.", "", 1)
            if re.match(r"^t\d{4}(\.\d{3})?$", tag_clean, re.IGNORECASE):
                rule.mitre_techniques.append(tag_clean.lower())
            else:
                rule.mitre_tactics.append(tag_clean.lower())
        return rule

    def parse_yaml_str(self, yaml_str: str) -> SigmaRule:
        import yaml
        raw = yaml.safe_load(yaml_str)
        if not isinstance(raw, dict):
            raise ValueError("Sigma rule must be a mapping")
        return self.parse(raw)

    @staticmethod
    def extract_field_conditions(name: str, value: Any) -> List[Tuple[str, str, Any]]:
        """
        Extract (field, operator, value) tuples from a Sigma detection entry.
        Operators: eq, contains, endswith, startswith, re
        """
        if not isinstance(value, (str, int, float, list)):
            return []

        results = []

        if "|" in name:
            field, modifier = name.rsplit("|", 1)
            modifier = modifier.strip()
        else:
            field = name
            modifier = "eq"

        if isinstance(value, list):
            for v in value:
                results.append((field, modifier, v))
        else:
            results.append((field, modifier, value))

        return results

    @staticmethod
    def sigma_to_conditions(detection: Dict[str, Any], condition_str: Optional[str] = None) -> Dict[str, Any]:
        """
        Convert Sigma detection selections into RuleEngine-compatible conditions dict.
        """
        conditions: Dict[str, Any] = {}
        selection_keys = [k for k in detection if k != "condition" and not k.startswith("_") and k != "timeframe"]

        if not selection_keys:
            return conditions

        if condition_str and "|" in condition_str and " of " in condition_str:
            parts = condition_str.split("|")
            condition_str = parts[0].strip() if " of " not in parts[0] else condition_str
            all_flag = "all of" in condition_str or "all" in condition_str.split("|")[0]
            target_names = [s.strip() for s in re.findall(r'(?:all of |any of )?(\w+)', condition_str)]
            if not target_names:
                target_names = selection_keys
            if all_flag:
                for select_name in target_names:
                    if select_name in detection and isinstance(detection[select_name], dict):
                        for k, v in detection[select_name].items():
                            detection_field = k.split("|")[0]
                            if detection_field not in conditions:
                                conditions[detection_field] = []
                            if isinstance(v, list):
                                conditions[detection_field].extend(v)
                            else:
                                conditions[detection_field].append(v)
            else:
                for select_name in target_names:
                    if select_name in detection and isinstance(detection[select_name], dict):
                        for k, v in detection[select_name].items():
                            if isinstance(v, list):
                                for item in v:
                                    conditions[k] = item
                            else:
                                conditions[k] = v
            return SigmaParser._simplify_conditions(conditions)

        for select_name in selection_keys:
            select = detection[select_name]
            if not isinstance(select, dict):
                continue
            for key, value in select.items():
                field_ops = SigmaParser.extract_field_conditions(key, value)
                for det_field, op, val in field_ops:
                    if op == "eq":
                        conditions[det_field] = val
                    elif op == "contains":
                        existing = conditions.get(det_field, [])
                        if isinstance(existing, list):
                            existing.append(val)
                            conditions[det_field] = existing
                        else:
                            conditions[det_field] = [existing, val]
                    elif op == "endswith":
                        existing = conditions.get(det_field, [])
                        entry = f"*{val}" if isinstance(val, str) else val
                        if isinstance(existing, list):
                            existing.append(entry)
                            conditions[det_field] = existing
                        else:
                            conditions[det_field] = [existing, entry]
                    elif op == "startswith":
                        existing = conditions.get(det_field, [])
                        entry = f"{val}*" if isinstance(val, str) else val
                        if isinstance(existing, list):
                            existing.append(entry)
                            conditions[det_field] = existing
                        else:
                            conditions[det_field] = [existing, entry]
                    elif op == "re":
                        conditions[det_field] = f"regex:{val}"
                    else:
                        conditions[det_field] = val
        return SigmaParser._simplify_conditions(conditions)

    @staticmethod
    def _simplify_conditions(conditions: Dict[str, Any]) -> Dict[str, Any]:
        simplified = {}
        for field, value in conditions.items():
            if isinstance(value, list) and len(value) == 1:
                simplified[field] = value[0]
            else:
                simplified[field] = value
        return simplified

    @staticmethod
    def conditions_to_rule_expression(conditions: Dict[str, Any]) -> str:
        """Convert conditions dict to a human-readable DSL expression string."""
        parts = []
        for field, value in conditions.items():
            if isinstance(value, list):
                vals = " or ".join(str(v) for v in value)
                parts.append(f"{field} in [{vals}]")
            elif isinstance(value, str) and value.startswith("regex:"):
                parts.append(f"{field} ~= {value[6:]!r}")
            else:
                parts.append(f"{field} == {value!r}")
        return " and ".join(parts) if parts else "true"


sigma_parser = SigmaParser()
