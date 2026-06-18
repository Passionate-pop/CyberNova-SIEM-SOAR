"""
CyberNova — Sigma Rule Converter
Converts parsed SigmaRule objects into RuleEngine DetectionRule objects.
"""
from __future__ import annotations

import logging
from typing import Optional

from cybernova.detection.rules_engine.rules import DetectionRule
from cybernova.detection.sigma.sigma_parser import SigmaParser, sigma_parser

log = logging.getLogger("cybernova.detection.sigma.converter")


class SigmaConverter:

    def convert(self, sigma_rule: SigmaParser.SigmaRule) -> Optional[DetectionRule]:
        try:
            conditions = SigmaParser.sigma_to_conditions(
                sigma_rule.detection, sigma_rule.condition
            )
            if not conditions:
                log.warning("Sigma rule '%s' produced no conditions, skipping", sigma_rule.title)
                return None

            rule_name = self._name_from_title(sigma_rule.title, sigma_rule.id)
            description = sigma_rule.description or sigma_rule.title
            if sigma_rule.references:
                refs = "; ".join(sigma_rule.references[:3])
                description = f"{description} [Ref: {refs}]"

            rule = DetectionRule(
                name=rule_name,
                severity=sigma_rule.severity,
                conditions=conditions,
                risk_score=sigma_rule.risk_score,
                description=description,
            )
            rule.mitre_tactic = sigma_rule.mitre_tactics[0] if sigma_rule.mitre_tactics else None
            rule.mitre_technique = sigma_rule.mitre_techniques[0] if sigma_rule.mitre_techniques else None
            return rule
        except (AttributeError, KeyError, TypeError, ValueError) as e:
            log.error("Failed to convert Sigma rule '%s': %s", sigma_rule.title, e)
            return None

    def convert_raw(self, raw: dict) -> Optional[DetectionRule]:
        parsed = sigma_parser.parse(raw)
        return self.convert(parsed)

    def convert_yaml(self, yaml_str: str) -> Optional[DetectionRule]:
        parsed = sigma_parser.parse_yaml_str(yaml_str)
        return self.convert(parsed)

    @staticmethod
    def _name_from_title(title: str, rule_id: Optional[str] = None) -> str:
        name = title.lower().strip()
        name = name.replace(" ", "_").replace("-", "_").replace("/", "_")
        name = "".join(c for c in name if c.isalnum() or c == "_")
        name = name.strip("_")[:100]
        if not name:
            name = f"sigma_rule_{rule_id[:8]}" if rule_id else "sigma_rule"
        return name


sigma_converter = SigmaConverter()
