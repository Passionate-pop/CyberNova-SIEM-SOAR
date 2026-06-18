"""
CyberNova — Sigma Rule Loader
Loads Sigma YAML rules from filesystem or string, converts to DetectionRule objects,
and optionally persists to the database.
"""
from __future__ import annotations

import logging
import os
from typing import List, Optional

import yaml

from cybernova.detection.rules_engine.rules import DetectionRule, rule_engine
from cybernova.detection.sigma.sigma_converter import sigma_converter

log = logging.getLogger("cybernova.detection.sigma.loader")


class SigmaLoader:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(__file__), "rules"
        )

    def load_file(self, filepath: str) -> Optional[DetectionRule]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                log.warning("Invalid Sigma rule (not a mapping): %s", filepath)
                return None
            rule = sigma_converter.convert_raw(raw)
            if rule:
                log.info("Loaded Sigma rule: %s from %s", rule.name, filepath)
            return rule
        except (OSError, yaml.YAMLError, AttributeError, KeyError, TypeError, ValueError) as e:
            log.error("Failed to load Sigma rule %s: %s", filepath, e)
            return None

    def load_directory(self, directory: Optional[str] = None) -> List[DetectionRule]:
        target = directory or self.rules_dir
        if not os.path.isdir(target):
            log.warning("Sigma rules directory not found: %s", target)
            return []
        rules: List[DetectionRule] = []
        for fname in sorted(os.listdir(target)):
            if fname.endswith((".yml", ".yaml")):
                fpath = os.path.join(target, fname)
                rule = self.load_file(fpath)
                if rule:
                    rules.append(rule)
        log.info("Loaded %d Sigma rules from %s", len(rules), target)
        return rules

    def register_all(self, directory: Optional[str] = None) -> int:
        rules = self.load_directory(directory)
        for rule in rules:
            rule_engine.register_rule(rule)
        return len(rules)

    @staticmethod
    def from_yaml_str(yaml_str: str) -> Optional[DetectionRule]:
        return sigma_converter.convert_yaml(yaml_str)


sigma_loader = SigmaLoader()
