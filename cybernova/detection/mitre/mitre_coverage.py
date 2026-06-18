"""
CyberNova — MITRE ATT&CK Coverage Analysis
Analyzes which techniques/tactics are covered by currently active detection rules.
"""
from __future__ import annotations

import logging
from typing import Dict, List

from cybernova.detection.rules_engine.rules import rule_engine, DetectionRule
from cybernova.detection.mitre.mitre import (
    MITRE_TACTICS, MITRE_TECHNIQUES,
    get_techniques_for_tactic,
)

log = logging.getLogger("cybernova.detection.mitre.coverage")


class MitreCoverage:

    def get_coverage(self) -> Dict[str, dict]:
        tactics: Dict[str, dict] = {}
        for tactic_id, tactic_name in MITRE_TACTICS.items():
            total = len(get_techniques_for_tactic(tactic_id))
            covered = 0
            covered_techniques: List[Dict[str, str]] = []
            for tech in get_techniques_for_tactic(tactic_id):
                matching_rules = self._rules_for_technique(tech["id"])
                if matching_rules:
                    covered += 1
                    covered_techniques.append({
                        "id": tech["id"],
                        "name": tech["name"],
                        "rules": [r.name for r in matching_rules],
                    })
            pct = round((covered / total * 100) if total > 0 else 0, 1)
            tactics[tactic_id] = {
                "name": tactic_name,
                "total_techniques": total,
                "covered_techniques": covered,
                "coverage_pct": pct,
                "techniques": covered_techniques,
            }
        return tactics

    def get_summary(self) -> Dict[str, any]:
        tactics = self.get_coverage()
        total_techniques = sum(t["total_techniques"] for t in tactics.values())
        total_covered = sum(t["covered_techniques"] for t in tactics.values())
        all_rules = rule_engine.list_rules()
        rules_with_mitre = sum(
            1 for r in all_rules
            if r.get("mitre_tactic") or r.get("mitre_technique")
        )

        return {
            "total_techniques": total_techniques,
            "covered_techniques": total_covered,
            "overall_coverage_pct": round((total_covered / total_techniques * 100) if total_techniques > 0 else 0, 1),
            "total_tactics": len(tactics),
            "total_rules": len(all_rules),
            "rules_with_mitre": rules_with_mitre,
            "tactics": tactics,
        }

    def get_uncovered_tactics(self) -> List[Dict[str, str]]:
        uncovered = []
        for tactic_id, tactic_name in MITRE_TACTICS.items():
            covered = self._tactic_coverage(tactic_id)
            if covered < 1:
                uncovered.append({"id": tactic_id, "name": tactic_name})
        return uncovered

    def get_uncovered_techniques(self) -> List[Dict[str, str]]:
        uncovered = []
        for tid, info in MITRE_TECHNIQUES.items():
            if not self._rules_for_technique(tid):
                uncovered.append({"id": tid, "name": info["name"], "tactic": info["tactic"]})
        return uncovered

    def get_subtechniques_for_technique(self, technique_id: str) -> List[Dict[str, str]]:
        prefix = technique_id + "."
        return [
            {"id": tid, "name": info["name"]}
            for tid, info in MITRE_TECHNIQUES.items()
            if tid.startswith(prefix)
        ]

    def _tactic_coverage(self, tactic_id: str) -> int:
        count = 0
        for tech in get_techniques_for_tactic(tactic_id):
            if self._rules_for_technique(tech["id"]):
                count += 1
        return count

    def _rules_for_technique(self, technique_id: str) -> List[DetectionRule]:
        # Check exact match and parent technique match
        matching = []
        for rule in rule_engine.rules:
            if not hasattr(rule, "mitre_technique") or not rule.mitre_technique:
                continue
            if rule.mitre_technique == technique_id:
                matching.append(rule)
            elif "." in technique_id:
                parent = technique_id.split(".")[0]
                if rule.mitre_technique == parent:
                    matching.append(rule)
            elif "." in (rule.mitre_technique or ""):
                child_parent = rule.mitre_technique.split(".")[0]
                if child_parent == technique_id:
                    matching.append(rule)
        return matching


mitre_coverage = MitreCoverage()
