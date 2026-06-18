from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Set

log = logging.getLogger("cybernova.residency.controls")

DATA_RESIDENCY_DIR = Path("data/residency_policies")


class DataRegion(str, Enum):
    US_EAST = "us-east-1"
    US_WEST = "us-west-2"
    EU_WEST = "eu-west-1"
    EU_CENTRAL = "eu-central-1"
    AP_SOUTHEAST = "ap-southeast-1"
    AP_NORTHEAST = "ap-northeast-1"
    SA_EAST = "sa-east-1"
    GLOBAL = "global"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"
    PCI = "pci"


REGION_JURISDICTIONS = {
    DataRegion.US_EAST: "US",
    DataRegion.US_WEST: "US",
    DataRegion.EU_WEST: "EU",
    DataRegion.EU_CENTRAL: "EU",
    DataRegion.AP_SOUTHEAST: "APAC",
    DataRegion.AP_NORTHEAST: "APAC",
    DataRegion.SA_EAST: "LATAM",
    DataRegion.GLOBAL: "GLOBAL",
}

CLASSIFICATION_RULES = {
    DataClassification.PII: {
        "allowed_regions": {DataRegion.US_EAST, DataRegion.US_WEST, DataRegion.EU_WEST, DataRegion.EU_CENTRAL},
        "encryption_required": True,
        "retention_days": 365,
        "audit_required": True,
    },
    DataClassification.PHI: {
        "allowed_regions": {DataRegion.US_EAST, DataRegion.US_WEST},
        "encryption_required": True,
        "retention_days": 2555,
        "audit_required": True,
    },
    DataClassification.PCI: {
        "allowed_regions": {DataRegion.US_EAST, DataRegion.US_WEST, DataRegion.EU_WEST},
        "encryption_required": True,
        "retention_days": 365,
        "audit_required": True,
    },
    DataClassification.CONFIDENTIAL: {
        "allowed_regions": {DataRegion.US_EAST, DataRegion.US_WEST, DataRegion.EU_WEST, DataRegion.EU_CENTRAL},
        "encryption_required": True,
        "retention_days": 730,
        "audit_required": True,
    },
    DataClassification.RESTRICTED: {
        "allowed_regions": {DataRegion.US_EAST, DataRegion.US_WEST},
        "encryption_required": True,
        "retention_days": 2555,
        "audit_required": True,
    },
    DataClassification.INTERNAL: {
        "allowed_regions": set(DataRegion),
        "encryption_required": False,
        "retention_days": 365,
        "audit_required": False,
    },
    DataClassification.PUBLIC: {
        "allowed_regions": set(DataRegion),
        "encryption_required": False,
        "retention_days": 90,
        "audit_required": False,
    },
}


@dataclass
class ResidencyPolicy:
    id: str
    name: str
    data_classification: DataClassification
    allowed_regions: Set[str] = field(default_factory=set)
    encryption_required: bool = True
    max_retention_days: int = 365
    audit_required: bool = True
    enabled: bool = True


class DataResidencyController:
    """
    Controls where data can be stored, processed, and transmitted based on
    classification and regional regulations (GDPR, HIPAA, PCI DSS, etc.).
    """

    def __init__(self):
        self._policies: Dict[str, ResidencyPolicy] = {}
        self._load_defaults()
        self._load_custom()

    def _load_defaults(self):
        for classification, rules in CLASSIFICATION_RULES.items():
            policy = ResidencyPolicy(
                id=f"residency_{classification.value}",
                name=f"{classification.value.upper()} Data Residency",
                data_classification=classification,
                allowed_regions={r.value for r in rules["allowed_regions"]},
                encryption_required=rules["encryption_required"],
                max_retention_days=rules["retention_days"],
                audit_required=rules["audit_required"],
                enabled=True,
            )
            self._policies[policy.id] = policy

    def _load_custom(self):
        DATA_RESIDENCY_DIR.mkdir(parents=True, exist_ok=True)
        custom_file = DATA_RESIDENCY_DIR / "custom_policies.json"
        if custom_file.exists():
            try:
                with open(custom_file) as f:
                    custom = json.load(f)
                for c in custom:
                    p = ResidencyPolicy(**c)
                    self._policies[p.id] = p
            except Exception as e:
                log.warning("Failed to load custom residency policies: %s", e)

    def _save_custom(self):
        DATA_RESIDENCY_DIR.mkdir(parents=True, exist_ok=True)
        custom = [vars(p) for p in self._policies.values()]
        with open(DATA_RESIDENCY_DIR / "custom_policies.json", "w") as f:
            json.dump(custom, f, indent=2, default=str)

    def get_policies(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": p.id,
                "name": p.name,
                "data_classification": p.data_classification.value,
                "allowed_regions": sorted(p.allowed_regions),
                "encryption_required": p.encryption_required,
                "max_retention_days": p.max_retention_days,
                "audit_required": p.audit_required,
                "enabled": p.enabled,
            }
            for p in self._policies.values()
        ]

    def validate_data_operation(
        self,
        data_classification: str,
        source_region: str,
        target_region: str,
        operation: str = "store",
    ) -> Dict[str, Any]:
        """Validate whether a data operation is allowed under residency rules."""
        try:
            classification = DataClassification(data_classification)
        except ValueError:
            return {"allowed": False, "reason": f"Unknown classification: {data_classification}"}

        policy = next(
            (p for p in self._policies.values() if p.data_classification == classification),
            None,
        )
        if not policy:
            return {"allowed": False, "reason": f"No policy for classification: {data_classification}"}

        if not policy.enabled:
            return {"allowed": True, "note": "Policy disabled"}

        violations = []

        if target_region and target_region not in policy.allowed_regions:
            violations.append(f"Region '{target_region}' not allowed for {data_classification} data")

        source_jurisdiction = REGION_JURISDICTIONS.get(DataRegion(source_region), "UNKNOWN")
        target_jurisdiction = REGION_JURISDICTIONS.get(DataRegion(target_region), "UNKNOWN")

        if source_jurisdiction == "EU" and target_jurisdiction != "EU":
            violations.append("Data transfer from EU to non-EU region may require GDPR adequacy decision")

        if violations:
            return {
                "allowed": False,
                "violations": violations,
                "policy_id": policy.id,
            }

        return {
            "allowed": True,
            "policy_id": policy.id,
            "encryption_required": policy.encryption_required,
            "max_retention_days": policy.max_retention_days,
            "audit_required": policy.audit_required,
        }

    def check_retention_compliance(self, data_classification: str, current_retention_days: int) -> Dict[str, Any]:
        """Check if retention period complies with data classification policy."""
        try:
            classification = DataClassification(data_classification)
        except ValueError:
            return {"compliant": False, "reason": f"Unknown classification: {data_classification}"}

        policy = next(
            (p for p in self._policies.values() if p.data_classification == classification),
            None,
        )
        if not policy:
            return {"compliant": False, "reason": f"No policy for classification: {data_classification}"}

        if current_retention_days > policy.max_retention_days:
            return {
                "compliant": False,
                "reason": f"Retention {current_retention_days}d exceeds max {policy.max_retention_days}d",
                "max_allowed": policy.max_retention_days,
            }

        return {"compliant": True, "max_allowed": policy.max_retention_days}

    def get_jurisdiction(self, region: str) -> str:
        return REGION_JURISDICTIONS.get(DataRegion(region), "UNKNOWN")

    def list_regions(self) -> List[Dict[str, Any]]:
        return [
            {"id": r.value, "name": r.name, "jurisdiction": REGION_JURISDICTIONS[r]}
            for r in DataRegion
        ]


data_residency = DataResidencyController()
