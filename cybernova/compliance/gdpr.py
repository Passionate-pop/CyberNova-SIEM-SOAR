"""
GDPR Evidence Collector — Data Subject Rights, DPIA Documentation,
Data Retention Enforcement, and Consent Management.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import AuditLog
from cybernova.storage.retention import retention_manager
from cybernova.residency.controls import data_residency
from cybernova.core.utils.helpers import new_id, utcnow

log = logging.getLogger("cybernova.compliance.gdpr")


# ── DPIA (Data Protection Impact Assessment) Records ───────────────

@dataclass
class DPIARecord:
    dpia_id: str
    processing_activity: str
    risk_level: str  # "low", "medium", "high"
    status: str  # "draft", "reviewed", "approved", "outdated"
    assessed_at: str
    reviewed_at: str = ""
    next_review_at: str = ""
    mitigation_measures: str = ""
    data_categories: List[str] = field(default_factory=list)


class DPIARegistry:
    """In-memory registry for Data Protection Impact Assessments (Art. 35)."""

    def __init__(self):
        self._dpias: List[DPIARecord] = []

    def record_dpia(
        self,
        processing_activity: str,
        risk_level: str = "medium",
        status: str = "draft",
        mitigation_measures: str = "",
        data_categories: Optional[List[str]] = None,
    ) -> DPIARecord:
        now = utcnow()
        next_review = (now + timedelta(days=365)).isoformat()
        record = DPIARecord(
            dpia_id=new_id(),
            processing_activity=processing_activity,
            risk_level=risk_level,
            status=status,
            assessed_at=now.isoformat(),
            next_review_at=next_review,
            mitigation_measures=mitigation_measures,
            data_categories=data_categories or [],
        )
        self._dpias.append(record)
        return record

    def get_dpias(self, status: Optional[str] = None) -> List[DPIARecord]:
        if status:
            return [d for d in self._dpias if d.status == status]
        return list(self._dpias)

    def count_high_risk(self) -> int:
        return sum(1 for d in self._dpias if d.risk_level == "high")

    def overall_status(self) -> Dict[str, Any]:
        now = utcnow()
        total = len(self._dpias)
        high_risk = self.count_high_risk()
        overdue_review = sum(
            1 for d in self._dpias
            if d.next_review_at and _parse_iso_or_future(d.next_review_at) <= now
        )
        status_counts = {}
        for d in self._dpias:
            status_counts[d.status] = status_counts.get(d.status, 0) + 1
        return {
            "total_dpias": total,
            "high_risk_dpias": high_risk,
            "overdue_review": overdue_review,
            "status_breakdown": status_counts,
            "all_approved": all(d.status == "approved" for d in self._dpias) if self._dpias else False,
        }


# ── Data Subject Request Records ───────────────────────────────────

@dataclass
class DataSubjectRequestRecord:
    request_id: str
    user_id: str
    request_type: str  # "access", "deletion", "portability", "objection", "rectification"
    status: str  # "submitted", "in_progress", "completed", "denied", "expired"
    submitted_at: str
    completed_at: str = ""
    response_summary: str = ""
    notes: str = ""


class DataSubjectRequestRegistry:
    """In-memory registry for Data Subject Access Requests (Art. 15, 17, 20)."""

    def __init__(self):
        self._requests: List[DataSubjectRequestRecord] = []

    def record_request(
        self,
        user_id: str,
        request_type: str = "access",
        status: str = "submitted",
    ) -> DataSubjectRequestRecord:
        record = DataSubjectRequestRecord(
            request_id=new_id(),
            user_id=user_id,
            request_type=request_type,
            status=status,
            submitted_at=utcnow().isoformat(),
        )
        self._requests.append(record)
        return record

    def complete_request(self, request_id: str, response_summary: str = "") -> bool:
        for r in self._requests:
            if r.request_id == request_id:
                r.status = "completed"
                r.completed_at = utcnow().isoformat()
                r.response_summary = response_summary or r.response_summary
                return True
        return False

    def get_requests(
        self,
        request_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[DataSubjectRequestRecord]:
        results = list(self._requests)
        if request_type:
            results = [r for r in results if r.request_type == request_type]
        if status:
            results = [r for r in results if r.status == status]
        return results

    def overall_status(self) -> Dict[str, Any]:
        total = len(self._requests)
        completed = sum(1 for r in self._requests if r.status == "completed")
        pending = sum(1 for r in self._requests if r.status in ("submitted", "in_progress"))
        denied = sum(1 for r in self._requests if r.status == "denied")
        return {
            "total_requests": total,
            "completed_requests": completed,
            "pending_requests": pending,
            "denied_requests": denied,
            "all_completed": completed == total if self._requests else False,
        }


# ── Consent Records ────────────────────────────────────────────────

@dataclass
class ConsentRecord:
    consent_id: str
    user_id: str
    purpose: str
    granted: bool
    granted_at: str
    revoked_at: str = ""
    source: str = "explicit"  # "explicit", "implicit", "contractual"


class ConsentRegistry:
    """In-memory registry for data subject consent (Art. 7)."""

    def __init__(self):
        self._consents: List[ConsentRecord] = []

    def grant_consent(
        self,
        user_id: str,
        purpose: str,
        source: str = "explicit",
    ) -> ConsentRecord:
        record = ConsentRecord(
            consent_id=new_id(),
            user_id=user_id,
            purpose=purpose,
            granted=True,
            granted_at=utcnow().isoformat(),
            source=source,
        )
        self._consents.append(record)
        return record

    def revoke_consent(self, user_id: str, purpose: str) -> bool:
        for c in self._consents:
            if c.user_id == user_id and c.purpose == purpose and c.granted:
                c.granted = False
                c.revoked_at = utcnow().isoformat()
                return True
        return False

    def get_active_consents(self, user_id: Optional[str] = None) -> List[ConsentRecord]:
        results = [c for c in self._consents if c.granted]
        if user_id:
            results = [c for c in results if c.user_id == user_id]
        return results

    def overall_status(self) -> Dict[str, Any]:
        total = len(self._consents)
        active = sum(1 for c in self._consents if c.granted)
        revoked = total - active
        purposes = set(c.purpose for c in self._consents)
        return {
            "total_consents": total,
            "active_consents": active,
            "revoked_consents": revoked,
            "distinct_purposes": sorted(purposes),
        }


def _parse_iso_or_future(iso_str: str) -> datetime:
    try:
        return datetime.fromisoformat(iso_str)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc) + timedelta(days=365)


dpia_registry = DPIARegistry()
dsar_registry = DataSubjectRequestRegistry()
consent_registry = ConsentRegistry()


# ── GDPR Compliance Collector ──────────────────────────────────────

GDPR_PERSONAL_DATA_RESOURCE_TYPES = [
    "user", "settings", "profile", "email", "contact",
]

GDPR_AUDIT_ACTIONS = [
    "user_created", "user_updated", "user_deleted",
    "login", "login_failed", "password_changed",
    "email_changed", "settings_updated",
]


class GDPRComplianceCollector:
    """
    Collects GDPR compliance evidence across four domains:
      - Data subject rights: access request logs and deletion evidence
      - DPIA documentation: Data Protection Impact Assessment records
      - Data retention enforcement: policy compliance checks
      - Consent management: consent tracking
    """

    async def collect_data_subject_access_logs(
        self, tenant_id: str, db: AsyncSession, period_days: int = 90,
    ) -> Dict[str, Any]:
        """Collect evidence of data subject access — PII-related audit logs."""
        try:
            since = utcnow() - timedelta(days=period_days)

            total = await self._count_pii_access(tenant_id, db, since)
            by_action = await self._aggregate_pii_access_by_action(tenant_id, db, since)
            by_resource = await self._aggregate_pii_access_by_resource(tenant_id, db, since)
            active_users = await self._count_pii_active_users(tenant_id, db, since)
            top_users = await self._top_pii_users(tenant_id, db, since, limit=10)

            dsar_status = dsar_registry.overall_status()
            deletion_requests = dsar_registry.get_requests(request_type="deletion")
            completed_deletions = sum(1 for r in deletion_requests if r.status == "completed")

            return {
                "period_days": period_days,
                "period_start": since.isoformat(),
                "total_pii_access_events": total,
                "actions_breakdown": by_action,
                "resources_accessed": by_resource,
                "active_users_with_pii_access": active_users,
                "top_users": top_users,
                "data_subject_requests": dsar_status,
                "deletion_requests_total": len(deletion_requests),
                "completed_deletions": completed_deletions,
                "status": "active" if total > 0 else "no_data",
            }
        except Exception as e:
            log.warning("Data subject access log collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_deletion_evidence(
        self, tenant_id: str, db: AsyncSession, period_days: int = 90,
    ) -> Dict[str, Any]:
        """Collect evidence of right-to-deletion fulfillment (Art. 17)."""
        try:
            since = utcnow() - timedelta(days=period_days)

            deletion_reqs = dsar_registry.get_requests(
                request_type="deletion", status="completed",
            )
            pending_deletions = dsar_registry.get_requests(
                request_type="deletion", status="submitted",
            )

            audit_deletions = await self._count_audit_user_deletions(tenant_id, db, since)

            return {
                "period_days": period_days,
                "period_start": since.isoformat(),
                "completed_deletion_requests": len(deletion_reqs),
                "pending_deletion_requests": len(pending_deletions),
                "deletion_requests": [
                    {
                        "request_id": r.request_id,
                        "user_id": r.user_id,
                        "submitted_at": r.submitted_at,
                        "completed_at": r.completed_at,
                        "response_summary": r.response_summary,
                    }
                    for r in sorted(
                        deletion_reqs + pending_deletions,
                        key=lambda x: x.submitted_at, reverse=True,
                    )
                ],
                "audit_log_user_deletions": audit_deletions,
                "status": "active" if (len(deletion_reqs) + len(pending_deletions)) > 0 else "no_data",
            }
        except Exception as e:
            log.warning("Deletion evidence collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_dpia_evidence(
        self, tenant_id: str, db: AsyncSession,
    ) -> Dict[str, Any]:
        """Collect DPIA documentation evidence (Art. 35)."""
        try:
            status = dpia_registry.overall_status()
            dpias = dpia_registry.get_dpias()

            return {
                "dpia_count": len(dpias),
                "dpia_status": status,
                "dpias": [
                    {
                        "dpia_id": d.dpia_id,
                        "processing_activity": d.processing_activity,
                        "risk_level": d.risk_level,
                        "status": d.status,
                        "assessed_at": d.assessed_at,
                        "next_review_at": d.next_review_at,
                        "mitigation_measures": d.mitigation_measures,
                        "data_categories": d.data_categories,
                    }
                    for d in sorted(dpias, key=lambda x: x.assessed_at, reverse=True)
                ],
                "high_risk_count": status["high_risk_dpias"],
                "overdue_review_count": status["overdue_review"],
                "status": "compliant" if status["all_approved"] else "warning",
            }
        except Exception as e:
            log.warning("DPIA evidence collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_retention_enforcement(
        self, tenant_id: str, db: AsyncSession,
    ) -> Dict[str, Any]:
        """Collect evidence of data retention enforcement (Art. 5(1)(e))."""
        try:
            policies = retention_manager.get_policies()
            pii_retention = self._check_pii_retention_policies()
            residency_check = data_residency.check_retention_compliance(
                "pii",
                policies.get("audit_logs", retention_manager._policies["audit_logs"]).retention_days
                if "audit_logs" in policies else 365,
            )

            return {
                "retention_policies": {
                    k: v.to_dict() for k, v in policies.items()
                },
                "pii_retention_check": pii_retention,
                "residency_retention_check": residency_check,
                "policy_count": len(policies),
                "min_retention_days": min(p.retention_days for p in policies.values()),
                "max_retention_days": max(p.retention_days for p in policies.values()),
                "status": "active" if len(policies) > 0 else "no_data",
            }
        except Exception as e:
            log.warning("Retention enforcement collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_consent_evidence(
        self, tenant_id: str, db: AsyncSession,
    ) -> Dict[str, Any]:
        """Collect evidence of consent management (Art. 7)."""
        try:
            status = consent_registry.overall_status()
            active_consents = consent_registry.get_active_consents()

            return {
                "consent_status": status,
                "active_consents": [
                    {
                        "consent_id": c.consent_id,
                        "user_id": c.user_id,
                        "purpose": c.purpose,
                        "granted_at": c.granted_at,
                        "source": c.source,
                    }
                    for c in sorted(active_consents, key=lambda x: x.granted_at, reverse=True)
                ],
                "consent_count": len(active_consents),
                "status": "active" if status["active_consents"] > 0 else "no_data",
            }
        except Exception as e:
            log.warning("Consent evidence collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_all(
        self, tenant_id: str, db: AsyncSession, period_days: int = 90,
    ) -> Dict[str, Any]:
        """Collect all GDPR evidence categories."""
        access = await self.collect_data_subject_access_logs(tenant_id, db, period_days)
        deletion = await self.collect_deletion_evidence(tenant_id, db, period_days)
        dpia = await self.collect_dpia_evidence(tenant_id, db)
        retention = await self.collect_retention_enforcement(tenant_id, db)
        consent = await self.collect_consent_evidence(tenant_id, db)

        return {
            "collected_at": utcnow().isoformat(),
            "tenant_id": tenant_id,
            "period_days": period_days,
            "data_subject_access_logs": access,
            "deletion_evidence": deletion,
            "dpia_evidence": dpia,
            "retention_enforcement": retention,
            "consent_evidence": consent,
        }

    # ── PII access log helpers ─────────────────────────────────────

    async def _count_pii_access(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> int:
        result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(GDPR_PERSONAL_DATA_RESOURCE_TYPES),
            )
        )
        return result.scalar() or 0

    async def _aggregate_pii_access_by_action(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> Dict[str, int]:
        result = await db.execute(
            select(AuditLog.action, func.count(AuditLog.id))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(GDPR_PERSONAL_DATA_RESOURCE_TYPES),
            )
            .group_by(AuditLog.action)
        )
        return {row[0]: row[1] for row in result}

    async def _aggregate_pii_access_by_resource(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> Dict[str, int]:
        result = await db.execute(
            select(AuditLog.resource_type, func.count(AuditLog.id))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(GDPR_PERSONAL_DATA_RESOURCE_TYPES),
            )
            .group_by(AuditLog.resource_type)
        )
        return {row[0]: row[1] for row in result}

    async def _count_pii_active_users(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> int:
        result = await db.execute(
            select(func.count(func.distinct(AuditLog.user_id)))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.user_id.isnot(None),
                AuditLog.resource_type.in_(GDPR_PERSONAL_DATA_RESOURCE_TYPES),
            )
        )
        return result.scalar() or 0

    async def _top_pii_users(
        self, tenant_id: str, db: AsyncSession, since: datetime, limit: int = 10,
    ) -> List[Dict[str, Any]]:
        result = await db.execute(
            select(AuditLog.user_id, func.count(AuditLog.id))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.user_id.isnot(None),
                AuditLog.resource_type.in_(GDPR_PERSONAL_DATA_RESOURCE_TYPES),
            )
            .group_by(AuditLog.user_id)
            .order_by(func.count(AuditLog.id).desc())
            .limit(limit)
        )
        return [{"user_id": row[0], "access_count": row[1]} for row in result]

    async def _count_audit_user_deletions(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> int:
        result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.action == "user_deleted",
            )
        )
        return result.scalar() or 0

    def _check_pii_retention_policies(self) -> Dict[str, Any]:
        policies = retention_manager.get_policies()
        pii_related = {k: v for k, v in policies.items() if k in (
            "audit_logs", "incidents", "response_actions",
        )}
        return {
            "pii_related_policies": {k: v.to_dict() for k, v in pii_related.items()},
            "audit_log_retention_days": policies.get("audit_logs", retention_manager._policies["audit_logs"]).retention_days,
            "compliant": all(p.retention_days <= 365 for p in pii_related.values()),
        }


gdpr_collector = GDPRComplianceCollector()
