"""
PCI DSS Evidence Collector — Cardholder Data Environment Detection,
CDE Access Logging, and Quarterly Scan Evidence.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.models import (
    Alert, APIKey, AuditLog, BlockedIP, Device, User,
)
from cybernova.core.utils.helpers import new_id, utcnow

log = logging.getLogger("cybernova.compliance.pci_dss")


# ── PCI DSS Scan Records ──────────────────────────────────────────────

@dataclass
class PCIDSSScanRecord:
    scan_id: str
    scan_type: str  # "asv", "internal_vulnerability", "network", "application"
    scanner_name: str
    status: str  # "passed", "failed", "in_progress"
    findings_count: int
    critical_findings: int
    high_findings: int
    scanned_at: str
    expires_at: str
    summary: str = ""


class ScanRegistry:
    """
    In-memory registry for PCI DSS scan evidence.
    Tracks ASV scans, internal vulnerability scans, and application scans.
    Scans older than 90 days are considered expired for quarterly compliance.
    """

    def __init__(self):
        self._scans: List[PCIDSSScanRecord] = []

    def record_scan(
        self,
        scan_type: str,
        scanner_name: str,
        status: str,
        findings_count: int = 0,
        critical_findings: int = 0,
        high_findings: int = 0,
        summary: str = "",
    ) -> PCIDSSScanRecord:
        now = utcnow()
        record = PCIDSSScanRecord(
            scan_id=new_id(),
            scan_type=scan_type,
            scanner_name=scanner_name,
            status=status,
            findings_count=findings_count,
            critical_findings=critical_findings,
            high_findings=high_findings,
            scanned_at=now.isoformat(),
            expires_at=(now + timedelta(days=90)).isoformat(),
            summary=summary,
        )
        self._scans.append(record)
        return record

    def get_scans(self, scan_type: Optional[str] = None) -> List[PCIDSSScanRecord]:
        if scan_type:
            return [s for s in self._scans if s.scan_type == scan_type]
        return list(self._scans)

    def latest_scan(self, scan_type: str) -> Optional[PCIDSSScanRecord]:
        matching = [s for s in self._scans if s.scan_type == scan_type]
        if not matching:
            return None
        return max(matching, key=lambda s: s.scanned_at)

    def is_current(self, scan_type: str) -> bool:
        latest = self.latest_scan(scan_type)
        if not latest:
            return False
        try:
            expires = datetime.fromisoformat(latest.expires_at)
            return expires > utcnow()
        except (ValueError, TypeError):
            return False

    def quarterly_status(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        now = now or utcnow()
        results = {}
        for scan_type in ("asv", "internal_vulnerability", "network", "application"):
            latest = self.latest_scan(scan_type)
            if latest:
                try:
                    scanned = datetime.fromisoformat(latest.scanned_at)
                    days_since = (now - scanned).days
                except (ValueError, TypeError):
                    days_since = 999
            else:
                days_since = 999

            results[scan_type] = {
                "last_scan": latest.scanned_at if latest else None,
                "days_since_last_scan": days_since,
                "status": latest.status if latest else "never_scanned",
                "findings": latest.findings_count if latest else 0,
                "is_current": days_since <= 90 if latest else False,
            }
        return results


scan_registry = ScanRegistry()


# ── PCI DSS Compliance Collector ──────────────────────────────────────

CDE_RESOURCE_TYPES = [
    "user", "settings", "api_key", "tenant", "pipeline", "automation",
]


class PCIComplianceCollector:
    """
    Collects PCI DSS compliance evidence across three domains:
      - CDE detection: devices, API keys, network exposure
      - CDE access logging: who accesses cardholder data environment
      - Quarterly scan evidence: ASV and internal scan tracking
    """

    async def detect_cde_components(
        self, tenant_id: str, db: AsyncSession,
    ) -> Dict[str, Any]:
        """Identify components within the cardholder data environment."""
        try:
            devices = await self._collect_devices(tenant_id, db)
            api_keys = await self._collect_api_keys(tenant_id, db)
            users = await self._collect_users(tenant_id, db)
            blocked_ips = await self._collect_blocked_ips(tenant_id, db)
            chd_alerts = await self._collect_chd_indicators(tenant_id, db, days=90)
            network_exposure = await self._network_exposure(tenant_id, db)

            total_cde_components = (
                devices.get("total_devices", 0)
                + api_keys.get("total_keys", 0)
                + users.get("total_users", 0)
            )

            return {
                "total_cde_components": total_cde_components,
                "devices": devices,
                "api_keys": api_keys,
                "users": users,
                "blocked_ips": blocked_ips,
                "chd_indicators": chd_alerts,
                "network_exposure": network_exposure,
                "status": "active" if total_cde_components > 0 else "no_data",
            }
        except Exception as e:
            log.warning("CDE detection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_cde_access_logs(
        self, tenant_id: str, db: AsyncSession, period_days: int = 90,
    ) -> Dict[str, Any]:
        """Collect CDE access logs — who accessed cardholder data environment."""
        try:
            since = utcnow() - timedelta(days=period_days)

            total = await self._count_cde_access(tenant_id, db, since)
            by_action = await self._aggregate_cde_access_by_action(tenant_id, db, since)
            by_resource = await self._aggregate_cde_access_by_resource(tenant_id, db, since)
            active_cde_users = await self._count_cde_active_users(tenant_id, db, since)
            top_cde_users = await self._top_cde_users(tenant_id, db, since, limit=10)

            return {
                "period_days": period_days,
                "period_start": since.isoformat(),
                "total_cde_access_events": total,
                "actions_breakdown": by_action,
                "resources_accessed": by_resource,
                "active_cde_users": active_cde_users,
                "top_cde_users": top_cde_users,
                "status": "active" if total > 0 else "no_data",
            }
        except Exception as e:
            log.warning("CDE access log collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_scan_evidence(
        self, tenant_id: str, db: AsyncSession,
    ) -> Dict[str, Any]:
        """Collect evidence of quarterly ASV scans and internal vulnerability scans."""
        try:
            quarterly = scan_registry.quarterly_status()
            all_scans = scan_registry.get_scans()

            return {
                "scan_count": len(all_scans),
                "scans": [
                    {
                        "scan_id": s.scan_id,
                        "scan_type": s.scan_type,
                        "scanner_name": s.scanner_name,
                        "status": s.status,
                        "findings_count": s.findings_count,
                        "critical_findings": s.critical_findings,
                        "high_findings": s.high_findings,
                        "scanned_at": s.scanned_at,
                        "expires_at": s.expires_at,
                        "summary": s.summary,
                    }
                    for s in sorted(all_scans, key=lambda x: x.scanned_at, reverse=True)
                ],
                "quarterly_scan_status": quarterly,
                "all_scans_current": all(
                    q["is_current"] for q in quarterly.values()
                ) if quarterly else False,
                "asv_scans_current": quarterly.get("asv", {}).get("is_current", False),
                "vulnerability_scans_current": quarterly.get(
                    "internal_vulnerability", {}
                ).get("is_current", False),
                "status": "active" if len(all_scans) > 0 else "no_data",
            }
        except Exception as e:
            log.warning("Scan evidence collection failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def collect_all(
        self, tenant_id: str, db: AsyncSession, period_days: int = 90,
    ) -> Dict[str, Any]:
        """Collect all PCI DSS evidence categories."""
        cde = await self.detect_cde_components(tenant_id, db)
        access = await self.collect_cde_access_logs(tenant_id, db, period_days)
        scans = await self.collect_scan_evidence(tenant_id, db)

        return {
            "collected_at": utcnow().isoformat(),
            "tenant_id": tenant_id,
            "period_days": period_days,
            "cde_components": cde,
            "cde_access_logs": access,
            "scan_evidence": scans,
        }

    # ── CDE detection helpers ──────────────────────────────────────────

    async def _collect_devices(self, tenant_id: str, db: AsyncSession) -> Dict[str, Any]:
        result = await db.execute(
            select(func.count(Device.id)).where(Device.tenant_id == tenant_id)
        )
        total = result.scalar() or 0
        result = await db.execute(
            select(func.count(Device.id)).where(
                Device.tenant_id == tenant_id, Device.is_active,
            )
        )
        active = result.scalar() or 0
        result = await db.execute(
            select(func.count(func.distinct(Device.os_type))).where(
                Device.tenant_id == tenant_id,
            )
        )
        os_types = result.scalar() or 0
        return {
            "total_devices": total,
            "active_devices": active,
            "distinct_os_types": os_types,
        }

    async def _collect_api_keys(self, tenant_id: str, db: AsyncSession) -> Dict[str, Any]:
        result = await db.execute(
            select(func.count(APIKey.id)).where(APIKey.tenant_id == tenant_id)
        )
        total = result.scalar() or 0
        result = await db.execute(
            select(func.count(APIKey.id)).where(
                APIKey.tenant_id == tenant_id, APIKey.is_active,
            )
        )
        active = result.scalar() or 0
        return {
            "total_keys": total,
            "active_keys": active,
        }

    async def _collect_users(self, tenant_id: str, db: AsyncSession) -> Dict[str, Any]:
        result = await db.execute(
            select(func.count(User.id)).where(User.tenant_id == tenant_id)
        )
        total = result.scalar() or 0
        result = await db.execute(
            select(func.count(User.id)).where(
                User.tenant_id == tenant_id, User.is_active,
            )
        )
        active = result.scalar() or 0
        return {
            "total_users": total,
            "active_users": active,
        }

    async def _collect_blocked_ips(self, tenant_id: str, db: AsyncSession) -> Dict[str, Any]:
        result = await db.execute(
            select(func.count(BlockedIP.id)).where(BlockedIP.tenant_id == tenant_id)
        )
        total = result.scalar() or 0
        result = await db.execute(
            select(func.count(BlockedIP.id)).where(
                BlockedIP.tenant_id == tenant_id,
                BlockedIP.expires_at.is_(None) | (BlockedIP.expires_at > utcnow()),
            )
        )
        active = result.scalar() or 0
        return {
            "total_blocked_ips": total,
            "active_blocked_ips": active,
        }

    async def _collect_chd_indicators(
        self, tenant_id: str, db: AsyncSession, days: int = 90,
    ) -> Dict[str, Any]:
        since = utcnow() - timedelta(days=days)
        result = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= since,
            )
        )
        total_alerts = result.scalar() or 0
        result = await db.execute(
            select(func.count(func.distinct(Alert.source_ip))).where(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= since,
                Alert.source_ip.isnot(None),
            )
        )
        distinct_source_ips = result.scalar() or 0
        result = await db.execute(
            select(func.count(func.distinct(Alert.dest_ip))).where(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= since,
                Alert.dest_ip.isnot(None),
            )
        )
        distinct_dest_ips = result.scalar() or 0
        return {
            "total_alerts_in_period": total_alerts,
            "distinct_source_ips": distinct_source_ips,
            "distinct_dest_ips": distinct_dest_ips,
        }

    async def _network_exposure(self, tenant_id: str, db: AsyncSession) -> Dict[str, Any]:
        result = await db.execute(
            select(func.count(func.distinct(Device.ip_address))).where(
                Device.tenant_id == tenant_id,
                Device.ip_address.isnot(None),
            )
        )
        unique_ips = result.scalar() or 0
        return {
            "unique_device_ips": unique_ips,
        }

    # ── CDE access log helpers ─────────────────────────────────────────

    async def _count_cde_access(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> int:
        result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(CDE_RESOURCE_TYPES),
            )
        )
        return result.scalar() or 0

    async def _aggregate_cde_access_by_action(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> Dict[str, int]:
        result = await db.execute(
            select(AuditLog.action, func.count(AuditLog.id))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(CDE_RESOURCE_TYPES),
            )
            .group_by(AuditLog.action)
        )
        return {row[0]: row[1] for row in result}

    async def _aggregate_cde_access_by_resource(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> Dict[str, int]:
        result = await db.execute(
            select(AuditLog.resource_type, func.count(AuditLog.id))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(CDE_RESOURCE_TYPES),
            )
            .group_by(AuditLog.resource_type)
        )
        return {row[0]: row[1] for row in result}

    async def _count_cde_active_users(
        self, tenant_id: str, db: AsyncSession, since: datetime,
    ) -> int:
        result = await db.execute(
            select(func.count(func.distinct(AuditLog.user_id)))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(CDE_RESOURCE_TYPES),
                AuditLog.user_id.isnot(None),
            )
        )
        return result.scalar() or 0

    async def _top_cde_users(
        self, tenant_id: str, db: AsyncSession, since: datetime, limit: int = 10,
    ) -> List[Dict[str, Any]]:
        result = await db.execute(
            select(AuditLog.user_id, func.count(AuditLog.id))
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.timestamp >= since,
                AuditLog.resource_type.in_(CDE_RESOURCE_TYPES),
                AuditLog.user_id.isnot(None),
            )
            .group_by(AuditLog.user_id)
            .order_by(func.count(AuditLog.id).desc())
            .limit(limit)
        )
        return [{"user_id": row[0], "access_count": row[1]} for row in result]


pci_collector = PCIComplianceCollector()
