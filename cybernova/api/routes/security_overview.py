"""
CyberNova — Security Overview Endpoint
Aggregates WAF stats, protection module status, and backend health.
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db_readonly
from cybernova.database.redis import get_redis
from cybernova.protection.waf import waf_engine
from cybernova.pipeline.unified_pipeline import unified_pipeline
from cybernova.database.postgres.models import Alert
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_dashboard_view
from cybernova.security.encryption.jwt_handler import CurrentUser

log = logging.getLogger("cybernova.security_overview")
router = APIRouter(prefix="/api/v1/security", tags=["Security"])


@router.get("/overview", summary="Security overview — WAF, protections, severity counts, service health")
async def security_overview(
    db: AsyncSession = Depends(get_db_readonly),
    user: CurrentUser = Depends(require_dashboard_view),
    tenant_id: str = Depends(get_tenant_id),
):
    # 1. WAF engine stats
    waf_stats = waf_engine.get_stats() if hasattr(waf_engine, "get_stats") else {}
    waf_result = {
        "total_inspections": waf_stats.get("total_inspections", 0),
        "rules_count": len(getattr(waf_engine, "all_rules", [])),
        "cache": {
            "hits": (waf_stats.get("cache") or {}).get("hits", 0) if isinstance(waf_stats.get("cache"), dict) else 0,
            "misses": (waf_stats.get("cache") or {}).get("misses", 0) if isinstance(waf_stats.get("cache"), dict) else 0,
            "size": (waf_stats.get("cache") or {}).get("size", 0) if isinstance(waf_stats.get("cache"), dict) else 0,
            "maxsize": (waf_stats.get("cache") or {}).get("maxsize", 2048) if isinstance(waf_stats.get("cache"), dict) else 2048,
            "hit_rate": (waf_stats.get("cache") or {}).get("hit_rate", 0) if isinstance(waf_stats.get("cache"), dict) else 0,
        },
    }

    # 2. Protection stats — query alerts grouped by rule_name using pure ORM (no raw SQL)
    from sqlalchemy import or_
    protection_keywords = {
        "waf": ["waf", "sqli", "xss", "injection"],
        "dlp": ["dlp", "data_loss", "exfil"],
        "phishing": ["phish", "phishing", "credential_harvest"],
        "webshell": ["webshell", "backdoor", "shell_upload"],
        "process_shield": ["process_shield", "malicious_process", "mimikatz"],
        "network_shield": ["network_shield", "c2", "malicious_connection", "port_scan"],
        "rootkit": ["rootkit", "kernel_mod", "driver_load"],
        "cryptojacking": ["cryptojack", "coinminer", "crypto_miner"],
    }
    protection_stats = {}
    for mod, keywords in protection_keywords.items():
        try:
            filters = [Alert.rule_name.ilike(f"%{kw}%") for kw in keywords]
            count_query = select(func.count(Alert.id)).where(
                Alert.tenant_id == tenant_id,
                or_(*filters),
            )
            result = await db.execute(count_query)
            protection_stats[mod] = result.scalar() or 0
        except Exception as e:
            log.warning("Protection stats query failed for %s: %s", mod, e)
            protection_stats[mod] = 0

    # 3. Severity counts from the DB
    severity_counts = {}
    for sev in ("critical", "high", "medium", "low"):
        count = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.tenant_id == tenant_id, Alert.severity == sev
            )
        )
        severity_counts[sev] = count.scalar() or 0

    # 4. Service health checks
    redis = await get_redis()
    pipeline_running = getattr(unified_pipeline, "_running", False)
    redis_connected = redis is not None
    db_connected = True  # we got this far with the DB, so it's connected

    return {
        "waf_stats": waf_result,
        "protection_stats": protection_stats,
        "severity_counts": severity_counts,
        "pipeline_running": pipeline_running,
        "redis_connected": redis_connected,
        "db_connected": db_connected,
    }
