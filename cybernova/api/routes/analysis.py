"""
CyberNova — File Analysis Endpoint
Upload files for steganography detection, hash lookup, and static analysis.
"""
from __future__ import annotations

import hashlib
import logging
import math
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from cybernova.database.postgres.session import get_db
from cybernova.security.encryption.jwt_handler import get_current_user, CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.enrichment.stego_detector import stego_detector
from cybernova.pipeline.unified_pipeline import unified_pipeline

log = logging.getLogger("cybernova.api.analysis")
router = APIRouter(prefix="/api/v1/analysis", tags=["File Analysis"])

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/upload", summary="Upload a file for security analysis")
async def analyze_file(
    file: UploadFile = File(...),
    filename: Optional[str] = Form(None),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Upload a file for comprehensive security analysis:
    - Steganography detection (LSB analysis, EXIF metadata, palette analysis)
    - File hash computation (SHA-256)
    - File type detection
    - Size and entropy analysis

    Supported formats: PNG, JPG, JPEG, GIF, BMP, TIFF (for stego analysis)
    All file types: hash and metadata analysis

    Max file size: 50 MB
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    name = filename or file.filename
    contents = await file.read()
    file_size = len(contents)

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({file_size / 1024 / 1024:.1f} MB). Max: {MAX_FILE_SIZE / 1024 / 1024:.0f} MB",
        )

    # Compute SHA-256 hash
    sha256 = hashlib.sha256(contents).hexdigest()

    # Basic file info
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    is_image = ext in ("png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp")

    findings: Dict[str, Any] = {
        "filename": name,
        "file_size": file_size,
        "sha256": sha256,
        "extension": ext,
        "is_image": is_image,
        "threat_detected": False,
        "risk_score": 0.0,
        "stego_analysis": None,
    }

    # ── Steganography Analysis (images only) ──
    if is_image:
        try:
            stego_result = await stego_detector.analyze(contents, filename=name)
            findings["stego_analysis"] = {
                "stego_suspected": stego_result.get("stego_suspected", False),
                "risk_score": stego_result.get("risk_score", 0.0),
                "format": stego_result.get("format"),
                "mode": stego_result.get("mode"),
                "size": stego_result.get("size"),
                "findings": stego_result.get("findings", []),
                "error": stego_result.get("error"),
            }
            if stego_result.get("stego_suspected"):
                findings["threat_detected"] = True
                findings["risk_score"] = max(findings["risk_score"], stego_result.get("risk_score", 0))
        except Exception as exc:
            log.warning("Stego analysis failed for %s: %s", name, exc)
            findings["stego_analysis"] = {"error": str(exc)}

    # ── Entropy analysis (high entropy = possible encoded/encrypted payload) ──
    if file_size > 0:
        entropy = _compute_entropy(contents)
        findings["entropy"] = round(entropy, 4)
        if entropy > 7.5:
            findings["threat_detected"] = True
            findings["risk_score"] = max(findings["risk_score"], 50.0)
            findings["high_entropy"] = True
    else:
        findings["entropy"] = 0.0

    # ── Fire detection event into pipeline ──
    event_data = {
        "event_type": "file_scanned",
        "severity": "critical" if findings["threat_detected"] else "info",
        "source_ip": "",
        "message": f"File analysis: {name} (SHA256: {sha256[:16]}...)",
        "extra_data": findings,
    }

    if findings["threat_detected"]:
        event_data["severity"] = "critical"
        event_data["event_type"] = "suspicious_file"

    try:
        await unified_pipeline.ingest(
            event_data,
            tenant_id=tenant_id,
            source="file_analysis_api",
            source_type="upload",
        )
        findings["pipeline_ingested"] = True
    except Exception as exc:
        log.warning("Failed to send file analysis event to pipeline: %s", exc)
        findings["pipeline_ingested"] = False

    return findings


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


@router.get("/hash/{sha256}", summary="Look up a file hash in alerts")
async def lookup_hash(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
):
    """
    Search for a SHA-256 hash across all alerts and security events.
    Returns any matching alerts that reference this hash.
    """
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256.lower()):
        raise HTTPException(status_code=400, detail="Invalid SHA-256 hash (must be 64 hex characters)")

    from sqlalchemy import select, text
    from cybernova.database.postgres.models import Alert

    # Search across alerts' extra_data for the hash
    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == tenant_id,
            Alert.extra_data.cast(text("text")).like(f"%{sha256}%"),
        ).order_by(Alert.created_at.desc()).limit(20)
    )
    alerts = result.scalars().all()

    return {
        "sha256": sha256,
        "matches_found": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "description": a.description,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }
