from __future__ import annotations

import base64
import hashlib
import logging
from pathlib import Path
from functools import lru_cache
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.agent_update")
router = APIRouter(prefix="/api/v1/agent/update", tags=["Agent Update"])

AGENT_DIST_DIR = Path("dist/agent")
SUPPORTED_ARCHS = {"x86_64", "aarch64", "amd64", "arm64"}
ARCH_NORMALIZE = {"amd64": "x86_64", "arm64": "aarch64"}


def _resolve_arch(arch: str) -> str:
    return ARCH_NORMALIZE.get(arch, arch)


@lru_cache(maxsize=1)
def _get_signer() -> Any:
    """Return Ed25519 private key. Generates + caches one if not configured."""
    settings = get_settings()
    key_b64 = settings.agent_signing_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if key_b64:
        from cryptography.hazmat.primitives.serialization import load_der_private_key

        key_bytes = base64.b64decode(key_b64)
        return load_der_private_key(key_bytes, password=None)

    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    log.warning(
        "No AGENT_SIGNING_PRIVATE_KEY configured. Generated ephemeral key. "
        "Embed this public key in agent builds: %s",
        base64.b64encode(pub_der).decode(),
    )
    return key


def _sign_sha256(sha256_hex: str) -> str:
    """Sign a SHA256 hex digest with Ed25519 and return base64 signature."""
    key = _get_signer()
    sig = key.sign(sha256_hex.encode("utf-8"))
    return base64.b64encode(sig).decode()


def _find_binaries() -> List[Dict[str, Any]]:
    binaries = []
    if not AGENT_DIST_DIR.exists():
        return binaries
    for f in sorted(AGENT_DIST_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not f.is_file() or f.name.startswith("."):
            continue
        if f.suffix in (".sha256", ".rb", ".rpm", ".deb", ".msi"):
            continue
        name = f.name
        if not name.startswith("cybernova-agent"):
            continue
        parts = name.replace("cybernova-agent-", "").rsplit(".", 1)
        stem = parts[0]
        meta = stem.split("-")
        arch = None
        version = None
        for m in meta:
            if m in SUPPORTED_ARCHS or m in ARCH_NORMALIZE:
                arch = _resolve_arch(m)
            if m.startswith("v"):
                version = m[1:]
        if arch and version:
            sha_path = f.with_suffix(f.suffix + ".sha256")
            sha256 = sha_path.read_text().strip() if sha_path.exists() else ""
            binaries.append({
                "filename": f.name,
                "arch": arch,
                "version": version,
                "size_bytes": f.stat().st_size,
                "sha256": sha256,
                "download_url": str(router.prefix) + f"/download/{arch}/{version}",
            })
    return binaries


@router.get("/check", summary="Check for available agent update")
async def check_update(
    current_version: str = Query(..., description="Current agent version"),
    arch: str = Query(..., description="Agent architecture (x86_64, aarch64, amd64, arm64)"),
):
    a = _resolve_arch(arch)
    binaries = _find_binaries()
    matched = [b for b in binaries if b["arch"] == a and b["version"] > current_version]
    matched.sort(key=lambda b: b["version"], reverse=True)

    if not matched:
        return {
            "update_available": False,
            "latest_version": "",
            "current_version": current_version,
        }

    latest = matched[0]
    sha256 = latest["sha256"]
    signature = _sign_sha256(sha256) if sha256 else ""

    return {
        "update_available": True,
        "latest_version": latest["version"],
        "current_version": current_version,
        "download_url": latest["download_url"],
        "size_bytes": latest["size_bytes"],
        "sha256": sha256,
        "signature": signature,
        "release_notes": f"https://cybernova.ai/releases/v{latest['version']}",
    }


@router.get("/download/{arch}/{version}", summary="Download signed agent binary")
async def download_update(
    arch: str,
    version: str,
):
    a = _resolve_arch(arch)
    binaries = _find_binaries()
    matched = [b for b in binaries if b["arch"] == a and b["version"] == version]
    if not matched:
        raise HTTPException(status_code=404, detail=f"Binary not found: {arch} v{version}")

    entry = matched[0]
    path = AGENT_DIST_DIR / entry["filename"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="Binary file not found on disk")

    sha256 = entry["sha256"] or hashlib.sha256(path.read_bytes()).hexdigest()
    signature = _sign_sha256(sha256)

    return FileResponse(
        str(path),
        media_type="application/octet-stream",
        filename=entry["filename"],
        headers={
            "X-Checksum-SHA256": sha256,
            "X-Signature-Ed25519": signature,
            "X-Content-Size": str(entry["size_bytes"]),
        },
    )


@router.get("/public-key", summary="Get server's Ed25519 public key for agent verification")
async def get_public_key():
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = _get_signer()
    pub = key.public_key()
    pub_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {
        "algorithm": "Ed25519",
        "public_key_base64": base64.b64encode(pub_der).decode(),
    }
