from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.marketplace.registry")

MARKETPLACE_DIR = Path("data/marketplace")
LOCAL_PACKAGES_DIR = MARKETPLACE_DIR / "local"
REMOTE_CACHE_DIR = MARKETPLACE_DIR / "remote"

PACKAGE_TYPES = ("detection_rule", "playbook", "analytics_query", "dashboard_template", "soar_action")


class MarketplaceRegistry:
    """
    Local registry for community rules, playbooks, and detection content.
    Supports local packages and remote marketplace sync.
    """

    def __init__(self):
        self._local_packages: Dict[str, Dict[str, Any]] = {}
        self._remote_cache: Dict[str, Dict[str, Any]] = {}
        self._init_dirs()

    def _init_dirs(self):
        LOCAL_PACKAGES_DIR.mkdir(parents=True, exist_ok=True)
        REMOTE_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def load_all(self):
        """Load all local packages from disk."""
        self._local_packages = {}
        for pkg_file in LOCAL_PACKAGES_DIR.glob("*.json"):
            try:
                with open(pkg_file) as f:
                    pkg = json.load(f)
                pkg_id = pkg.get("id", pkg_file.stem)
                self._local_packages[pkg_id] = pkg
            except Exception as e:
                log.warning("Failed to load package %s: %s", pkg_file, e)

        for pkg_file in REMOTE_CACHE_DIR.glob("*.json"):
            try:
                with open(pkg_file) as f:
                    pkg = json.load(f)
                pkg_id = pkg.get("id", pkg_file.stem)
                self._remote_cache[pkg_id] = pkg
            except Exception as e:
                log.warning("Failed to load remote package %s: %s", pkg_file, e)

        log.info("Loaded %d local and %d cached remote packages", len(self._local_packages), len(self._remote_cache))

    async def install_package(self, package_data: Dict[str, Any]) -> Dict[str, Any]:
        """Install a package from uploaded data."""
        pkg_id = package_data.get("id", str(uuid.uuid4()))
        package_data["id"] = pkg_id
        package_data["installed_at"] = datetime.now(timezone.utc).isoformat()

        pkg_type = package_data.get("type", "detection_rule")
        if pkg_type not in PACKAGE_TYPES:
            raise ValueError(f"Invalid package type: {pkg_type}. Must be one of {PACKAGE_TYPES}")

        filepath = LOCAL_PACKAGES_DIR / f"{pkg_id}.json"
        with open(filepath, "w") as f:
            json.dump(package_data, f, indent=2, default=str)

        self._local_packages[pkg_id] = package_data
        log.info("Installed package: %s (%s)", package_data.get("name", pkg_id), pkg_type)
        return package_data

    async def uninstall_package(self, pkg_id: str) -> bool:
        """Uninstall a local package."""
        filepath = LOCAL_PACKAGES_DIR / f"{pkg_id}.json"
        if filepath.exists():
            filepath.unlink()
        self._local_packages.pop(pkg_id, None)
        self._remote_cache.pop(pkg_id, None)
        log.info("Uninstalled package: %s", pkg_id)
        return True

    async def apply_package(self, pkg_id: str, tenant_id: str = "default") -> Dict[str, Any]:
        """Apply a package's content to the active system."""
        pkg = self._local_packages.get(pkg_id) or self._remote_cache.get(pkg_id)
        if not pkg:
            raise ValueError(f"Package not found: {pkg_id}")

        pkg_type = pkg.get("type")
        content = pkg.get("content", {})
        results = {"applied": [], "errors": []}

        if pkg_type == "detection_rule":
            try:
                from cybernova.database.postgres.session import get_db_session
                from cybernova.database.postgres.models import DetectionRule
                async for db in get_db_session():
                    rule = DetectionRule(
                        tenant_id=tenant_id,
                        name=content.get("name", pkg.get("name", pkg_id)),
                        description=content.get("description", ""),
                        rule_expression=content.get("rule_expression", ""),
                        severity=content.get("severity", "medium"),
                        risk_score=content.get("risk_score", 50),
                        event_type=content.get("event_type"),
                        mitre_tactic=content.get("mitre_tactic"),
                        mitre_technique=content.get("mitre_technique"),
                        enabled=content.get("enabled", True),
                    )
                    db.add(rule)
                    await db.commit()
                    results["applied"].append(f"rule:{rule.id}")
                    break
            except Exception as e:
                results["errors"].append(str(e))

        elif pkg_type == "playbook":
            try:
                from cybernova.response.automation.engine import playbook_engine
                playbook = await playbook_engine.create_playbook(content)
                results["applied"].append(f"playbook:{playbook.id}")
            except Exception as e:
                results["errors"].append(str(e))

        return results

    def list_packages(self, pkg_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all available packages, optionally filtered by type."""
        packages = []
        for pkg_id, pkg in {**self._remote_cache, **self._local_packages}.items():
            if pkg_type and pkg.get("type") != pkg_type:
                continue
            packages.append({
                "id": pkg_id,
                "name": pkg.get("name", pkg_id),
                "type": pkg.get("type", "unknown"),
                "version": pkg.get("version", "1.0.0"),
                "description": pkg.get("description", ""),
                "author": pkg.get("author", "community"),
                "installed": pkg_id in self._local_packages,
                "installed_at": pkg.get("installed_at"),
            })
        return sorted(packages, key=lambda p: p["name"])

    def get_package(self, pkg_id: str) -> Optional[Dict[str, Any]]:
        return self._local_packages.get(pkg_id) or self._remote_cache.get(pkg_id)

    async def sync_remote(self, marketplace_url: str = "https://marketplace.cybernova.io/api/v1/packages"):
        """Sync packages from the remote marketplace."""
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(marketplace_url) as resp:
                    if resp.status == 200:
                        remote_packages = await resp.json()
                        for pkg in remote_packages.get("packages", []):
                            pkg_id = pkg.get("id", str(uuid.uuid4()))
                            filepath = REMOTE_CACHE_DIR / f"{pkg_id}.json"
                            with open(filepath, "w") as f:
                                json.dump(pkg, f, indent=2, default=str)
                            self._remote_cache[pkg_id] = pkg
                        log.info("Synced %d packages from remote marketplace", len(remote_packages.get("packages", [])))
        except Exception as e:
            log.warning("Remote marketplace sync failed: %s", e)


marketplace_registry = MarketplaceRegistry()
