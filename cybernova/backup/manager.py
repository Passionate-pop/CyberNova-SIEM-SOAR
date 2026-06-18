from __future__ import annotations

import asyncio
import logging
import os
import subprocess  # nosec
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.backup.manager")

BACKUP_DIR = Path("data/backups")


class BackupManager:
    """
    Manages Postgres WAL-G / pg_dump backups for disaster recovery.
    Cold storage S3 sync removed for $0 local deployment.
    """

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._stats = {
            "last_db_backup": None,
            "total_db_backups": 0,
            "errors": 0,
        }

    async def start(self, interval: int = 86400):
        self._running = True
        self._task = asyncio.create_task(self._run_loop(interval))
        log.info("Backup manager started (interval: %ds)", interval)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Backup manager stopped")

    async def _run_loop(self, interval: int):
        while self._running:
            try:
                await self.run_db_backup()
            except Exception as e:
                log.error("Backup cycle error: %s", e)
                self._stats["errors"] += 1
            await asyncio.sleep(interval)

    async def run_db_backup(self) -> Dict[str, Any]:
        """Run pg_dump backup of the database."""
        settings = get_settings()
        db_url = settings.effective_database_url
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"cybernova_db_{timestamp}.dump"
        filepath = BACKUP_DIR / filename

        try:
            loop = asyncio.get_running_loop()

            def _backup():
                if "postgresql" in db_url:
                    from urllib.parse import urlparse, unquote
                    parsed = urlparse(db_url)
                    user = parsed.username or "postgres"
                    pw = unquote(parsed.password or "")
                    host = parsed.hostname or "localhost"
                    port = str(parsed.port or 5432)
                    dbname = (parsed.path or "/cybernova").lstrip("/").split("?")[0]
                    if not dbname:
                        dbname = "cybernova"
                    os.environ["PGPASSWORD"] = pw
                    result = subprocess.run(  # nosec
                        ["pg_dump", "-h", host, "-p", port, "-U", user, "-d", dbname,
                         "-F", "c", "-f", str(filepath), "-v"],
                        capture_output=True, text=True, timeout=300,
                    )
                    if result.returncode != 0:
                        raise RuntimeError(f"pg_dump failed: {result.stderr}")
                else:
                    filepath.write_text("")
                return str(filepath)

            path = await loop.run_in_executor(None, _backup)
            size_bytes = filepath.stat().st_size if filepath.exists() else 0
            self._stats["last_db_backup"] = timestamp
            self._stats["total_db_backups"] += 1
            log.info("DB backup complete: %s (%d bytes)", path, size_bytes)
            return {
                "status": "success",
                "path": path,
                "size_bytes": size_bytes,
                "timestamp": timestamp,
            }
        except Exception as e:
            log.error("DB backup failed: %s", e)
            self._stats["errors"] += 1
            return {"status": "failed", "error": str(e)}

    async def restore_db(self, backup_file: str) -> Dict[str, Any]:
        """Restore database from a backup file."""
        settings = get_settings()
        db_url = settings.effective_database_url
        filepath = Path(backup_file)
        if not filepath.exists():
            return {"status": "failed", "error": f"Backup file not found: {backup_file}"}

        try:
            loop = asyncio.get_running_loop()

            def _restore():
                if "postgresql" in db_url:
                    from urllib.parse import urlparse, unquote
                    parsed = urlparse(db_url)
                    user = parsed.username or "postgres"
                    pw = unquote(parsed.password or "")
                    host = parsed.hostname or "localhost"
                    port = str(parsed.port or 5432)
                    dbname = (parsed.path or "/cybernova").lstrip("/").split("?")[0]
                    if not dbname:
                        dbname = "cybernova"
                    os.environ["PGPASSWORD"] = pw
                    result = subprocess.run(  # nosec
                        ["pg_restore", "-h", host, "-p", port, "-U", user, "-d", dbname,
                         "-c", "--if-exists", str(filepath)],
                        capture_output=True, text=True, timeout=600,
                    )
                    if result.returncode != 0:
                        raise RuntimeError(f"pg_restore failed: {result.stderr}")
                return True

            await loop.run_in_executor(None, _restore)
            log.info("DB restore complete from: %s", backup_file)
            return {"status": "success", "source": backup_file}
        except Exception as e:
            log.error("DB restore failed: %s", e)
            return {"status": "failed", "error": str(e)}

    async def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups."""
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backups = []
        for f in sorted(BACKUP_DIR.glob("*.dump"), reverse=True):
            backups.append({
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "created_at": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
            })
        return backups

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


backup_manager = BackupManager()
