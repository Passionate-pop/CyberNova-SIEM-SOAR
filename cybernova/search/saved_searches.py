"""
CyberNova — Saved Search Management
Persists saved searches to JSON files per tenant in data/saved_searches/
Supports scheduling via cron expressions.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


log = logging.getLogger("cybernova.search.saved")


@dataclass
class SavedSearch:
    id: str
    tenant_id: str
    name: str
    query: str
    index: str = "alerts"
    schedule: Optional[str] = None
    created_by: str = ""
    created_at: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> SavedSearch:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def _get_data_dir() -> Path:
    path = Path("data") / "saved_searches"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _tenant_file(tenant_id: str) -> Path:
    return _get_data_dir() / f"{tenant_id}.json"


def _load_all(tenant_id: str) -> List[SavedSearch]:
    path = _tenant_file(tenant_id)
    if not path.exists():
        return []
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return [SavedSearch.from_dict(item) for item in data]
    except (json.JSONDecodeError, IOError) as e:
        log.warning("Failed to load saved searches for tenant %s: %s", tenant_id, e)
        return []


def _save_all(tenant_id: str, searches: List[SavedSearch]) -> None:
    path = _tenant_file(tenant_id)
    try:
        with open(path, "w") as f:
            json.dump([asdict(s) for s in searches], f, indent=2, default=str)
    except IOError as e:
        log.error("Failed to save searches for tenant %s: %s", tenant_id, e)
        raise


class SavedSearchService:

    async def save(
        self,
        user: Any,
        tenant_id: str,
        name: str,
        query: str,
        index: str = "alerts",
        schedule: Optional[str] = None,
    ) -> SavedSearch:
        from cybernova.core.utils.helpers import new_id, utcnow

        searches = _load_all(tenant_id)
        existing = [s for s in searches if s.name == name]
        if existing:
            entry = existing[0]
            entry.query = query
            entry.index = index
            entry.schedule = schedule
        else:
            entry = SavedSearch(
                id=new_id(),
                tenant_id=tenant_id,
                name=name,
                query=query,
                index=index,
                schedule=schedule,
                created_by=user.id if hasattr(user, 'id') else "",
                created_at=utcnow().isoformat() if callable(utcnow) else datetime.now(timezone.utc).isoformat(),
            )
            searches.append(entry)

        _save_all(tenant_id, searches)
        return entry

    async def list(self, tenant_id: str) -> List[SavedSearch]:
        return _load_all(tenant_id)

    async def get(self, search_id: str, tenant_id: str) -> Optional[SavedSearch]:
        searches = _load_all(tenant_id)
        for s in searches:
            if s.id == search_id:
                return s
        return None

    async def delete(self, search_id: str, tenant_id: str) -> bool:
        searches = _load_all(tenant_id)
        filtered = [s for s in searches if s.id != search_id]
        if len(filtered) == len(searches):
            return False
        _save_all(tenant_id, filtered)
        return True

    async def execute_scheduled(self) -> List[Dict[str, Any]]:
        """Run all scheduled searches across all tenants.
        Returns list of execution results.
        """
        from cybernova.database.postgres.session import async_session_factory
        from cybernova.search.query_parser import parse_query
        from cybernova.search.service import search_service

        results = []
        searches_dir = _get_data_dir()

        if not searches_dir.exists():
            return results

        for fpath in searches_dir.glob("*.json"):
            tenant_id = fpath.stem
            try:
                searches = _load_all(tenant_id)
            except Exception as e:
                log.warning("Failed to load searches for %s: %s", tenant_id, e)
                continue

            for saved in searches:
                if not saved.schedule:
                    continue

                if not self._should_run(saved.schedule):
                    continue

                try:
                    async with async_session_factory() as db:
                        query = parse_query(saved.query)
                        query.limit = 100
                        result = await search_service.search(query, tenant_id, db)
                        result["saved_search_id"] = saved.id
                        result["saved_search_name"] = saved.name
                        result["tenant_id"] = tenant_id
                        results.append(result)
                except Exception as e:
                    log.error("Scheduled search '%s' failed for tenant %s: %s", saved.name, tenant_id, e)

        return results

    def _should_run(self, cron_expr: str) -> bool:
        """Simple cron evaluator — runs if current minute matches.
        Supports: '* * * * *' (minute hour day month weekday)
        Returns True for every-match or matching patterns.
        """
        try:
            parts = cron_expr.strip().split()
            if len(parts) != 5:
                return False

            now = datetime.now(timezone.utc)
            minute, hour, day, month, weekday = parts

            if not self._cron_match(minute, now.minute):
                return False
            if not self._cron_match(hour, now.hour):
                return False
            if not self._cron_match(day, now.day):
                return False
            if not self._cron_match(month, now.month):
                return False
            return self._cron_match(weekday, now.weekday())
        except Exception as e:
            log.warning("Cron schedule matching failed: %s", e)
            return False

    def _cron_match(self, pattern: str, value: int) -> bool:
        if pattern == '*':
            return True
        if '/' in pattern:
            parts = pattern.split('/')
            step = int(parts[1])
            return value % step == 0
        if ',' in pattern:
            return value in [int(x) for x in pattern.split(',')]
        if '-' in pattern:
            low, high = pattern.split('-')
            return int(low) <= value <= int(high)
        return int(pattern) == value


saved_search_service = SavedSearchService()
