"""
CyberNova — GeoIP Service
Real IP geolocation with MaxMind GeoLite2 support, in-memory + file cache, and API fallback.
Blocking calls (MaxMind DB read) offloaded to thread pool executor.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from cybernova.config.settings import get_settings
from cybernova.core.utils.retry import retry_async

log = logging.getLogger("cybernova.geoip")

CACHE_TTL_SECONDS = 3600
FILE_CACHE_PATH = os.environ.get("GEOIP_FILE_CACHE", "/app/data/geoip_cache.json")
GEO_API_URL = "http://ip-api.com/json/{ip}"


@dataclass
class GeoIPResult:
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    lat: float = 0.0
    lon: float = 0.0
    isp: str = ""
    org: str = ""
    asn: str = ""
    is_from_db: bool = False
    is_from_cache: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GeoIPService:
    """GeoIP lookup service with layered resolution strategy and async safety."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._reader: Any = None
        self._mem_cache: Dict[str, tuple[float, GeoIPResult]] = {}
        self._file_cache: Dict[str, GeoIPResult] = {}
        self._mem_lock = asyncio.Lock()
        self._file_lock = asyncio.Lock()
        self._reader_lock = asyncio.Lock()
        self._save_pending = False
        self._init_maxmind()

    def _init_maxmind(self) -> None:
        db_path = os.environ.get(
            "GEOIP_DB_PATH",
            "/usr/share/GeoIP/GeoLite2-City.mmdb",
        )
        try:
            import geoip2.database
            if Path(db_path).exists():
                self._reader = geoip2.database.Reader(db_path)
                log.info("GeoIP: using MaxMind database at %s", db_path)
            else:
                log.warning("GeoIP: MaxMind DB not found at %s, using API fallback", db_path)
        except ImportError:
            log.info("GeoIP: geoip2 not installed, using API fallback")

    async def _resolve_maxmind(self, ip: str) -> Optional[GeoIPResult]:
        async with self._reader_lock:
            if self._reader is None:
                return None
        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(None, self._reader.city, ip)
            return GeoIPResult(
                country=response.country.name or "",
                country_code=response.country.iso_code or "",
                city=response.city.name or "",
                region=response.subdivisions.most_specific.name if response.subdivisions else "",
                lat=response.location.latitude or 0.0,
                lon=response.location.longitude or 0.0,
                isp=response.traits.isp or "",
                org=response.traits.organization or "",
                is_from_db=True,
            )
        except Exception as exc:
            log.debug("GeoIP: MaxMind lookup failed for %s: %s", ip, exc)
            return None

    async def _resolve_api(self, ip: str) -> Optional[GeoIPResult]:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=3.0)) as client:
                resp = await retry_async(
                    lambda: client.get(GEO_API_URL.format(ip=ip)),
                    max_retries=2,
                    base_delay=0.5,
                    retryable_exceptions=(httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError),
                )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("status") != "success":
                return None
            return GeoIPResult(
                country=data.get("country", ""),
                country_code=data.get("countryCode", ""),
                city=data.get("city", ""),
                region=data.get("regionName", ""),
                lat=data.get("lat", 0.0),
                lon=data.get("lon", 0.0),
                isp=data.get("isp", ""),
                org=data.get("org", ""),
                asn=str(data.get("as", "")),
                is_from_db=False,
            )
        except Exception as exc:
            log.debug("GeoIP: API fallback failed for %s: %s", ip, exc)
            return None

    async def lookup(self, ip: str) -> Dict[str, Any]:
        async with self._mem_lock:
            entry = self._mem_cache.get(ip)
            if entry is not None:
                ts, result = entry
                if time.monotonic() - ts <= CACHE_TTL_SECONDS:
                    result.is_from_cache = True
                    return result.to_dict()
                del self._mem_cache[ip]

        async with self._file_lock:
            cached = self._file_cache.get(ip)
            if cached is not None:
                async with self._mem_lock:
                    self._mem_cache[ip] = (time.monotonic(), cached)
                cached.is_from_cache = True
                return cached.to_dict()

        result = await self._resolve_maxmind(ip)
        if result is None:
            result = await self._resolve_api(ip)
        if result is None:
            result = GeoIPResult(country="Unknown", country_code="XX", is_from_db=False)

        async with self._mem_lock:
            self._mem_cache[ip] = (time.monotonic(), result)
        async with self._file_lock:
            self._file_cache[ip] = result
            if not self._save_pending:
                self._save_pending = True
                asyncio.create_task(self._save_file_cache_debounced())

        log.info("GeoIP: resolved %s -> %s, %s", ip, result.country_code, result.city)
        return result.to_dict()

    async def _save_file_cache_debounced(self) -> None:
        await asyncio.sleep(10)
        try:
            async with self._file_lock:
                path = Path(FILE_CACHE_PATH)
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = {ip: asdict(r) for ip, r in self._file_cache.items()}
                path.write_text(json.dumps(raw, indent=2))
                self._save_pending = False
        except Exception as exc:
            log.warning("GeoIP: file cache save failed: %s", exc)
            self._save_pending = False

    async def close(self) -> None:
        async with self._reader_lock:
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception as e:
                    log.warning("GeoIP reader close error: %s", e)
                self._reader = None


geoip_service = GeoIPService()
