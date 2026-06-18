"""
CyberNova — Global Threat Network: Threat Intelligence
IOC sharing, reputation scoring, external feed integration.
With Circuit Breaker protection for external APIs, retry framework, and connection pooling.
"""
from __future__ import annotations

import asyncio
import logging
import ipaddress
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

import httpx

from cybernova.config.settings import get_settings
from cybernova.resilience.circuit_breaker import get_circuit_breaker, CircuitBreakerConfig
from cybernova.core.utils.retry import retry_async

log = logging.getLogger("cybernova.network.threat_intel")

LOCAL_BLACKLIST = {"203.0.113.1", "198.51.100.5", "192.0.2.100", "10.99.99.99"}


@dataclass
class LRUCache:
    max_size: int = 1000
    ttl_seconds: int = 3600
    _cache: OrderedDict = field(default_factory=OrderedDict)
    _timestamps: Dict[str, float] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def get(self, key: str) -> Any:
        async with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps.get(key, 0) < self.ttl_seconds:
                    self._cache.move_to_end(key)
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
        return None

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if len(self._cache) >= self.max_size:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
                del self._timestamps[oldest]
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def __contains__(self, key: str) -> bool:
        return key in self._cache


threat_intel_cache = LRUCache(max_size=500, ttl_seconds=3600)

IP_DAILY_COUNTS: Dict[str, int] = {}
_ip_lockout_until: float = 0
_ip_lockout_threshold = 450
_counter_lock = asyncio.Lock()

SAFE_IP_PREFIXES: Set[str] = {
    "8.8.", "8.8.8", "8.8.4", "8.8.4.4",
    "1.1.1", "1.0.0",
    "23.12.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
    "20.37.", "20.38.", "20.39.", "20.40.", "20.41.", "20.42.", "20.43.", "20.44.",
    "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "13.70.", "13.71.",
    "40.64.", "40.65.", "40.66.", "40.67.", "40.68.", "40.69.", "40.70.", "40.71.",
    "52.0.", "52.1.", "52.2.", "52.3.", "52.4.", "52.5.", "52.6.", "52.7.", "52.8.", "52.9.",
    "20.190.", "20.191.", "20.192.", "20.193.", "20.194.", "20.195.", "20.196.", "20.197.",
    "51.4.", "51.5.", "51.8.", "51.10.", "51.11.", "51.12.",
    "17.0.", "17.1.", "17.2.", "17.3.", "17.4.", "17.5.", "17.6.", "17.7.", "17.8.", "17.9.",
    "157.240.", "157.241.", "157.242.", "157.243.", "157.244.", "157.245.", "157.246.",
    "142.250.", "142.251.", "142.252.", "142.253.", "142.254.", "142.255.",
    "172.217.", "172.253.",
    "216.239.", "216.58.",
    "74.125.", "74.126.", "74.127.",
    "139.130.", "203.0.113.",
}

SAFE_IP_RANGES: list = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
]

SAFE_DOMAINS: set = {
    "google.com", "googleapis.com", "googleusercontent.com", "ggpht.com",
    "cloudflare.com", "cloudflare.net", "cf-ns.com",
    "microsoft.com", "microsoftonline.com", "msftncsi.com", "msftconnecttest.com",
    "windows.com", "windows.net", "azure.com", "azureedge.net",
    "github.com", "githubusercontent.com", "github.io",
    "apple.com", "icloud.com", "mzstatic.com",
    "amazonaws.com", "amazon.com", "aws",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "twimg.com",
    "reddit.com", "redd.it",
    "spotify.com", "scdn.co",
    "netflix.com", "nflxvideo.net",
    "slack.com", "slack-edge.com",
    "zoom.us",
    "akamai.com", "akamaiedge.net", "akamai.net",
    "cdn.akamai.com", "edge.akamai.com",
}

IOC_DATABASE: Dict[str, Dict[str, Any]] = {}
_ioc_lock = asyncio.Lock()
_shared_client: Optional[httpx.AsyncClient] = None
_client_lock = asyncio.Lock()


async def _get_client() -> httpx.AsyncClient:
    global _shared_client
    if _shared_client is None:
        async with _client_lock:
            if _shared_client is None:
                _shared_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(10.0, connect=5.0),
                    limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
                    headers={"User-Agent": "CyberNova/2.0"},
                )
    return _shared_client


async def _query_virustotal(ip: str, api_key: str) -> Dict[str, Any]:
    client = await _get_client()
    resp = await client.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
    )
    resp.raise_for_status()
    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    return {
        "malicious": malicious_count > 0,
        "detections": malicious_count + suspicious_count,
        "total_engines": sum(stats.values()),
        "country_code": data.get("country_code", ""),
        "network": data.get("network", ""),
        "asn": data.get("asn", ""),
    }


async def _query_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    client = await _get_client()
    resp = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        headers={"Key": api_key, "Accept": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return {
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "country_code": data.get("countryCode", ""),
        "usage_type": data.get("usageType", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "total_reports": data.get("totalReports", 0),
    }


async def _query_otx(ip: str, api_key: str) -> Dict[str, Any]:
    client = await _get_client()
    resp = await client.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers={"X-OTX-API-KEY": api_key},
    )
    resp.raise_for_status()
    data = resp.json()
    pulse_info = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    pulse_names = [p.get("name", "") for p in pulse_info.get("pulses", [])[:5]]
    return {
        "pulses": pulse_count,
        "is_malicious": pulse_count >= 2,
        "pulse_names": pulse_names,
    }


async def _with_retry(fn, *args, **kwargs) -> Dict[str, Any]:
    try:
        return await retry_async(
            fn, *args, **kwargs,
            max_retries=2,
            base_delay=1.0,
            backoff_factor=2.0,
            jitter=0.1,
            retryable_exceptions=(httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError, httpx.HTTPStatusError),
        )
    except Exception as exc:
        log.debug("External API call failed after retries: %s", exc)
        raise


class ThreatIntelService:

    def __init__(self):
        self._virustotal_cb = get_circuit_breaker(
            "virustotal",
            CircuitBreakerConfig(failure_threshold=5, success_threshold=2, timeout_seconds=60.0)
        )
        self._abuseipdb_cb = get_circuit_breaker(
            "abuseipdb",
            CircuitBreakerConfig(failure_threshold=5, success_threshold=2, timeout_seconds=60.0)
        )
        self._otx_cb = get_circuit_breaker(
            "otx",
            CircuitBreakerConfig(failure_threshold=5, success_threshold=2, timeout_seconds=60.0)
        )

    def is_safe_ip(self, ip: str) -> bool:
        if not ip:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for network in SAFE_IP_RANGES:
                if addr in network:
                    return True
            for prefix in SAFE_IP_PREFIXES:
                if ip.startswith(prefix):
                    return True
            return False
        except ValueError:
            return True

    def is_safe_domain(self, domain: str) -> bool:
        if not domain:
            return True
        domain_lower = domain.lower()
        for safe in SAFE_DOMAINS:
            if safe in domain_lower or domain_lower.endswith(safe):
                return True
        return False

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        global IP_DAILY_COUNTS, _ip_lockout_until

        result: Dict[str, Any] = {
            "ip": ip,
            "sources": [],
            "is_malicious": False,
            "risk_modifier": 0,
            "is_safe": False,
            "safe_reason": None,
            "circuit_breakers": {},
        }

        if ip in LOCAL_BLACKLIST:
            result["is_malicious"] = True
            result["sources"].append("local_blacklist")
            result["risk_modifier"] = 30

        if self.is_safe_ip(ip) and not result["is_malicious"]:
            result["is_safe"] = True
            result["safe_reason"] = "known_safe_ip"
            result["risk_modifier"] = -50
            return result

        if result["is_malicious"]:
            await threat_intel_cache.set(ip, result.copy())
            return result

        cached = await threat_intel_cache.get(ip)
        if cached is not None:
            cached["from_cache"] = True
            return cached

        async with _ioc_lock:
            if ip in IOC_DATABASE:
                result.update(IOC_DATABASE[ip])
                result["sources"].append("ioc_database")

        async with _counter_lock:
            total_today = sum(IP_DAILY_COUNTS.values())
            if total_today >= _ip_lockout_threshold:
                if time.time() < _ip_lockout_until:
                    result["rate_limited"] = True
                    result["rate_limit_reason"] = f"Daily limit ({_ip_lockout_threshold}) reached. Resets at midnight UTC."
                    return result
                IP_DAILY_COUNTS = {}
                _ip_lockout_until = 0

        settings = get_settings()

        if settings.virustotal_api_key:
            vt_result = await self._virustotal_cb.call(
                lambda: _with_retry(_query_virustotal, ip, settings.virustotal_api_key),
                fallback={},
            )
            if vt_result and vt_result.get("malicious"):
                result["is_malicious"] = True
                result["risk_modifier"] = max(result["risk_modifier"], 40)
                result["sources"].append("virustotal")
                result["virustotal"] = {
                    "malicious": vt_result.get("malicious", False),
                    "detections": vt_result.get("detections", 0),
                    "country_code": vt_result.get("country_code", ""),
                    "asn": vt_result.get("asn", ""),
                }
            result["circuit_breakers"]["virustotal"] = self._virustotal_cb.state.value
            async with _counter_lock:
                IP_DAILY_COUNTS["virustotal"] = IP_DAILY_COUNTS.get("virustotal", 0) + 1
                total_today = sum(IP_DAILY_COUNTS.values())
                if total_today >= _ip_lockout_threshold - 50:
                    _ip_lockout_until = time.time() + 86400

        if settings.abuseipdb_api_key:
            abuse_result = await self._abuseipdb_cb.call(
                lambda: _with_retry(_query_abuseipdb, ip, settings.abuseipdb_api_key),
                fallback={},
            )
            if abuse_result and abuse_result.get("abuse_confidence", 0) > 50:
                result["is_malicious"] = True
                result["risk_modifier"] = max(result["risk_modifier"], 35)
                result["sources"].append("abuseipdb")
                result["abuseipdb"] = {
                    "abuse_confidence_score": abuse_result.get("abuse_confidence", 0),
                    "country_code": abuse_result.get("country_code", ""),
                    "usage_type": abuse_result.get("usage_type", ""),
                    "isp": abuse_result.get("isp", ""),
                    "total_reports": abuse_result.get("total_reports", 0),
                }
            result["circuit_breakers"]["abuseipdb"] = self._abuseipdb_cb.state.value

        if settings.otx_api_key:
            otx_result = await self._otx_cb.call(
                lambda: _with_retry(_query_otx, ip, settings.otx_api_key),
                fallback={},
            )
            if otx_result and otx_result.get("is_malicious"):
                result["is_malicious"] = True
                result["risk_modifier"] = max(result["risk_modifier"], 30)
                result["sources"].append("otx")
                result["otx"] = {
                    "pulses": otx_result.get("pulses", 0),
                    "is_malicious": otx_result.get("is_malicious", False),
                    "pulse_names": otx_result.get("pulse_names", []),
                }
            result["circuit_breakers"]["otx"] = self._otx_cb.state.value
            async with _counter_lock:
                IP_DAILY_COUNTS["otx"] = IP_DAILY_COUNTS.get("otx", 0) + 1
                total_today = sum(IP_DAILY_COUNTS.values())
                if total_today >= _ip_lockout_threshold - 50:
                    _ip_lockout_until = time.time() + 86400

        await threat_intel_cache.set(ip, result.copy())
        return result

    async def add_ioc(self, indicator: str, ioc_type: str, metadata: Dict[str, Any] = None) -> None:
        async with _ioc_lock:
            IOC_DATABASE[indicator] = {
                "type": ioc_type, "is_malicious": True,
                "risk_modifier": 25, **(metadata or {}),
            }
        log.info("IOC added: %s (%s)", indicator, ioc_type)

    async def get_reputation(self, ip: str) -> Dict[str, Any]:
        result = await self.lookup_ip(ip)
        score = 100 - result.get("risk_modifier", 0) * 2
        return {"ip": ip, "reputation_score": max(0, score),
                "is_malicious": result["is_malicious"],
                "sources": result["sources"]}

    async def list_iocs(self) -> List[Dict[str, Any]]:
        async with _ioc_lock:
            return [{"indicator": k, **v} for k, v in IOC_DATABASE.items()]


threat_intel_service = ThreatIntelService()
