"""Tests for threat intelligence and GeoIP services."""
from __future__ import annotations
import pytest
from cybernova.network.threat_intel import ThreatIntelService


@pytest.mark.asyncio
async def test_safe_ip_detection():
    service = ThreatIntelService()
    assert service.is_safe_ip("10.0.0.1") is True
    assert service.is_safe_ip("192.168.1.1") is True
    assert service.is_safe_ip("127.0.0.1") is True
    assert service.is_safe_ip("172.16.0.1") is True


@pytest.mark.asyncio
async def test_public_ip_not_safe():
    service = ThreatIntelService()
    assert service.is_safe_ip("8.8.8.8") is True  # Google DNS in safe list
    assert service.is_safe_ip("1.1.1.1") is True   # Cloudflare in safe list


@pytest.mark.asyncio
async def test_lookup_safe_ip():
    service = ThreatIntelService()
    result = await service.lookup_ip("10.0.0.1")
    assert result["is_safe"] is True
    assert result["risk_modifier"] == -50


@pytest.mark.asyncio
async def test_safe_ip_ranges():
    service = ThreatIntelService()
    assert service.is_safe_ip("203.0.113.1") is True  # documentation/test range
    assert service.is_safe_ip("198.51.100.5") is True  # documentation/test range
    assert service.is_safe_ip("192.0.2.100") is True   # documentation/test range


@pytest.mark.asyncio
async def test_local_blacklist_overrides_safe_range():
    """LOCAL_BLACKLIST IPs are flagged even when they fall in safe ranges."""
    service = ThreatIntelService()
    for ip in ["203.0.113.1", "198.51.100.5", "192.0.2.100"]:
        result = await service.lookup_ip(ip)
        assert result["is_malicious"] is True, f"{ip} should be blacklisted"
        assert "local_blacklist" in result["sources"], f"{ip} should be from local_blacklist"
        assert result["risk_modifier"] == 30


@pytest.mark.asyncio
async def test_safe_domain():
    service = ThreatIntelService()
    assert service.is_safe_domain("google.com") is True
    assert service.is_safe_domain("microsoft.com") is True
    assert service.is_safe_domain("github.com") is True
    assert service.is_safe_domain("evil-malware-site.com") is False


@pytest.mark.asyncio
async def test_reputation_api():
    service = ThreatIntelService()
    result = await service.get_reputation("10.0.0.1")
    assert result["reputation_score"] == 200
    assert result["is_malicious"] is False
