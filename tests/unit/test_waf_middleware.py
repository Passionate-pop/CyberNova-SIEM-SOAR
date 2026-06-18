from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cybernova.protection.waf_middleware import register_waf_middleware

SAMPLE_MALICIOUS = {
    "method": "POST",
    "path": "/api/test",
    "source_ip": "127.0.0.1",
    "attack_detected": True,
    "blocked": True,
    "max_risk_score": 92.0,
    "findings": [
        {"rule": "sql_tautology", "category": "sqli", "severity": "critical", "risk_score": 92.0},
    ],
    "finding_count": 1,
}

SAMPLE_SUSPICIOUS = {**SAMPLE_MALICIOUS, "blocked": False}

SAMPLE_CLEAN = {
    "method": "GET",
    "path": "/api/items",
    "source_ip": "127.0.0.1",
    "attack_detected": False,
    "blocked": False,
    "max_risk_score": 0.0,
    "findings": [],
    "finding_count": 0,
}


@pytest.fixture
def app():
    app = FastAPI()
    register_waf_middleware(app)

    @app.post("/api/test")
    async def test_endpoint(request: Request):
        await request.body()
        return {"ok": True}

    @app.get("/api/items")
    async def list_items():
        return {"items": []}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/search")
    async def search(q: str = ""):
        return {"q": q}

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_waf_blocks_malicious_request(client):
    with patch("cybernova.protection.waf_middleware.waf_engine.analyze_request", return_value=SAMPLE_MALICIOUS):
        resp = client.post("/api/test", json={"q": "1' OR '1'='1"})
    assert resp.status_code == 403
    data = resp.json()
    assert data["detail"] == "Request blocked by Web Application Firewall"
    assert resp.headers.get("X-WAF-Blocked") == "true"
    assert resp.headers.get("X-WAF-Risk-Score") == "99.0"


def test_waf_attaches_headers_for_suspicious(client):
    with patch("cybernova.protection.waf_middleware.waf_engine.analyze_request", return_value=SAMPLE_SUSPICIOUS):
        # Use a benign payload that won't trigger pre-check (XSS/CMDi/SQLi regexes)
        resp = client.post("/api/test", json={"msg": "potentially suspicious activity detected"})
    assert resp.status_code == 200
    assert resp.headers.get("X-WAF-Inspected") == "true"
    assert resp.headers.get("X-WAF-Findings") == "1"
    # Engine mock returns max_risk_score=92.0 (SAMPLE_SUSPICIOUS)
    assert resp.headers.get("X-WAF-Risk-Score") == "92.0"


def test_waf_passes_clean_request(client):
    with patch("cybernova.protection.waf_middleware.waf_engine.analyze_request", return_value=SAMPLE_CLEAN):
        resp = client.get("/api/items")
    assert resp.status_code == 200
    assert resp.json() == {"items": []}
    assert resp.headers.get("X-WAF-Inspected") is None


def test_waf_skips_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert resp.headers.get("X-WAF-Inspected") is None


def test_waf_inspects_get_with_query_params(client):
    mock_result = {
        "method": "GET",
        "path": "/api/search",
        "source_ip": "127.0.0.1",
        "attack_detected": True,
        "blocked": False,
        "max_risk_score": 80.0,
        "findings": [
            {"rule": "xss_script_tag", "category": "xss", "severity": "high", "risk_score": 80.0},
        ],
        "finding_count": 1,
    }
    with patch("cybernova.protection.waf_middleware.waf_engine.analyze_request", return_value=mock_result) as mock:
        # Use a benign query value that won't trigger pre-check patterns
        resp = client.get("/api/search", params={"q": "legitimate-search-term"})
    assert resp.status_code == 200
    assert resp.headers.get("X-WAF-Inspected") == "true"
    _, kwargs = mock.call_args
    assert kwargs["method"] == "GET"
    assert kwargs["path"] == "/api/search"
    assert "q" in kwargs["query_params"]
