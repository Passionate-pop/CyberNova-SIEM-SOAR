"""Tests for the DLP engine — verifies sensitive data detection patterns."""
from __future__ import annotations
import pytest
from cybernova.protection.dlp import scan_text


def test_detects_aws_key():
    result = scan_text("My AWS key is AKIAIOSFODNN7EXAMPLE")
    assert result["findings"] is not None
    assert len(result["findings"]) > 0
    assert result["max_risk_score"] > 0


def test_detects_credit_card():
    result = scan_text("My card number is 4111111111111111")
    assert result["findings"] is not None
    assert len(result["findings"]) > 0
    assert any("card" in f["type"] for f in result["findings"])


def test_detects_ssn():
    result = scan_text("My SSN is 123-45-6789")
    assert len(result["findings"]) > 0
    assert any("ssn" in f["type"] for f in result["findings"])


def test_detects_jwt():
    result = scan_text("api_key=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8")
    assert len(result["findings"]) > 0


def test_detects_email():
    result = scan_text("Contact admin@cybernova.io for access")
    assert len(result["findings"]) > 0
    assert any("email" in f["type"] for f in result["findings"])


def test_clean_text_no_findings():
    result = scan_text("The quick brown fox jumps over the lazy dog")
    assert result["max_risk_score"] == 0
    assert len(result["findings"]) == 0
