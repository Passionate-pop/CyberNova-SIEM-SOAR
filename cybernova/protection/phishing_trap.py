"""
Phishing Trap — detects credential harvesting pages, phishing URLs,
fake login portals, and social engineering indicators.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict
from urllib.parse import urlparse

log = logging.getLogger("cybernova.protection.phishing_trap")

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                    ".loan", ".click", ".work", ".date", ".men", ".win"}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update",
    "confirm", "banking", "paypal", "amazon", "apple", "microsoft",
    "google", "facebook", "instagram", "netflix", "chase", "wellsfargo",
    "bankofamerica", "reset-password", "password-reset", "authenticate",
    "2fa", "two-factor", "verification", "security-check",
    "unusual-activity", "limited-access", "restricted",
]

FAKE_LOGIN_KEYWORDS = [
    r"(secure|login|account|verify|authenticate)[.\-_]*(bank|paypal|amazon|apple|google|microsoft|facebook)",
    r"(account|password|credit.?card|ssn|social.?security).*(verify|update|confirm)",
    r"(unusual|suspicious|unauthorized).*(login|access|activity|sign.?in)",
    r"(click|tap).*(verify|confirm|update).*(account|payment|billing)",
]

PHISHING_EMAIL_HEADERS = [
    r"Reply-To:\s*[^<]*<[^>]*@[^>]*(?!\bcorp\b|\bcompany\b)[^>]*>",
    r"From:\s*[^<]*service[^<]*<[^>]*@[a-z0-9.-]{3,}\.(tk|ml|ga|cf|gq|xyz)>",
]


def analyze_url(url: str) -> Dict[str, Any]:
    findings = []
    risk_score = 0.0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Check for IP address URL (instead of domain name)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain):
            findings.append({"type": "phishing_ip_url", "risk": 70.0,
                             "message": "URL uses IP address instead of domain name"})
            risk_score = max(risk_score, 70.0)

        # Check suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append({"type": "phishing_suspicious_tld", "risk": 55.0,
                                 "message": f"Suspicious TLD: {tld}"})
                risk_score = max(risk_score, 55.0)
                break

        # Check subdomain count (excessive subdomains = obfuscation)
        subdomain_parts = domain.split(".")
        if len(subdomain_parts) > 4:
            findings.append({"type": "phishing_excessive_subdomains", "risk": 50.0,
                             "message": f"Excessive subdomains: {domain}"})
            risk_score = max(risk_score, 50.0)

        # Check for homograph attack (mixed scripts)
        if re.search(r"[а-яА-Я]", domain):  # Cyrillic in domain
            findings.append({"type": "phishing_homograph_attack", "risk": 95.0,
                             "message": f"Homograph attack detected: {domain}"})
            risk_score = max(risk_score, 95.0)

        # Check path and query for suspicious keywords
        full_path = url.lower()
        for kw in SUSPICIOUS_FAKE_KEYWORDS:
            matches = list(re.finditer(kw, full_path))
            for m in matches:
                findings.append({"type": "phishing_suspicious_keyword", "risk": 65.0,
                                 "message": f"Suspicious content: '{m.group()[:50]}' in URL",
                                 "matched": m.group()[:50]})
                risk_score = max(risk_score, 65.0)

        # Check for @ in URL (credentials in URL)
        if "@" in url and "@" not in domain:
            findings.append({"type": "phishing_credentials_in_url", "risk": 85.0,
                             "message": "Credentials included in URL (before @)"})
            risk_score = max(risk_score, 85.0)

    except Exception as e:
        log.warning("PhishingTrap URL analysis failed for %s: %s", url[:100], e)

    return {
        "url": url[:200],
        "phishing_detected": len(findings) > 0,
        "max_risk_score": round(risk_score, 1),
        "finding_count": len(findings),
        "findings": findings,
    }


SUSPICIOUS_FAKE_KEYWORDS = [
    re.compile(p, re.I) for p in FAKE_LOGIN_KEYWORDS
]

SUSPICIOUS_EMAIL_HEADERS = [
    re.compile(p, re.I) for p in PHISHING_EMAIL_HEADERS
]


def analyze_email_content(subject: str, body: str, from_addr: str = "") -> Dict[str, Any]:
    findings = []
    risk_score = 0.0
    combined = f"{subject} {body}"

    # Urgency tactics
    urgency_words = ["urgent", "immediate", "action required", "account suspended",
                     "security alert", "unauthorized login", "verify now",
                     "limited time", "expire", "suspended", "restricted"]
    for word in urgency_words:
        if word.lower() in combined.lower():
            findings.append({"type": "phishing_urgency_tactic", "risk": 45.0,
                             "message": f"Urgency keyword: '{word}'"})
            risk_score = max(risk_score, 45.0)

    # Suspicious links
    urls = re.findall(r'https?://[^\s"\'<>]+', combined)
    for url in urls:
        url_result = analyze_url(url)
        if url_result["phishing_detected"]:
            findings.extend(url_result["findings"])
            risk_score = max(risk_score, url_result["max_risk_score"])

    # Mismatched sender display name
    if from_addr:
        display_match = re.match(r'^([^<]+)<([^>]+)>', from_addr)
        if display_match:
            display_name = display_match.group(1).strip().lower()
            email_addr = display_match.group(2).strip().lower()
            if display_name and email_addr:
                name_parts = display_name.replace(".", " ").split()
                email_local = email_addr.split("@")[0] if "@" in email_addr else ""
                if name_parts and email_local and not any(p in email_local for p in name_parts):
                    findings.append({"type": "phishing_spoofed_sender", "risk": 75.0,
                                     "message": f"Sender display name doesn't match email address: {from_addr[:80]}"})
                    risk_score = max(risk_score, 75.0)

    return {
        "phishing_detected": len(findings) > 0,
        "max_risk_score": round(risk_score, 1),
        "finding_count": len(findings),
        "findings": findings,
    }


phishing_trap = analyze_url
