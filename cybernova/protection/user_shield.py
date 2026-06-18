from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

log = logging.getLogger("cybernova.protection.user_shield")

SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan",
    ".click", ".work", ".date", ".men", ".win", ".bid", ".trade",
    ".webcam", ".science", ".party", ".review", ".country", ".stream",
    ".download", ".myftpupload", ".beatstream", ".surf", ".gdn",
}

HOMOGRAPH_CHARS: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "к": "k",
    "м": "m", "н": "h", "в": "b", "т": "t",
}

URGENCY_KEYWORDS: List[str] = [
    "urgent", "immediate action", "account suspended", "security alert",
    "unauthorized login", "verify now", "limited time", "expires",
    "suspended", "restricted", "disabled", "terminated",
    "unusual activity", "suspicious login", "someone accessed",
    "click here", "download now", "act now", "don't lose",
    "final warning", "last notice", "overdue", "payment required",
    "confirm identity", "verify account", "update billing",
]

FAKE_LOGIN_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:sign[-\s]?in|log[-\s]?in|login).*(?:account|bank|paypal|amazon|apple|microsoft)", re.I),
    re.compile(r"(?:verify|confirm|update).*(?:identity|account|payment|billing|credit)", re.I),
    re.compile(r"(?:unusual|suspicious|unauthorized).*(?:login|access|activity|sign.in)", re.I),
    re.compile(r"(?:click|tap).*(?:verify|confirm|update).*(?:account|payment)", re.I),
    re.compile(r"(?:password|credential|ssn|social.security|credit.card).*(?:expir|reset|verify)", re.I),
]

BEC_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:ceo|cfo|president|director|manager|owner).*(?:request|authorize|approve|transfer)", re.I),
    re.compile(r"(?:wire|payment|ach|transfer|invoice).*(?:urgent|immediate|asap)", re.I),
    re.compile(r"(?:confidential|secret|private|restricted).*(?:attach|document|file)", re.I),
    re.compile(r"(?:gift.card|itunes|amazon.card|google.play).*(?:purchase|buy|send)", re.I),
]

SPOOFED_SENDER_PATTERNS: List[re.Pattern] = [
    re.compile(r"service[@\s]|support[@\s]|help[@\s]|admin[@\s]|no.?reply[@\s]", re.I),
    re.compile(r"@.*(?:gmail|yahoo|hotmail|outlook|aol|protonmail|tutanota)", re.I),
]

SOCIAL_ENG_TOPICS: List[str] = [
    "inheritance", "lottery", "prize", "won", "award", "grant",
    "funds transfer", "overseas", "beneficiary", "estate",
    "donation", "charity", "investment opportunity",
    "work from home", "make money", "cryptocurrency",
    "romance", "dating", "military", "deployed",
]

KNOWN_PHISHING_KITS: Set[str] = {
    "phishkit", "evilginx", "modlishka", "mfakess",
    "socialfish", "gophish", "kingphisher", "setoolkit",
}


class UserShield:
    def __init__(self):
        self._url_reputation: Dict[str, Tuple[float, float]] = {}
        self._sender_history: Dict[str, List[float]] = defaultdict(list)
        self._phish_attempts: Dict[str, List[float]] = defaultdict(list)
        self._last_cleanup: float = time.time()

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        """Analyze event for social engineering, phishing, and credential abuse."""
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        event.get("message", "")
        source_ip = event.get("source_ip", extra.get("src_ip", ""))

        if etype in ("http_request", "web_request"):
            url = extra.get("url", extra.get("path", ""))
            self._analyze_url(url, results)

        if etype in ("email_event", "email_received"):
            subject = extra.get("subject", "")
            body = extra.get("body", "")
            sender = extra.get("from", extra.get("sender", ""))
            self._analyze_email(subject, body, sender, results)

        if etype in ("failed_login", "login_failure", "authentication_failure"):
            user = event.get("user", extra.get("user", ""))
            self._detect_credential_abuse(source_ip, user, results)

        self._cleanup()

        return results

    def _analyze_url(self, url: str, res: dict):
        if not url:
            return
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception as e:
            log.warning("URL parse error: %s", e)
            return

        now = time.time()
        if domain in self._url_reputation:
            last_seen, last_risk = self._url_reputation[domain]
            if now - last_seen < 3600:
                if last_risk >= 70:
                    self._add_finding(res, "known_phishing_domain", f"Previously flagged phishing domain: {domain}", last_risk, {"domain": domain})
                    return

        risk = 0.0
        findings = []

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain):
            findings.append(("ip_address_url", 70, "URL uses IP instead of domain"))
            risk = max(risk, 70)

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(("suspicious_tld", 55, f"Suspicious TLD: {tld}"))
                risk = max(risk, 55)
                break

        parts = domain.split(".")
        if len(parts) > 4:
            findings.append(("excessive_subdomains", 50, f"Excessive subdomains: {domain}"))
            risk = max(risk, 50)

        for cyrillic, latin in HOMOGRAPH_CHARS.items():
            if cyrillic in domain:
                findings.append(("homograph_attack", 95, f"Homograph attack: {domain} contains Cyrillic '{cyrillic}'"))
                risk = max(risk, 95)
                break

        for kw in ["login", "signin", "verify", "account", "secure", "confirm", "banking", "paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix", "chase", "wellsfargo", "bankofamerica", "password-reset", "authenticate", "2fa", "two-factor", "verification", "security-check", "unusual-activity", "limited-access", "restricted"]:
            if kw in domain:
                findings.append(("brand_impersonation", 72, f"Brand impersonation: '{kw}' in {domain}"))
                risk = max(risk, 72)

        if "@" in url and "@" not in domain:
            findings.append(("credentials_in_url", 85, "Credentials in URL before @"))
            risk = max(risk, 85)

        for phish in KNOWN_PHISHING_KITS:
            if phish in url.lower():
                findings.append(("phishing_kit", 95, f"Known phishing kit: {phish}"))
                risk = max(risk, 95)

        self._url_reputation[domain] = (now, risk)
        for ftype, r, msg in findings:
            self._add_finding(res, f"phishing_{ftype}", msg, r, {"domain": domain, "url": url[:120]})

    def _analyze_email(self, subject: str, body: str, sender: str, res: dict):
        combined = f"{subject} {body}".lower()
        now = time.time()
        self._sender_history[sender].append(now)
        self._sender_history[sender] = [t for t in self._sender_history[sender] if t > now - 86400]

        for word in URGENCY_KEYWORDS:
            if word.lower() in combined:
                self._add_finding(res, "phishing_urgency", f"Urgency tactic: '{word}' in email", 50, {"word": word})
                break

        for pat in FAKE_LOGIN_PATTERNS:
            if pat.search(combined):
                self._add_finding(res, "phishing_fake_login", f"Fake login pattern: {pat.pattern[:50]}", 82, {"pattern": pat.pattern[:60]})
                break

        for pat in BEC_PATTERNS:
            if pat.search(combined):
                self._add_finding(res, "bec_attempt", f"BEC pattern: {pat.pattern[:50]}", 88, {"pattern": pat.pattern[:60]})
                break

        for topic in SOCIAL_ENG_TOPICS:
            if topic in combined:
                self._add_finding(res, "social_engineering", f"Social engineering topic: '{topic}'", 65, {"topic": topic})
                break

        urls = re.findall(r"https?://[^\s\"'<>]+", combined)
        for url in urls[:5]:
            self._analyze_url(url, res)

        if sender:
            for pat in SPOOFED_SENDER_PATTERNS:
                if pat.search(sender):
                    sender_name = sender.split("<")[0].strip() if "<" in sender else sender
                    email_part = sender.split("<")[1].split(">")[0] if "<" in sender else sender
                    if sender_name and email_part and sender_name.lower() not in email_part.lower():
                        self._add_finding(res, "phishing_spoofed_sender", f"Spoofed sender: {sender[:80]}", 78, {"sender": sender[:120]})
                        break

        if len(self._sender_history[sender]) > 20:
            self._add_finding(res, "email_flood", f"Email flood from {sender}: {len(self._sender_history[sender])} in 24h", 60, {"sender": sender, "count": len(self._sender_history[sender])})

    def _detect_credential_abuse(self, source_ip: str, user: str, res: dict):
        now = time.time()
        self._phish_attempts[source_ip].append(now)
        self._phish_attempts[source_ip] = [t for t in self._phish_attempts[source_ip] if t > now - 300]
        if len(self._phish_attempts[source_ip]) > 20:
            self._add_finding(res, "credential_stuffing", f"Credential stuffing from {source_ip}: {len(self._phish_attempts[source_ip])} attempts", 88, {"source_ip": source_ip, "count": len(self._phish_attempts[source_ip])})

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < 3600:
            return
        self._last_cleanup = now
        cutoff = now - 86400
        self._sender_history = defaultdict(list, {k: v for k, v in self._sender_history.items() if v and v[-1] > cutoff})
        if len(self._url_reputation) > 10000:
            self._url_reputation = {k: v for k, v in list(self._url_reputation.items())[-5000:]}

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True


user_shield = UserShield()
