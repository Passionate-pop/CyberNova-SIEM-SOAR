"""
CyberNova — Intelligence Schemas
Pydantic models for IOC management, reputation scoring, threat feeds, and TAXII/STIX parsing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── IOC Models ──────────────────────────────────────────────────────────────

class IOCCreate(BaseModel):
    """Schema for adding a new IOC manually."""
    indicator: str = Field(..., min_length=1, max_length=512, description="The IOC value (IP, domain, hash, URL, etc.)")
    ioc_type: str = Field(
        ..., pattern=r"^(ip|domain|url|md5|sha1|sha256|hash|email|registry|mutex|text)$",
        description="Type of the indicator"
    )
    description: str = Field(default="", max_length=2000)
    source: str = Field(default="manual", max_length=100)
    added_by: Optional[str] = None

    @field_validator("indicator")
    @classmethod
    def trim_indicator(cls, v: str) -> str:
        return v.strip()


class IOCEntry(BaseModel):
    """A single IOC entry as stored in the database."""
    indicator: str
    type: str
    is_malicious: bool = True
    risk_modifier: int = Field(default=25, ge=0, le=100)
    description: str = ""
    source: str = "manual"
    added_by: Optional[str] = None
    created_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IOCListResponse(BaseModel):
    """Response for listing IOCs with pagination."""
    total: int
    iocs: List[IOCEntry]
    limit: int = 100


class IOCOperationResponse(BaseModel):
    """Response for IOC add/delete operations."""
    accepted: bool
    indicator: str
    type: Optional[str] = None
    error: Optional[str] = None


# ── Reputation Models ───────────────────────────────────────────────────────

class ReputationScore(BaseModel):
    """Reputation score for an IP address."""
    ip: str
    reputation_score: int = Field(..., ge=0, le=100, description="0 = malicious, 100 = safe")
    is_malicious: bool = False
    sources: List[str] = Field(default_factory=list)
    is_safe: bool = False
    safe_reason: Optional[str] = None
    from_cache: bool = False
    rate_limited: bool = False
    rate_limit_reason: Optional[str] = None
    risk_modifier: int = 0


class ThreatIntelLookup(BaseModel):
    """Full threat intelligence lookup result for an IP."""
    ip: str
    is_malicious: bool = False
    risk_modifier: int = 0
    is_safe: bool = False
    safe_reason: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
    virustotal: Optional[Dict[str, Any]] = None
    abuseipdb: Optional[Dict[str, Any]] = None
    otx: Optional[Dict[str, Any]] = None
    circuit_breakers: Dict[str, str] = Field(default_factory=dict)
    from_cache: bool = False
    rate_limited: bool = False
    rate_limit_reason: Optional[str] = None


# ── Feed Models ─────────────────────────────────────────────────────────────

class FeedSourceStats(BaseModel):
    """Statistics for a single feed source."""
    total_polls: int = 0
    total_iocs: int = 0
    last_poll_time: Optional[str] = None
    errors: int = 0
    running: bool = False


class FeedPollResponse(BaseModel):
    """Response after manually polling a feed."""
    accepted: bool
    iocs_ingested: int
    stats: FeedSourceStats
    error: Optional[str] = None


class FeedStatusResponse(BaseModel):
    """Current status of the feed scheduler."""
    running: bool
    total_polls: int
    total_iocs: int
    last_poll_time: Optional[str] = None
    errors: int = 0


# ── TAXII / STIX Models ─────────────────────────────────────────────────────

class TAXIICollectionInfo(BaseModel):
    """Information about a discovered TAXII collection."""
    name: str
    url: str
    collection_id: str
    description: Optional[str] = None


class TAXIIPollRequest(BaseModel):
    """Request to poll a specific TAXII feed."""
    discovery_url: str = Field(..., description="TAXII discovery endpoint URL")
    username: str = Field(default="")
    password: str = Field(default="")
    collection_names: Optional[List[str]] = Field(default=None, description="Optional subset of collections to poll")
    added_after: str = Field(default="")

    @field_validator("discovery_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("discovery_url must start with http:// or https://")
        return v.rstrip("/")


class MISPPollRequest(BaseModel):
    """Request to poll a specific MISP instance."""
    url: str = Field(..., description="MISP instance base URL")
    api_key: str = Field(..., min_length=1)
    verify_ssl: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v.rstrip("/")


class ParsedSTIXIndicator(BaseModel):
    """A parsed indicator from a STIX object."""
    type: str = Field(..., description="Indicator type: ip, domain, url, hash, etc.")
    value: str


class ParsedSTIXObject(BaseModel):
    """A parsed STIX 2.1 object from a TAXII feed."""
    stix_id: str
    name: str
    type: str  # indicator, malware, attack-pattern, threat-actor
    description: str = ""
    indicators: List[ParsedSTIXIndicator]
    labels: List[str] = Field(default_factory=list)
    created: str = ""
    source: str = "taxii"
    feed_url: Optional[str] = None


class MISPIndicator(BaseModel):
    """A parsed indicator from a MISP event attribute."""
    type: str
    value: str
    attr_type: str
    category: str = ""
    comment: str = ""
    event_info: str = ""
    threat_level: str = ""
    source: str = "misp"
    feed_url: Optional[str] = None


# ── Global Threat Feed ──────────────────────────────────────────────────────

class GlobalThreatFeedItem(BaseModel):
    """A single item in the global threat feed shown on the dashboard."""
    id: str
    indicator: str
    type: str
    risk_score: int = Field(default=0, ge=0, le=100)
    source: str
    timestamp: str
    description: str = ""
    severity: str = "medium"
    tags: List[str] = Field(default_factory=list)
    country: Optional[str] = None
    asn: Optional[str] = None
    tlp: str = "white"
    first_seen: str = ""
    last_seen: str = ""
    related_observables: List[str] = Field(default_factory=list)
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    kill_chain_phase: Optional[str] = None
    confidence: int = Field(default=50, ge=0, le=100)
