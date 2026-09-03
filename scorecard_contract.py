"""
Header Detective — Scorecard & Report Pydantic Contracts

Defines the exact JSON shapes produced by ScorecardBuilder and ReportGenerator.
Validates output before it reaches the dashboard or API consumer.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Scorecard sub-models
# ---------------------------------------------------------------------------

class ComponentScores(BaseModel):
    auth_score: int = Field(ge=0, le=30, description="Authentication penalty score (0=clean, 30=all fail)")
    auth_weight: float = 0.25
    geo_score: int = Field(ge=0, le=30, description="Geolocation anomaly score")
    geo_weight: float = 0.25
    language_score: int = Field(ge=0, le=30, description="Language/NLP threat score")
    language_weight: float = 0.25
    link_attachment_score: int = Field(ge=0, le=30, description="Link/attachment risk score")
    link_attachment_weight: float = 0.25


class KeyIndicator(BaseModel):
    signal: str = Field(description="Source signal: auth, geo, language, or link")
    severity: Severity
    description: str


class Scorecard(BaseModel):
    overall_risk_level: RiskLevel
    overall_score: int = Field(ge=0, le=100, description="Composite 0-100 threat score")
    component_scores: ComponentScores
    key_indicators: list[KeyIndicator] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Report sub-models
# ---------------------------------------------------------------------------

class AuthDetail(BaseModel):
    result: str
    explanation: str


class AuthReport(BaseModel):
    spf: AuthDetail
    dkim: AuthDetail
    dmarc: AuthDetail


class GeoReport(BaseModel):
    resolved_hops: int = 0
    unresolved_hops: int = 0
    countries_visited: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)


class LanguageReport(BaseModel):
    classification: str = "low_risk"
    threat_score: float = 0.0
    top_indicators: list[dict] = Field(default_factory=list)
    extracted_entities: dict = Field(default_factory=dict)


class RoutingReport(BaseModel):
    total_hops: int = 0
    protocols_used: list[str] = Field(default_factory=list)
    suspicious_patterns: list[str] = Field(default_factory=list)


class DetailedFindings(BaseModel):
    authentication: AuthReport
    geolocation: GeoReport
    language: LanguageReport
    routing: RoutingReport


class TimelineEntry(BaseModel):
    hop_index: int
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    timestamp: Optional[str] = None
    protocol: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    is_private: bool = False
    anomaly_flags: list[str] = Field(default_factory=list)


class Report(BaseModel):
    file_hash: str
    sender_domain: Optional[str] = None
    summary: str
    detailed_findings: DetailedFindings
    timeline: list[TimelineEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level combined output
# ---------------------------------------------------------------------------

class ScorecardReportOutput(BaseModel):
    scorecard: Scorecard
    report: Report
