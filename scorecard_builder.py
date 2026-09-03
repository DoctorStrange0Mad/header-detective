"""
Header Detective — Scorecard Builder

Computes a multi-signal phishing threat score from Tejas's auth output,
Jayshree's geo enrichment, and Ashith's language analysis. Produces a
structured scorecard with key indicators and recommendations.

Usage:
    from scorecard_builder import ScorecardBuilder

    builder = ScorecardBuilder()
    result = builder.build(tejas_output, geo_payload=geo, language_output=lang)
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Optional

from scorecard_contract import (
    AuthDetail,
    AuthReport,
    ComponentScores,
    DetailedFindings,
    GeoReport,
    KeyIndicator,
    LanguageReport,
    Report,
    RiskLevel,
    Scorecard,
    ScorecardReportOutput,
    Severity,
    TimelineEntry,
    RoutingReport,
)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

_EARTH_RADIUS_KM = 6371.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points on Earth (km)."""
    rlat1, rlon1, rlat2, rlon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = rlat2 - rlat1
    dlon = rlon2 - rlon1
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO-8601 timestamp string, return datetime or None."""
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def score_auth(auth: dict[str, Any]) -> tuple[int, list[KeyIndicator]]:
    """Score authentication results. Returns (score, indicators). Max 30."""
    indicators: list[KeyIndicator] = []
    penalty = 0

    # --- SPF (max 10) ---
    spf = auth.get("spf", {})
    spf_result = spf.get("result", "none")
    spf_map = {"pass": 0, "softfail": 5, "neutral": 4, "none": 7, "fail": 10, "error": 7}
    spf_pen = spf_map.get(spf_result, 7)
    penalty += spf_pen
    if spf_result in ("fail", "softfail", "none", "error"):
        indicators.append(KeyIndicator(
            signal="auth",
            severity=Severity.HIGH if spf_result == "fail" else Severity.MEDIUM,
            description=f"SPF {spf_result}: {spf.get('details', '')}".strip(),
        ))

    # --- DKIM (max 10) ---
    dkim = auth.get("dkim", {})
    dkim_result = dkim.get("result", "none")
    dkim_map = {"pass": 0, "none": 7, "fail": 10, "error": 7}
    dkim_pen = dkim_map.get(dkim_result, 7)
    penalty += dkim_pen
    if dkim_result in ("fail", "none", "error"):
        indicators.append(KeyIndicator(
            signal="auth",
            severity=Severity.HIGH if dkim_result == "fail" else Severity.MEDIUM,
            description=f"DKIM {dkim_result}" + (f" (selector={dkim.get('selector')})" if dkim.get("selector") else ""),
        ))

    # --- DMARC (max 10) ---
    dmarc = auth.get("dmarc", {})
    dmarc_result = dmarc.get("result", "none")
    dmarc_policy = dmarc.get("policy")
    alignment = dmarc.get("alignment", {})

    dmarc_pen = 0
    if dmarc_result == "pass":
        policy_map = {"reject": 0, "quarantine": 1, "none": 3, None: 3}
        dmarc_pen = policy_map.get(dmarc_policy, 3)
    elif dmarc_result == "fail":
        dmarc_pen = 10
    else:
        dmarc_pen = 7

    # Alignment failure bonus
    if dmarc_result == "pass" and not alignment.get("spf", False) and not alignment.get("dkim", False):
        dmarc_pen += 2
        indicators.append(KeyIndicator(
            signal="auth",
            severity=Severity.MEDIUM,
            description="DMARC passed but neither SPF nor DKIM aligned",
        ))

    penalty += dmarc_pen
    if dmarc_result == "fail":
        indicators.append(KeyIndicator(
            signal="auth",
            severity=Severity.HIGH,
            description=f"DMARC failed (policy={dmarc_policy})",
        ))
    elif dmarc_result == "none":
        indicators.append(KeyIndicator(
            signal="auth",
            severity=Severity.MEDIUM,
            description="No DMARC record found for sender domain",
        ))

    # Bonus: multiple auth failures compound risk
    if spf_result == "fail" and dkim_result == "fail":
        penalty += 3
        indicators.append(KeyIndicator(
            signal="auth",
            severity=Severity.CRITICAL,
            description="Both SPF and DKIM failed — strong spoofing indicator",
        ))

    return _clamp(penalty, high=30), indicators


def score_geo(
    hops: list[dict[str, Any]],
    path: list[dict[str, Any]],
    unresolved_count: int,
) -> tuple[int, list[KeyIndicator]]:
    """Score geolocation anomalies. Returns (score, indicators). Max 30."""
    indicators: list[KeyIndicator] = []
    penalty = 0
    total_hops = len(hops)

    if total_hops == 0:
        return 0, indicators

    # --- Unresolved hops (max 15) ---
    unresolved_pen = min(unresolved_count * 4, 15)
    penalty += unresolved_pen
    if unresolved_count > 0:
        ratio = unresolved_count / total_hops
        severity = Severity.HIGH if ratio > 0.5 else Severity.MEDIUM
        indicators.append(KeyIndicator(
            signal="geo",
            severity=severity,
            description=f"{unresolved_count}/{total_hops} hops unresolved (private/loopback IPs)",
        ))
        if ratio > 0.5:
            penalty += 4

    # --- Impossible travel detection (max 10) ---
    impossible_travel_count = 0
    for i in range(len(path) - 1):
        h1 = path[i]
        h2 = path[i + 1]
        if h1.get("lat") is None or h2.get("lat") is None:
            continue
        distance = _haversine_km(h1["lat"], h1["lon"], h2["lat"], h2["lon"])

        # Large jumps suggest spoofing or misconfigured relays
        if distance > 5000:
            impossible_travel_count += 1
            indicators.append(KeyIndicator(
                signal="geo",
                severity=Severity.HIGH,
                description=f"Large geographic jump: {h1.get('city') or h1.get('country', '?')} → {h2.get('city') or h2.get('country', '?')} ({distance:.0f} km)",
            ))

    impossible_pen = min(impossible_travel_count * 5, 10)
    penalty += impossible_pen

    # --- Same country bonus (reduces score) ---
    countries = {p.get("country") for p in path if p.get("country")}
    if len(countries) == 1 and len(path) > 1:
        penalty -= 2

    return _clamp(penalty, high=30), indicators


def score_language(language_output: Optional[dict[str, Any]]) -> tuple[int, list[KeyIndicator]]:
    """Score language/NLP threat. Returns (score, indicators). Max 30."""
    indicators: list[KeyIndicator] = []

    if not language_output:
        return 0, indicators

    lang = language_output.get("language_analysis", {})
    threat_score = lang.get("language_threat_score", 0.0)
    score = _clamp(round(threat_score * 30), high=30)

    # Top indicators
    for ind in lang.get("indicators", [])[:3]:
        sev_str = ind.get("severity", "medium")
        try:
            sev = Severity(sev_str)
        except ValueError:
            sev = Severity.MEDIUM
        indicators.append(KeyIndicator(
            signal="language",
            severity=sev,
            description=f"[{ind.get('category', '?')}] \"{ind.get('phrase', '?')}\"",
        ))

    classification = lang.get("classification", "low_risk")
    if classification in ("high_risk", "critical_risk"):
        indicators.append(KeyIndicator(
            signal="language",
            severity=Severity.HIGH if classification == "high_risk" else Severity.CRITICAL,
            description=f"Language classification: {classification} (score={threat_score:.2f})",
        ))

    return score, indicators


def score_links(link_data: Optional[dict[str, Any]]) -> tuple[int, list[KeyIndicator]]:
    """Score link/attachment risk. Returns (score, indicators). Max 30."""
    indicators: list[KeyIndicator] = []

    if not link_data:
        return 0, indicators

    link_analysis = link_data.get("link_analysis", {})
    risk_score = link_analysis.get("link_risk_score", 0.0)
    malicious = link_analysis.get("malicious_urls", 0)
    suspicious = link_analysis.get("suspicious_urls", 0)

    score = _clamp(round(risk_score * 30), high=30)

    if malicious > 0:
        indicators.append(KeyIndicator(
            signal="link",
            severity=Severity.CRITICAL,
            description=f"{malicious} malicious URL(s) detected",
        ))
    if suspicious > 0:
        indicators.append(KeyIndicator(
            signal="link",
            severity=Severity.HIGH,
            description=f"{suspicious} suspicious URL(s) detected",
        ))

    return score, indicators


# ---------------------------------------------------------------------------
# Suspicious routing pattern detection
# ---------------------------------------------------------------------------

def _detect_suspicious_patterns(hops: list[dict[str, Any]], path: list[dict[str, Any]]) -> list[str]:
    """Detect suspicious routing patterns in the hop chain."""
    patterns: list[str] = []

    # Check for excessive hops
    if len(hops) > 10:
        patterns.append(f"Unusually long relay chain ({len(hops)} hops)")

    # Check for loopback chains
    loopback_streak = 0
    max_loopback_streak = 0
    for hop in hops:
        ip = hop.get("from_ip", "")
        if ip and ip.startswith("127."):
            loopback_streak += 1
            max_loopback_streak = max(max_loopback_streak, loopback_streak)
        else:
            loopback_streak = 0
    if max_loopback_streak >= 2:
        patterns.append(f"Multiple consecutive loopback hops (streak: {max_loopback_streak})")

    # Check for protocol anomalies
    protocols = {hop.get("protocol") for hop in hops if hop.get("protocol")}
    if "IMAP (fetchmail-5.9.0)" in protocols:
        patterns.append("fetchmail protocol detected (local mail retrieval)")
    if len(protocols) > 3:
        patterns.append(f"Multiple protocols used: {', '.join(sorted(protocols))}")

    # Check for duplicate IPs
    ips = [hop.get("from_ip") for hop in hops if hop.get("from_ip")]
    seen = set()
    dupes = set()
    for ip in ips:
        if ip in seen:
            dupes.add(ip)
        seen.add(ip)
    if dupes:
        patterns.append(f"Duplicate sender IPs: {', '.join(sorted(dupes))}")

    return patterns


# ---------------------------------------------------------------------------
# Report generation helpers
# ---------------------------------------------------------------------------

def _explain_spf(result: str) -> str:
    explanations = {
        "pass": "Sender IP is authorized to send for this domain.",
        "fail": "Sender IP is NOT authorized. This is a strong spoofing indicator.",
        "softfail": "Sender IP is not authorized, but the domain is not strictly rejecting.",
        "neutral": "SPF record exists but makes no assertion about the sender.",
        "none": "No SPF record found. Domain is unprotected against spoofing.",
        "error": "SPF check failed due to a DNS or processing error.",
    }
    return explanations.get(result, f"SPF result: {result}")


def _explain_dkim(result: str) -> str:
    explanations = {
        "pass": "Email signature verified. Message integrity confirmed.",
        "fail": "DKIM signature verification failed. Message may be tampered with.",
        "none": "No DKIM signature found. Domain does not sign emails.",
        "error": "DKIM check encountered an error.",
    }
    return explanations.get(result, f"DKIM result: {result}")


def _explain_dmarc(result: str, policy: Optional[str]) -> str:
    if result == "pass":
        return f"DMARC policy active (p={policy or 'none'}). Alignment {'verified' if policy in ('reject', 'quarantine') else 'present but not enforced'}."
    if result == "fail":
        return "DMARC check failed. Sender domain's DMARC policy was not satisfied."
    return "No DMARC policy configured. Domain is vulnerable to email spoofing."


def _build_timeline(
    hops: list[dict[str, Any]],
    geo_hops: Optional[list[dict[str, Any]]] = None,
) -> list[TimelineEntry]:
    """Build the hop-by-hop timeline for the report."""
    timeline: list[TimelineEntry] = []
    geo_map: dict[int, dict] = {}

    if geo_hops:
        for gh in geo_hops:
            geo_map[gh.get("hop_index", -1)] = gh

    for hop in hops:
        idx = hop.get("hop_index", -1)
        geo = geo_map.get(idx, {}).get("geo") if geo_hops else None
        from ipaddress import ip_address as _ip_parse

        is_private = False
        ip_str = hop.get("from_ip")
        if ip_str:
            try:
                ip_obj = _ip_parse(ip_str)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            except (ValueError, AttributeError):
                pass

        anomaly_flags: list[str] = []
        if is_private:
            anomaly_flags.append("private_ip")
        if hop.get("timestamp"):
            ts = _parse_timestamp(hop["timestamp"])
            if ts and ts.year < 2000:
                anomaly_flags.append("unusually_old_timestamp")

        timeline.append(TimelineEntry(
            hop_index=idx,
            from_host=hop.get("from_host"),
            from_ip=hop.get("from_ip"),
            by_host=hop.get("by_host"),
            timestamp=hop.get("timestamp"),
            protocol=hop.get("protocol"),
            city=geo.get("city") if geo else None,
            country=geo.get("country") if geo else None,
            is_private=is_private,
            anomaly_flags=anomaly_flags,
        ))

    return timeline


def _generate_recommendations(
    risk_level: RiskLevel,
    auth_indicators: list[KeyIndicator],
    geo_indicators: list[KeyIndicator],
    lang_indicators: list[KeyIndicator],
) -> list[str]:
    """Generate actionable recommendations based on findings."""
    recs: list[str] = []

    if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        recs.append("Do NOT interact with links or attachments in this email.")
        recs.append("Report this email to your security team immediately.")

    # Auth recommendations
    auth_fails = [i for i in auth_indicators if i.signal == "auth" and i.severity in (Severity.HIGH, Severity.CRITICAL)]
    if auth_fails:
        spf_fail = any("SPF" in i.description and "fail" in i.description.lower() for i in auth_fails)
        dkim_fail = any("DKIM" in i.description and "fail" in i.description.lower() for i in auth_fails)
        if spf_fail and dkim_fail:
            recs.append("Both SPF and DKIM failed — this email is very likely spoofed.")
        elif spf_fail:
            recs.append("SPF failure indicates the sender IP is not authorized for this domain.")
        elif dkim_fail:
            recs.append("DKIM failure suggests the email was modified in transit or forged.")

    # Geo recommendations
    geo_anomalies = [i for i in geo_indicators if i.severity in (Severity.HIGH, Severity.CRITICAL)]
    if geo_anomalies:
        recs.append("Geographic anomalies in relay path suggest email may not originate from claimed source.")

    # Language recommendations
    lang_critical = [i for i in lang_indicators if i.severity in (Severity.HIGH, Severity.CRITICAL)]
    if lang_critical:
        recs.append("Language analysis flagged phishing indicators — treat with high suspicion.")

    if not recs:
        recs.append("No significant issues detected. Exercise normal caution.")

    return recs


def _build_summary(
    risk_level: RiskLevel,
    overall_score: int,
    sender_domain: Optional[str],
    auth: dict,
    total_hops: int,
    lang_classification: Optional[str],
) -> str:
    """Generate a one-paragraph executive summary."""
    domain_str = sender_domain or "unknown domain"
    spf_r = auth.get("spf", {}).get("result", "?")
    dkim_r = auth.get("dkim", {}).get("result", "?")
    dmarc_r = auth.get("dmarc", {}).get("result", "?")

    parts = [
        f"Email from {domain_str} received a {risk_level.value} risk score of {overall_score}/100.",
        f"Authentication: SPF={spf_r}, DKIM={dkim_r}, DMARC={dmarc_r}.",
        f"Relay chain traced through {total_hops} hop(s).",
    ]

    if lang_classification:
        parts.append(f"Language analysis classified the content as {lang_classification}.")

    if risk_level == RiskLevel.CRITICAL:
        parts.append("This email exhibits strong indicators of phishing or spoofing and should be treated as malicious.")
    elif risk_level == RiskLevel.HIGH:
        parts.append("This email shows multiple suspicious indicators and warrants immediate review.")
    elif risk_level == RiskLevel.MEDIUM:
        parts.append("Some anomalies detected; manual review recommended.")
    elif risk_level == RiskLevel.LOW:
        parts.append("Minor anomalies found but likely legitimate.")
    else:
        parts.append("No significant risk indicators detected.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

class ScorecardBuilder:
    """
    Multi-signal phishing scorecard builder.

    Ingests outputs from upstream modules and produces a unified threat
    scorecard with key indicators, recommendations, and a structured report.

    Usage:
        builder = ScorecardBuilder()
        result = builder.build(
            tejas_output,
            geo_payload=geo_payload,        # optional
            language_output=language_output, # optional
            link_data=link_data,             # optional (future)
        )
    """

    def build(
        self,
        tejas_output: dict[str, Any],
        geo_payload: Optional[dict[str, Any]] = None,
        language_output: Optional[dict[str, Any]] = None,
        link_data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Build the full scorecard + report from upstream module outputs.

        Args:
            tejas_output: Full output from process_email() / /analyze
            geo_payload:  Output from build_map_payload() (optional)
            language_output: Output from analyze_eml() / analyze_email() (optional)
            link_data:    Future: link/attachment analysis (optional)

        Returns:
            Dict matching ScorecardReportOutput schema.
        """
        auth = tejas_output.get("auth", {})
        hops = tejas_output.get("hops", [])
        warnings = tejas_output.get("warnings", [])
        sender_domain = tejas_output.get("sender_domain")

        # Extract geo data
        geo_hops = None
        geo_path: list[dict] = []
        unresolved_count = 0
        if geo_payload:
            geo_hops = geo_payload.get("hops")
            geo_path = geo_payload.get("path", [])
            unresolved_count = geo_payload.get("unresolved_hop_count", 0)

        # --- Component scores ---
        auth_score, auth_indicators = score_auth(auth)
        geo_score, geo_indicators = score_geo(hops, geo_path, unresolved_count)
        lang_score, lang_indicators = score_language(language_output)
        link_score, link_indicators = score_links(link_data)

        # --- Composite (each component max 30, sum capped at 100) ---
        total = auth_score + geo_score + lang_score + link_score
        overall = _clamp(total, high=100)

        # --- Risk level ---
        risk_level = _classify_risk(overall)

        # --- All indicators ---
        all_indicators = auth_indicators + geo_indicators + lang_indicators + link_indicators
        all_indicators.sort(key=lambda i: list(Severity).index(i.severity), reverse=True)

        # --- Component scores ---
        components = ComponentScores(
            auth_score=auth_score,
            geo_score=geo_score,
            language_score=lang_score,
            link_attachment_score=link_score,
        )

        # --- Recommendations ---
        recommendations = _generate_recommendations(risk_level, auth_indicators, geo_indicators, lang_indicators)

        # --- Build scorecard ---
        scorecard = Scorecard(
            overall_risk_level=risk_level,
            overall_score=overall,
            component_scores=components,
            key_indicators=all_indicators,
            recommendations=recommendations,
        )

        # --- Build report ---
        total_hops = len(hops)
        protocols = sorted({h.get("protocol") for h in hops if h.get("protocol")})
        suspicious_patterns = _detect_suspicious_patterns(hops, geo_path)

        # Geolocation details
        countries = sorted({p.get("country") for p in geo_path if p.get("country")})
        geo_anomalies = [i.description for i in geo_indicators]

        # Language details
        lang_data = language_output.get("language_analysis", {}) if language_output else {}
        top_indicators = lang_data.get("indicators", [])[:5]
        entities = lang_data.get("entities", {})

        # Include all auth/geo/language warnings
        report_warnings = list(warnings)
        if lang_data:
            report_warnings.extend(lang_data.get("warnings", []))

        findings = DetailedFindings(
            authentication=AuthReport(
                spf=AuthDetail(result=auth.get("spf", {}).get("result", "none"), explanation=_explain_spf(auth.get("spf", {}).get("result", "none"))),
                dkim=AuthDetail(result=auth.get("dkim", {}).get("result", "none"), explanation=_explain_dkim(auth.get("dkim", {}).get("result", "none"))),
                dmarc=AuthDetail(result=auth.get("dmarc", {}).get("result", "none"), explanation=_explain_dmarc(auth.get("dmarc", {}).get("result", "none"), auth.get("dmarc", {}).get("policy"))),
            ),
            geolocation=GeoReport(
                resolved_hops=total_hops - unresolved_count,
                unresolved_hops=unresolved_count,
                countries_visited=countries,
                anomalies=geo_anomalies,
            ),
            language=LanguageReport(
                classification=lang_data.get("classification", "low_risk"),
                threat_score=lang_data.get("language_threat_score", 0.0),
                top_indicators=top_indicators,
                extracted_entities=entities,
            ),
            routing=RoutingReport(
                total_hops=total_hops,
                protocols_used=protocols,
                suspicious_patterns=suspicious_patterns,
            ),
        )

        summary = _build_summary(risk_level, overall, sender_domain, auth, total_hops, lang_data.get("classification"))
        timeline = _build_timeline(hops, geo_hops)

        report = Report(
            file_hash=tejas_output.get("file_hash_sha256", ""),
            sender_domain=sender_domain,
            summary=summary,
            detailed_findings=findings,
            timeline=timeline,
        )

        output = ScorecardReportOutput(scorecard=scorecard, report=report)
        return output.model_dump(mode="json")


def _classify_risk(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    if score >= 10:
        return RiskLevel.LOW
    return RiskLevel.NONE


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scorecard_builder.py <tejas_output.json> [geo_payload.json] [language_output.json]")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        tejas = json.load(f)

    geo = None
    lang = None
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            geo = json.load(f)
    if len(sys.argv) > 3:
        with open(sys.argv[3]) as f:
            lang = json.load(f)

    builder = ScorecardBuilder()
    result = builder.build(tejas, geo_payload=geo, language_output=lang)
    print(json.dumps(result, indent=2))
