# Header Detective — Scorecard & Report Output Contract

**Module:** Scorecard + Report Generator (Pushkar, Member 5)  
**Input:** Tejas's `/analyze` output + Jayshree's geo enrichment + Ashith's language analysis  
**Output:** Multi-signal phishing scorecard + PDF report  
**Consumed by:** Sagar (Member 6) Dashboard Integrator

---

## Upstream Inputs

### 1. Tejas's `/analyze` output (required)

```json
{
  "file_hash_sha256": "string (64 hex chars)",
  "hops": [
    {
      "hop_index": 0,
      "from_host": "string|null",
      "from_ip": "string|null",
      "by_host": "string|null",
      "timestamp": "ISO-8601|null",
      "protocol": "string|null"
    }
  ],
  "auth": {
    "spf":    { "result": "pass|fail|softfail|neutral|none|error", "domain": "string|null", "details": "string" },
    "dkim":   { "result": "pass|fail|none|error", "selector": "string|null", "domain": "string|null" },
    "dmarc":  { "result": "pass|fail|none", "policy": "none|quarantine|reject|null",
                "alignment": { "spf": "bool", "dkim": "bool" } }
  },
  "sender_domain": "string|null",
  "warnings": ["string"]
}
```

### 2. Jayshree's geo enrichment (optional)

```json
{
  "sender_domain": "string|null",
  "hops": [ /* Tejas hops + geo key per hop */ ],
  "path": [ { "hop_index": 0, "lat": 53.38, "lon": -6.24, "city": "Dublin", "country": "Ireland" } ],
  "unresolved_hop_count": 3
}
```

### 3. Ashith's language analysis (optional)

```json
{
  "language_analysis": {
    "model": { "name": "string", "label": "string|null", "phishing_probability": "float|null", "score": "float|null", "available": "bool" },
    "rule_score": 0.0,
    "language_threat_score": 0.0,
    "classification": "low_risk|medium_risk|high_risk|critical_risk",
    "indicators": [ { "category": "string", "phrase": "string", "severity": "string" } ],
    "entities": { "persons": [], "organizations": [], "money": [], "dates": [], "locations": [] },
    "summary": ["string"],
    "warnings": ["string"]
  }
}
```

### 4. Link/Attachment risk from Sahishnu (future, not yet implemented)

Placeholder structure:

```json
{
  "link_analysis": {
    "urls_scanned": 0,
    "malicious_urls": 0,
    "suspicious_urls": 0,
    "malicious_attachments": 0,
    "link_risk_score": 0.0
  }
}
```

---

## Output: Scorecard JSON

Produced by `ScorecardBuilder.build()` in `scorecard_builder.py`.

```json
{
  "scorecard": {
    "overall_risk_level": "critical|high|medium|low|none",
    "overall_score": 0,
    "component_scores": {
      "auth_score": 0,
      "auth_weight": 0.25,
      "geo_score": 0,
      "geo_weight": 0.25,
      "language_score": 0,
      "language_weight": 0.25,
      "link_attachment_score": 0,
      "link_attachment_weight": 0.25
    },
    "key_indicators": [
      {
        "signal": "auth|geo|language|link",
        "severity": "critical|high|medium|low|info",
        "description": "string"
      }
    ],
    "recommendations": ["string"]
  },
  "report": {
    "file_hash": "string",
    "sender_domain": "string|null",
    "summary": "string",
    "detailed_findings": {
      "authentication": {
        "spf": { "result": "string", "explanation": "string" },
        "dkim": { "result": "string", "explanation": "string" },
        "dmarc": { "result": "string", "explanation": "string" }
      },
      "geolocation": {
        "resolved_hops": 0,
        "unresolved_hops": 0,
        "countries_visited": ["string"],
        "anomalies": ["string"]
      },
      "language": {
        "classification": "string",
        "threat_score": 0.0,
        "top_indicators": [ { "category": "string", "phrase": "string", "severity": "string" } ],
        "extracted_entities": { "persons": [], "organizations": [], "money": [] }
      },
      "routing": {
        "total_hops": 0,
        "protocols_used": ["string"],
        "suspicious_patterns": ["string"]
      }
    },
    "timeline": [
      {
        "hop_index": 0,
        "from_host": "string|null",
        "from_ip": "string|null",
        "by_host": "string|null",
        "timestamp": "string|null",
        "protocol": "string|null",
        "city": "string|null",
        "country": "string|null",
        "is_private": false,
        "anomaly_flags": ["string"]
      }
    ]
  }
}
```

---

## Scoring Methodology

### Composite Score (0–100)

The overall score is the sum of four component scores (each 0–30), capped at 100:

| Component | Max | Source | Scoring Logic |
|-----------|-----|--------|---------------|
| `auth_score` | 30 | `auth.spf`, `auth.dkim`, `auth.dmarc` | Each failed protocol contributes penalties |
| `geo_score` | 30 | `geo.hops[].geo`, `geo.path`, `geo.unresolved_hop_count` | Unresolved hops, impossible travel, routing anomalies |
| `language_score` | 30 | `language_analysis.language_threat_score` | Direct mapping from 0.0–1.0 to 0–30 |
| `link_attachment_score` | 30 | Sahishnu's module (future) | Defaults to 0 when unavailable |

### Threat Levels

| Score Range | Level | Meaning |
|-------------|-------|---------|
| 0–9 | `none` | No risk detected |
| 10–29 | `low` | Likely legitimate, minor anomalies |
| 30–59 | `medium` | Suspicious, warrants review |
| 60–79 | `high` | Probable phishing |
| 80–100 | `critical` | Almost certainly malicious |

### Auth Scoring (`auth_score` — max 30)

| Protocol | Result | Penalty |
|----------|--------|---------|
| SPF | `pass` | 0 |
| SPF | `softfail` | 5 |
| SPF | `neutral` | 4 |
| SPF | `none` | 7 |
| SPF | `fail` | 10 |
| SPF | `error` | 7 |
| DKIM | `pass` | 0 |
| DKIM | `none` | 7 |
| DKIM | `fail` | 10 |
| DKIM | `error` | 7 |
| DMARC | `pass` (policy=reject) | 0 |
| DMARC | `pass` (policy=quarantine) | 1 |
| DMARC | `pass` (policy=none) | 3 |
| DMARC | `none` | 7 |
| DMARC | `fail` | 10 |
| DMARC alignment failure | — | +2 |
| Multiple auth failures (SPF+DKIM both fail) | — | +3 bonus |

Total auth penalties sum to max 30 (capped).

### Geo Scoring (`geo_score` — max 30)

| Factor | Penalty |
|--------|---------|
| Each unresolved hop | +4 (capped at 15) |
| Unresolved ratio > 50% | +4 bonus |
| Impossible travel detected | +5 per occurrence (capped at 10) |
| Same country all hops | -2 (reduces score) |

Total geo penalties sum to max 30 (capped).

### Language Scoring (`language_score` — max 30)

Direct mapping: `language_threat_score` (0.0–1.0) × 30, rounded to nearest integer.

### Link/Attachment Scoring (`link_attachment_score` — max 30)

When Sahishnu's module is unavailable, defaults to 0. When available, `link_risk_score` (0.0–1.0) × 30.

---

## PDF Report

Produced by `ReportGenerator.generate_pdf()` in `report_generator.py`.

### Report Sections

1. **Header** — File SHA-256, sender domain, generation timestamp, overall threat badge
2. **Scorecard Summary** — Large composite score with color-coded gauge
3. **Authentication Results** — SPF/DKIM/DMARC with pass/fail indicators
4. **Geolocation Analysis** — Hop count, resolved/unresolved, countries, anomalies
5. **Language Analysis** — Classification, top indicators, entities
6. **Relay Timeline** — Tabular hop-by-hop breakdown
7. **Recommendations** — Actionable next steps based on score

### Visual Design

- Color coding: green (none/low), yellow (medium), orange (high), red (critical)
- Section headers with colored underlines
- Tables for structured data
- Bullet lists for findings

---

## TODO — Confirm with Sagar (Member 6) before integrating

> **These questions must be resolved directly with the downstream team member.**

1. **Payload consumption:** Will you consume the scorecard JSON from `/analyze-with-scorecard`, or import `ScorecardBuilder` directly?

2. **PDF report delivery:** Should the PDF be returned as a binary stream (`application/pdf`) alongside JSON, or stored on disk and served via a URL endpoint?

3. **Score weights:** Are equal 25% weights acceptable, or does the dashboard need configurable weights?

4. **Timeline fields:** Does the dashboard need `anomaly_flags` per hop, or is the overall score sufficient?

5. **Cached reports:** Should reports be cached by `file_hash_sha256` to avoid re-generating for the same email?

6. **Link/Attachment integration:** When Sahishnu's module is ready, should the scorecard auto-detect it, or require explicit opt-in?
