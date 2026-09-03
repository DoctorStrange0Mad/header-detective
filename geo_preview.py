"""
Header Detective - Geo Preview API (Jayshree, Member 2)

A lightweight FastAPI test harness that lets you POST raw hops JSON directly
to /geo-preview and get back the map payload — no .eml file, no Tejas's full
pipeline needed.

This is a DEV TOOL only. It is separate from Tejas's api.py and does NOT
touch main.py / hop_parser.py / auth_checks.py.

Run:
    pip install fastapi uvicorn geoip2
    uvicorn geo_preview:app --reload --port 8002

Then POST from curl or the React dev UI:
    curl -X POST http://localhost:8002/geo-preview \\
         -H "Content-Type: application/json" \\
         -d @sample_hops.json

Or open the auto-docs in your browser:
    http://localhost:8002/docs

Sample body shape (mirrors Tejas's /analyze output — only "hops" is required):
{
    "sender_domain": "example.com",
    "hops": [
        {
            "hop_index": 0,
            "from_host": "mail.attacker.io",
            "from_ip": "103.21.244.0",
            "by_host": "mx1.example.com",
            "timestamp": "2024-08-01T10:00:00+00:00",
            "protocol": "ESMTP"
        }
    ]
}
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from geo_lookup import build_map_payload, _get_reader

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Header Detective — Geo Preview",
    description=(
        "Dev harness for the Geo Visualizer module. "
        "POST a hops list, get back the map payload without needing a .eml file."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # fine for local dev; tighten for production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class HopIn(BaseModel):
    """
    One relay hop, matching Tejas's exact output schema from hop_parser.py:
        hop_index, from_host, from_ip, by_host, timestamp, protocol

    Only hop_index is strictly required; everything else is optional so you
    can send partial/synthetic hops during UI development.

    NOTE: there is no by_ip field — by_host is a hostname string, not an IP.
    """
    hop_index: int
    from_host: Optional[str] = None
    from_ip:   Optional[str] = None
    by_host:   Optional[str] = None
    timestamp: Optional[str] = None
    protocol:  Optional[str] = None

    class Config:
        extra = "allow"   # pass-through any extra fields Tejas adds in future


class GeoPreviewRequest(BaseModel):
    sender_domain: Optional[str] = Field(None, example="example.com")
    hops: List[HopIn] = Field(..., min_length=1, example=[
        {
            "hop_index": 0,
            "from_ip": "103.21.244.0",
            "by_host": "mx1.example.com",
        }
    ])

    # Allow Tejas's full output to be pasted in directly (extra keys ignored)
    class Config:
        extra = "allow"


class PathPoint(BaseModel):
    hop_index: int
    lat: float
    lon: float
    city: Optional[str]
    country: Optional[str]


class GeoPreviewResponse(BaseModel):
    sender_domain: Optional[str]
    hops: List[Dict[str, Any]]
    path: List[PathPoint]
    unresolved_hop_count: int
    db_path: str = Field(description="Absolute path to the MaxMind DB that was used")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "module": "Geo Preview (dev harness)",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    """
    Quick liveness + DB-presence check.
    Returns 503 if the MaxMind DB is missing so the React dev server can show
    a clear setup banner instead of a cryptic 500 on the first POST.
    """
    db_path = os.environ.get(
        "GEOIP_DB_PATH",
        os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb"),
    )
    db_present = os.path.exists(db_path)
    payload = {
        "status": "ok" if db_present else "degraded",
        "geoip_db": db_path,
        "geoip_db_present": db_present,
    }
    if not db_present:
        payload["setup_hint"] = (
            "Download GeoLite2-City.mmdb from https://www.maxmind.com/en/geolite2/signup "
            f"and place it at {db_path}, or set the GEOIP_DB_PATH env var."
        )
        # Return 503 so the frontend health-check can surface a clear message
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=payload)
    return payload


@app.post("/geo-preview", response_model=GeoPreviewResponse)
def geo_preview(body: GeoPreviewRequest):
    """
    Enrich a raw hops list with geolocation and return the map payload.

    - Accepts Tejas's full /analyze output pasted directly (extra keys ignored).
    - Returns the same shape as build_map_payload() in geo_lookup.py.
    - Returns HTTP 503 with a setup message if the MaxMind DB is missing.
    - Returns HTTP 422 automatically for malformed request bodies (Pydantic).
    """
    # Convert Pydantic models back to plain dicts so geo_lookup.py is happy
    tejas_output = {
        "sender_domain": body.sender_domain,
        "hops": [h.model_dump() for h in body.hops],
    }

    try:
        payload = build_map_payload(tejas_output)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "GeoIP database not found",
                "message": str(exc),
                "fix": (
                    "Download GeoLite2-City.mmdb from MaxMind "
                    "(https://www.maxmind.com/en/geolite2/signup) "
                    "and place it next to geo_lookup.py, "
                    "or set the GEOIP_DB_PATH environment variable."
                ),
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": "Geo enrichment failed", "message": str(exc)},
        ) from exc

    db_path = os.environ.get(
        "GEOIP_DB_PATH",
        os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb"),
    )
    return {**payload, "db_path": db_path}


# ---------------------------------------------------------------------------
# Built-in sample data endpoint — handy for rapid UI prototyping
# ---------------------------------------------------------------------------

# A small set of real public IPs that MaxMind resolves to different countries.
# Use GET /geo-preview/sample to get a ready-made payload without crafting JSON.
_SAMPLE_HOPS = [
    {
        # Hop 0 — no from_ip (typical for the first Received header).
        # Correctly recorded as unresolved; demonstrates expected behaviour.
        "hop_index": 0,
        "from_host": None,
        "from_ip":   None,
        "by_host":   "smtpstore.strencom.net (Postfix)",
        "timestamp": "2002-10-07T08:35:44+00:00",
        "protocol":  "ESMTP",
    },
    {
        # Hop 1 — enterprise.wasptech.com → Dublin, Ireland (53.39, -6.24)
        # Confirmed resolves in GeoLite2-City.
        "hop_index": 1,
        "from_host": "enterprise.wasptech.com",
        "from_ip":   "217.75.2.106",
        "by_host":   "smtpstore.strencom.net (Postfix)",
        "timestamp": "2002-10-07T08:35:44+00:00",
        "protocol":  "ESMTP",
    },
    {
        # Hop 2 — smtpstore.strencom.net → Dublin, Ireland (53.39, -6.24)
        # Same city as hop 1 — demonstrates stacked-marker behaviour.
        "hop_index": 2,
        "from_host": "smtpstore.strencom.net",
        "from_ip":   "217.75.0.66",
        "by_host":   "lugh.tuatha.org (Postfix)",
        "timestamp": "2002-10-07T08:25:04+00:00",
        "protocol":  "ESMTP",
    },
    {
        # Hop 3 — loopback (127.0.0.1) — correctly unresolved; demonstrates
        # that internal relay hops produce geo: null and are excluded from path.
        "hop_index": 3,
        "from_host": "lugh.tuatha.org",
        "from_ip":   "127.0.0.1",
        "by_host":   "lugh.tuatha.org (Postfix)",
        "timestamp": "2002-10-07T08:26:09+00:00",
        "protocol":  "ESMTP",
    },
    {
        # Hop 4 — dogma.slashnull.org → Ireland (country-level only, city: null)
        # Demonstrates that city can be null even when a hop is in path[].
        "hop_index": 4,
        "from_host": "lugh.tuatha.org",
        "from_ip":   "194.125.145.45",
        "by_host":   "dogma.slashnull.org (8.11.6/8.11.6)",
        "timestamp": "2002-10-07T08:25:26+00:00",
        "protocol":  "ESMTP",
    },
    {
        # Hop 5 — final delivery via loopback — unresolved.
        "hop_index": 5,
        "from_host": "localhost",
        "from_ip":   "127.0.0.1",
        "by_host":   "spamassassin.taint.org (Postfix)",
        "timestamp": "2002-10-07T11:04:48+00:00",
        "protocol":  "ESMTP",
    },
]


@app.get("/geo-preview/sample", response_model=GeoPreviewResponse)
def geo_preview_sample():
    """
    Returns a pre-built map payload using a hardcoded set of sample hops.
    Useful for getting the React component rendering immediately without
    crafting your own JSON.
    """
    tejas_output = {
        "sender_domain": "wasptech.com",
        "hops": _SAMPLE_HOPS,
    }
    try:
        payload = build_map_payload(tejas_output)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    db_path = os.environ.get(
        "GEOIP_DB_PATH",
        os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb"),
    )
    return {**payload, "db_path": db_path}
