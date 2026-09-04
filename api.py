"""
FastAPI endpoint wrapper for Header Detective.
Sagar can call POST /analyze with the .eml file and get back the JSON.

Run with:
    pip install fastapi uvicorn python-multipart
    uvicorn api:app --reload --port 8001
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
import json
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from main import process_email
from language_detector import analyze_eml
from scorecard_builder import ScorecardBuilder


def extract_artifacts(filepath: str) -> dict:
    """Return display-safe URL and attachment metadata from an uploaded email."""
    with open(filepath, "rb") as stream:
        message = BytesParser(policy=policy.default).parse(stream)

    text_parts = []
    attachments = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "name": filename or "Unnamed attachment",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
            })
        elif part.get_content_type() in ("text/plain", "text/html"):
            try:
                text_parts.append(part.get_content())
            except Exception:
                pass

    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    seen = set()
    urls = []
    for url in url_pattern.findall("\n".join(str(text) for text in text_parts)):
        clean_url = url.rstrip(".,;:)")
        if clean_url in seen:
            continue
        seen.add(clean_url)
        urls.append({"url": clean_url, "domain": urlparse(clean_url).hostname})

    return {"urls": urls, "attachments": attachments}

app = FastAPI(
    title="Header Detective API",
    description="Parse .eml files and verify SPF/DKIM/DMARC. Output: hop list + auth results.",
    version="1.0.0"
)

# Allow React frontend (Sagar's dashboard) to call this
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"module": "Header Detective", "status": "running", "version": "1.0.0"}

@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    """
    Upload a .eml file and get back the full analysis JSON.

    Returns:
        file_hash_sha256: SHA-256 of the raw file
        hops: list of relay hops (IP, host, timestamp, protocol)
        auth: SPF / DKIM / DMARC results
        sender_domain: extracted From domain
        warnings: list of any parse issues (never crashes)
    """
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    # Write upload to a temp file so process_email can read it
    try:
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name

        result = process_email(tmp_path)
        return result

    except Exception as e:
        # Even on total failure, return valid schema
        return {
            "file_hash_sha256": "0" * 64,
            "hops": [],
            "auth": {
                "spf":   {"result": "error", "domain": None, "details": str(e)},
                "dkim":  {"result": "error", "selector": None, "domain": None},
                "dmarc": {"result": "none", "policy": None, "alignment": {"spf": False, "dkim": False}}
            },
            "sender_domain": None,
            "warnings": [f"API-level failure: {str(e)}"]
        }
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except:
            pass

@app.post("/analyze-language")
async def analyze_language(file: UploadFile = File(...)):
    """Analyze email language without changing the existing /analyze contract."""
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        return analyze_eml(tmp_path)
    except Exception as exc:
        # Do not expose uploaded email contents in errors or logs.
        return {
            "language_analysis": {
                "model": {"name": "dima806/phishing-email-detection", "label": None, "phishing_probability": None, "score": None, "available": False},
                "rule_score": 0.0, "language_threat_score": 0.0, "classification": "low_risk",
                "indicators": [], "entities": {"persons": [], "organizations": [], "money": [], "dates": [], "locations": []},
                "summary": [], "warnings": [f"Language upload/parser failure: {type(exc).__name__}"],
            }
        }
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

@app.post("/analyze-complete")
async def analyze_complete(file: UploadFile = File(...)):
    """Run the complete analysis once and return the single dashboard contract.

    This endpoint is the canonical source for the UI: authentication, language,
    optional geo enrichment, and the scorecard are calculated from the same
    uploaded file in one request.  The frontend must not recalculate scores.
    """
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        base = process_email(tmp_path)
        language = analyze_eml(tmp_path)
        artifacts = extract_artifacts(tmp_path)
        geo_payload = None
        try:
            # Kept optional because the GeoLite DB may not be installed locally.
            from geo_lookup import build_map_payload
            geo_payload = build_map_payload(base)
        except Exception as exc:
            base["warnings"].append(f"Geo enrichment unavailable: {type(exc).__name__}")

        scored = ScorecardBuilder().build(
            base,
            geo_payload=geo_payload,
            language_output=language,
        )
        return {
            **base,
            **language,
            **scored,
            "artifacts": artifacts,
            **({"map": geo_payload} if geo_payload else {}),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Complete analysis failed: {type(exc).__name__}") from exc
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

@app.get("/health")
def health():
    return {"status": "ok"}
