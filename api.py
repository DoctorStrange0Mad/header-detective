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
from main import process_email

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

@app.get("/health")
def health():
    return {"status": "ok"}
