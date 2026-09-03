# Header Detective

Parses `.eml` email files for SPF/DKIM/DMARC results and relay hop info,
and plots the relay path on a world map (Geo Visualizer module).

---

## Team Modules

| Member | Module | Entry point |
|---|---|---|
| Tejas | Relay Tracing + Auth Checks | `main.py` / `api.py` |
| Jayshree | Geo Visualizer (Map Builder) | `geo_lookup.py` / `geo_preview.py` |
| Ashith | Language Detective (NLP) | `language_detector/detector.py` / `api.py` (`POST /analyze-language`) |
| Sahishnu | Link/Attachment Scanner + Campaign Graph | — |
| Pushkar | Scorecard + Report Generator | — |
| Sagar | Dashboard Integrator | — |

---

## 1. Python Setup

**Python 3.13 required.**

Install all backend dependencies:

```bash
pip install mailparser dnspython dkimpy checkdmarc python-dateutil fastapi uvicorn python-multipart geoip2
```

Or use the requirements file (after adding `geoip2`):

```bash
pip install -r requirements.txt
pip install geoip2
```

### Language Detective (Member 3)

`POST /analyze-language` accepts an `.eml` upload like `/analyze`, but returns
only the isolated language-analysis contract and does not change Header
Detective's existing response. Install the added dependencies and spaCy model:

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

The first local inference downloads/caches
`dima806/phishing-email-detection`; email content is never sent to an external
inference API. If ML or spaCy is unavailable, the API returns rule-based
evidence with a warning. Run tests with:

```bash
python -m unittest language_detector.tests.test_language_detector
```

Run the service and open the interactive API page:

```bash
uvicorn api:app --reload --port 8001
```

Open `http://127.0.0.1:8001/docs`, select `POST /analyze-language`, click
**Try it out**, upload an `.eml` file, then click **Execute**.

The response contains `language_analysis.model.phishing_probability`,
`rule_score`, `language_threat_score`, matched `indicators`, spaCy `entities`,
and `warnings`. A model-only medium-risk result with no indicators is an
uncertain signal requiring review; it does not prove the email is phishing.
This module is one input to the final multi-signal score owned by Members 5/6.

---

## 2. GeoLite2 Database (required for Geo Visualizer)

The map module uses MaxMind's **GeoLite2-City** database for offline IP geolocation.
The `.mmdb` file is **not in the repo** (MaxMind license prohibits redistribution).
Every teammate who runs the backend needs to download it once — it takes 2 minutes.

### Step-by-step download

**Step 1 — Create a free MaxMind account**

👉 [https://www.maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)

Use any email. No credit card required.

**Step 2 — Go to your account downloads page**

After signing in, go to:

👉 [https://www.maxmind.com/en/accounts/current/geoip/downloads](https://www.maxmind.com/en/accounts/current/geoip/downloads)

**Step 3 — Download GeoLite2-City**

Find **GeoLite2-City** in the list → click **Download GZIP** (the `.mmdb` binary edition, NOT the CSV).

Direct permalink (requires being signed in):

👉 [https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz](https://www.maxmind.com/en/accounts/current/geoip/downloads)

**Step 4 — Extract and place the file**

Extract the downloaded `.tar.gz`. Inside you'll find `GeoLite2-City.mmdb`.

Place it here (next to `geo_lookup.py`):

```
header-detective/
└── GeoLite2-City.mmdb   ← put it here
```

Or set an environment variable to point anywhere else:

```bash
# Windows PowerShell
$env:GEOIP_DB_PATH = "C:\path\to\GeoLite2-City.mmdb"

# macOS / Linux
export GEOIP_DB_PATH="/path/to/GeoLite2-City.mmdb"
```

**Step 5 — Verify it works**

```bash
python -c "from geo_lookup import lookup_ip; import json; print(json.dumps(lookup_ip('8.8.8.8'), indent=2))"
```

Expected output (approximate):
```json
{
  "lat": 37.751,
  "lon": -97.822,
  "city": null,
  "country": "United States",
  "country_code": "US"
}
```

If you see this, the database is working. If you get a `FileNotFoundError`, the `.mmdb` is not in the right place.

---

## 3. Running the backends

### Tejas's main API (email analysis)

```bash
uvicorn api:app --reload --port 8001
```

Docs: [http://localhost:8001/docs](http://localhost:8001/docs)

### Jayshree's Geo Preview API (map dev harness)

```bash
uvicorn geo_preview:app --reload --port 8002
```

Docs: [http://localhost:8002/docs](http://localhost:8002/docs)

Sample data (no upload needed): [http://localhost:8002/geo-preview/sample](http://localhost:8002/geo-preview/sample)

Health check (confirms DB found): [http://localhost:8002/health](http://localhost:8002/health)

---

## 4. Frontend (Geo Visualizer dev preview)

To visually verify the map component in a browser:

```bash
# Terminal 1 — start the geo backend
uvicorn geo_preview:app --reload --port 8002

# Terminal 2 — start the Vite dev server (from the frontend/ folder)
cd frontend
npm install
npm run dev
```

Open: [http://localhost:5173](http://localhost:5173)

To run the Jest tests:

```bash
cd frontend
npm test
```

---

## 5. Tools & Dependencies

### Python

| Package | Purpose |
|---|---|
| [mailparser](https://pypi.org/project/mail-parser/) | `.eml` parsing |
| [dnspython](https://pypi.org/project/dnspython/) | DNS resolution |
| [dkimpy](https://pypi.org/project/dkimpy/) | DKIM verification |
| [checkdmarc](https://pypi.org/project/checkdmarc/) | DMARC policy check |
| [python-dateutil](https://pypi.org/project/python-dateutil/) | Timestamp parsing |
| [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/) | REST API |
| [python-multipart](https://pypi.org/project/python-multipart/) | File uploads |
| [geoip2](https://pypi.org/project/geoip2/) | MaxMind DB reader (Geo Visualizer) |
| [transformers](https://huggingface.co/docs/transformers/) + [PyTorch](https://pytorch.org/) | Local phishing classifier (`dima806/phishing-email-detection`) |
| [spaCy](https://spacy.io/) + `en_core_web_sm` | Local NER for language-analysis context |

### Frontend (Geo Visualizer)

| Package | Purpose |
|---|---|
| [react-leaflet](https://react-leaflet.js.org/) | Interactive map |
| [leaflet](https://leafletjs.com/) | Map engine |
| [vite](https://vitejs.dev/) | Dev server |
| [jest](https://jestjs.io/) + [@testing-library/react](https://testing-library.com/docs/react-testing-library/intro/) | Unit tests |

---

## 6. Output contract

See [`OUTPUT_CONTRACT.md`](./OUTPUT_CONTRACT.md) for the exact JSON shape that
the Geo Visualizer hands off downstream (Pushkar / Sagar).
