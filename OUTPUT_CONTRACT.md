# Geo Visualizer — Output Contract

**Module:** Geo Visualizer (Jayshree, Member 2)  
**Produced by:** `build_map_payload()` in `geo_lookup.py`  
**Input:** Tejas's (Member 1) full `/analyze` output dict  
**Verified against:** `ham_easy_00103.23abe7cbe651a970e2dc6cc531c268a3.eml` on 2026-09-03

---

## Exact payload shape (as produced by a real run)

```json
{
  "sender_domain": "wasptech.com",
  "hops": [
    {
      "hop_index": 0,
      "from_host": "enterprise.wasptech.com",
      "from_ip": "217.75.2.106",
      "by_host": "smtpstore.strencom.net (Postfix)",
      "timestamp": "2002-10-07T08:35:44+00:00",
      "protocol": "ESMTP",
      "geo": {
        "lat": 53.3857,
        "lon": -6.2403,
        "city": "Dublin",
        "country": "Ireland",
        "country_code": "IE"
      }
    },
    {
      "hop_index": 1,
      "from_host": "smtpstore.strencom.net",
      "from_ip": "217.75.0.66",
      "by_host": "lugh.tuatha.org (Postfix)",
      "timestamp": "2002-10-07T08:25:04+00:00",
      "protocol": "ESMTP",
      "geo": {
        "lat": 53.3857,
        "lon": -6.2403,
        "city": "Dublin",
        "country": "Ireland",
        "country_code": "IE"
      }
    },
    {
      "hop_index": 2,
      "from_host": "lugh.tuatha.org",
      "from_ip": "127.0.0.1",
      "by_host": "lugh.tuatha.org (Postfix)",
      "timestamp": "2002-10-07T08:26:09+00:00",
      "protocol": "ESMTP",
      "geo": null
    },
    {
      "hop_index": 3,
      "from_host": "lugh.tuatha.org",
      "from_ip": "194.125.145.45",
      "by_host": "dogma.slashnull.org (8.11.6/8.11.6)",
      "timestamp": "2002-10-07T08:25:26+00:00",
      "protocol": "ESMTP",
      "geo": {
        "lat": 53.3472,
        "lon": -6.2439,
        "city": null,
        "country": "Ireland",
        "country_code": "IE"
      }
    },
    {
      "hop_index": 4,
      "from_host": "jalapeno",
      "from_ip": "127.0.0.1",
      "by_host": "localhost",
      "timestamp": "2002-10-07T11:04:48+00:00",
      "protocol": "IMAP (fetchmail-5.9.0)",
      "geo": null
    },
    {
      "hop_index": 5,
      "from_host": "localhost",
      "from_ip": "127.0.0.1",
      "by_host": "spamassassin.taint.org (Postfix)",
      "timestamp": "2002-10-07T11:04:48+00:00",
      "protocol": "ESMTP",
      "geo": null
    }
  ],
  "path": [
    {
      "hop_index": 0,
      "lat": 53.3857,
      "lon": -6.2403,
      "city": "Dublin",
      "country": "Ireland"
    },
    {
      "hop_index": 1,
      "lat": 53.3857,
      "lon": -6.2403,
      "city": "Dublin",
      "country": "Ireland"
    },
    {
      "hop_index": 3,
      "lat": 53.3472,
      "lon": -6.2439,
      "city": null,
      "country": "Ireland"
    }
  ],
  "unresolved_hop_count": 3
}
```

---

## Field-by-field description

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `sender_domain` | string \| null | Domain extracted from the email's From header by Tejas's `main.py`. Null if extraction failed. |
| `hops` | array | Every relay hop from Tejas's `hop_parser.py`, in original `hop_index` order, each extended with a `geo` key added by this module. |
| `path` | array | Filtered subset of `hops` — only the hops where geolocation succeeded (i.e. `geo` is not null). These are what the map component plots. `hop_index` values are non-contiguous when internal hops are filtered out (e.g. 0, 1, 3 in the example above — hop 2 was loopback). |
| `unresolved_hop_count` | integer | Number of hops where `geo` is null. In the example: hops 2, 4, 5 all had `from_ip = 127.0.0.1` (loopback). See `is_geolocatable()` in `geo_lookup.py` for the full filter list. |

### Fields on each object in `hops[]`

These first five fields come directly from Tejas's `hop_parser.py` and are not modified:

| Field | Type | Description |
|---|---|---|
| `hop_index` | integer | Zero-based position of this hop in the Received header chain, outermost first. |
| `from_host` | string \| null | Hostname of the sending server, parsed from the `from` clause of the Received header. May include extra text e.g. `"smtpstore.strencom.net (Postfix)"`. |
| `from_ip` | string \| null | IP address of the sending server, extracted from brackets in the `from` clause. The **only** IP field in Tejas's schema. Null when the header omits it. |
| `by_host` | string \| null | Hostname of the receiving server, from the `by` clause. This is always a hostname string — there is no `by_ip` field. |
| `timestamp` | string \| null | ISO-8601 UTC timestamp of when this hop received the message. |
| `protocol` | string \| null | Protocol string from the `with` clause, e.g. `"ESMTP"`, `"ESMTPS"`. |
| `geo` | object \| null | Added by this module. Null when `from_ip` is absent, private, loopback, link-local, reserved, or multicast, or when MaxMind has no record for the IP. See sub-fields below. |

### Sub-fields of `geo` (when not null)

| Field | Type | Description |
|---|---|---|
| `lat` | float | Latitude from MaxMind GeoLite2-City database. Never null when `geo` itself is not null (null lat/lon causes `geo` to be set to null). |
| `lon` | float | Longitude from MaxMind GeoLite2-City database. Same guarantee as `lat`. |
| `city` | string \| null | City name from MaxMind. Null for IPs that resolve only to country level (common for some ISP/datacenter ranges). |
| `country` | string \| null | Full country name from MaxMind, e.g. `"Ireland"`. |
| `country_code` | string \| null | ISO 3166-1 alpha-2 country code, e.g. `"IE"`. Present in `hops[].geo` but **not** copied into `path[]` entries (path only carries lat/lon/city/country). |

### Fields on each object in `path[]`

`path` entries are a projected subset of the `hops` entries where `geo != null`.
`country_code` is intentionally omitted from `path` — it stays in `hops[].geo` only.

| Field | Type | Description |
|---|---|---|
| `hop_index` | integer | Same `hop_index` as the source hop. Use this to correlate back to `hops[]` or to Tejas's original output. |
| `lat` | float | Copy of `hops[i].geo.lat`. |
| `lon` | float | Copy of `hops[i].geo.lon`. |
| `city` | string \| null | Copy of `hops[i].geo.city`. May be null even when the hop is in `path[]`. |
| `country` | string \| null | Copy of `hops[i].geo.country`. |

---

## Known behaviours to be aware of

- **Non-contiguous hop_index in `path[]`:** When internal/loopback hops are filtered out, the `hop_index` values in `path[]` will have gaps (e.g. 0, 1, 3). The map polyline connects them in `hop_index` order regardless. This is correct — it reflects that an intermediate relay was on an internal network.

- **Duplicate coordinates:** Two hops from the same datacenter/ISP will resolve to the same lat/lon. The map will stack two markers on the same point. The `HopMap.jsx` component currently does not deduplicate these — both markers render, the top one is clickable.

- **`city: null` in `path[]`:** A hop can appear in `path[]` (meaning it has coordinates) but still have `city: null` if MaxMind only has a country-level record for that IP range. The map popup will show only the country name in that case.

- **GeoLite2 accuracy:** This uses the free GeoLite2-City database, not the paid GeoIP2 City. Accuracy is lower for ISP/residential ranges. Coordinates are accurate to city/region level, not street level.

- **DB path:** Resolved at import time from the `GEOIP_DB_PATH` environment variable, defaulting to `GeoLite2-City.mmdb` in the same directory as `geo_lookup.py`. The file is opened once and the reader is reused across calls.

---

## TODO — confirm with Member 3 before integrating

> **These questions must be resolved directly with the downstream team member.
> Do not assume answers — the schema can be adjusted once confirmed.**

1. **`hops` array vs `path` array:** Do you need the full `hops` array (all 6 hops, with `geo: null` on unresolved ones), or only the filtered `path` array (just the 3 locatable hops)? The full `hops` array includes all original Tejas fields plus `geo`; `path` is coordinates-only.

2. **IP addresses in output:** The `path[]` entries do not include `from_ip`. If your module needs the IP address alongside the coordinates (e.g. for reverse-DNS enrichment, ASN lookup, or display), confirm and we will add `from_ip` to each `path[]` entry.

3. **`country_code`:** Currently present in `hops[].geo` but omitted from `path[]`. If you need ISO country codes in the path entries, confirm and we will add them.

4. **Timestamp in path:** `path[]` entries do not include `timestamp`. If you need the time each hop occurred alongside coordinates (e.g. for a time-ordered geo-timeline), confirm and we will add it.

5. **Payload delivery mechanism:** This module produces the payload via `build_map_payload()` in `geo_lookup.py`, and exposes it through the `/geo-preview` endpoint in `geo_preview.py` (dev, port 8002) and will be integrated into Tejas's `/analyze` endpoint as `/analyze-geo`. Confirm which of these you are consuming, or whether you want the Python function imported directly.
