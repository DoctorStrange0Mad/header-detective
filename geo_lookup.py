"""
Header Detective - Geo Visualizer module (Jayshree, Member 2)

Takes Tejas's hop JSON (from main.py / api.py's /analyze output) and
enriches each hop with lat/lon/city/country using a local MaxMind
GeoLite2-City database. Fully offline after the .mmdb is downloaded --
no API calls, no rate limits, safe for a live demo.

Setup:
    pip install geoip2
    1. Make a free account at https://www.maxmind.com/en/geolite2/signup
    2. Download "GeoLite2-City" (the .mmdb binary, not the CSV version)
    3. Put GeoLite2-City.mmdb in this same folder (or set GEOIP_DB_PATH)

Usage:
    from geo_lookup import enrich_hops_with_geo

    tejas_output = process_email(filepath)   # from Tejas's main.py
    geo_hops = enrich_hops_with_geo(tejas_output["hops"])
"""

import os
import ipaddress
import geoip2.database
import geoip2.errors

GEOIP_DB_PATH = os.environ.get(
    "GEOIP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
)

# Module-level singleton — opened once, reused across calls.
# NOTE: if you change GEOIP_DB_PATH at runtime after the first lookup,
# the old reader stays open. Restart the process or call _reset_reader()
# (test helper below) to pick up the new path.
_reader = None


def _get_reader():
    """Lazy-load the DB reader once, reuse across calls (opening is expensive)."""
    global _reader
    if _reader is None:
        if not os.path.exists(GEOIP_DB_PATH):
            raise FileNotFoundError(
                f"\n\n  [Header Detective] GeoLite2-City.mmdb not found.\n"
                f"  Expected path: {GEOIP_DB_PATH}\n\n"
                "  Fix:\n"
                "    1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup\n"
                "    2. Download GeoLite2-City.mmdb (the binary .mmdb, NOT the CSV)\n"
                f"    3. Place it at the path above, OR set the GEOIP_DB_PATH env var.\n"
            )
        _reader = geoip2.database.Reader(GEOIP_DB_PATH)
    return _reader


def _reset_reader():
    """Close and reset the singleton reader. Used in tests / when swapping DB files."""
    global _reader
    if _reader is not None:
        _reader.close()
        _reader = None


def _normalize_ip(ip_str):
    """
    Parse ip_str and return a normalised ip_address object, or None on failure.

    Handles:
    - Plain IPv4 and IPv6 strings
    - IPv6-mapped IPv4 addresses (::ffff:192.168.1.1) — unwrapped to their
      IPv4 form so private-range checks work correctly (::ffff:10.0.0.1 IS
      private even though the raw IPv6 object reports is_private=False on
      some Python versions).
    - Bracketed IPv6 literals like [2001:db8::1] — brackets stripped first.
    """
    if not ip_str or not isinstance(ip_str, str):
        return None

    # Strip brackets that appear in some Received headers: [2001:db8::1]
    ip_str = ip_str.strip().strip("[]")

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    # Unwrap IPv6-mapped IPv4 (::ffff:192.168.x.x) so private checks apply
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    return ip_obj


def is_geolocatable(ip_str):
    """
    Return True only for IPs that are worth sending to the MaxMind DB.

    Filters out:
    - None / empty / non-string values
    - Malformed IP literals
    - Private, loopback, link-local, reserved, multicast addresses
    - IPv6-mapped private IPv4 addresses (e.g. ::ffff:10.0.0.1)
    """
    ip_obj = _normalize_ip(ip_str)
    if ip_obj is None:
        return False
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    ):
        return False
    return True


def lookup_ip(ip_str):
    """
    Return {lat, lon, city, country, country_code} or None if it can't be located.

    Returns None (never raises) for:
    - Non-geolocatable IPs (private, loopback, etc.)
    - IPs not present in the MaxMind DB
    - Any unexpected geoip2 error
    """
    if not is_geolocatable(ip_str):
        return None

    # Normalise again so the reader gets a clean string (no brackets)
    ip_obj = _normalize_ip(ip_str)
    clean_ip = str(ip_obj)

    reader = _get_reader()
    try:
        response = reader.city(clean_ip)
        lat = response.location.latitude
        lon = response.location.longitude
        # MaxMind returns None for lat/lon when the city record has no coordinates
        if lat is None or lon is None:
            return None
        return {
            "lat": lat,
            "lon": lon,
            "city": response.city.name,           # may be None — that's fine
            "country": response.country.name,      # may be None
            "country_code": response.country.iso_code,  # may be None
        }
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception:
        # Catch-all so a corrupt DB record never crashes the whole analysis
        return None


def enrich_hops_with_geo(hops):
    """
    Takes Tejas's `hops` list (list of dicts with hop_index/from_host/from_ip/
    by_host/timestamp/protocol) and returns a NEW list where each hop has an
    added "geo" key:

        "geo": {"lat": .., "lon": .., "city": .., "country": .., "country_code": ..}
        or
        "geo": None   <- when it couldn't be located (private IP, missing IP,
                         unknown IP, or hop 0 which typically has no from_ip)

    Tejas's schema has exactly one IP field per hop: from_ip.
    by_host is a hostname string, not an IP — there is no by_ip key.
    When from_ip is absent (common for hop 0), that hop is correctly recorded
    as unresolved; this is expected behaviour, not a bug.

    Hops are returned in the same hop_index order Tejas gave them in, so the
    frontend can draw the dotted line in the correct hop sequence.
    """
    enriched = []
    for hop in hops:
        geo = lookup_ip(hop.get("from_ip"))
        enriched.append({**hop, "geo": geo})
    return enriched


def build_map_payload(tejas_output):
    """
    Convenience wrapper: takes Tejas's FULL output dict (not just hops) and
    returns the payload shape the frontend map component expects.

    This is what you actually hand off to Sagar for the dashboard.
    """
    geo_hops = enrich_hops_with_geo(tejas_output.get("hops", []))
    locatable = [h for h in geo_hops if h["geo"] is not None]

    return {
        "sender_domain": tejas_output.get("sender_domain"),
        "hops": geo_hops,
        "path": [
            {
                "hop_index": h["hop_index"],
                "lat": h["geo"]["lat"],
                "lon": h["geo"]["lon"],
                "city": h["geo"]["city"],
                "country": h["geo"]["country"],
            }
            for h in locatable
        ],
        "unresolved_hop_count": len(geo_hops) - len(locatable),
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python geo_lookup.py <tejas_output.json>")
        print("  (run Tejas's main.py on an .eml first to produce this file)")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        tejas_output = json.load(f)

    payload = build_map_payload(tejas_output)
    print(json.dumps(payload, indent=2))
