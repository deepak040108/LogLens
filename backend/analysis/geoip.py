"""
analysis/geoip.py
 ------------------------------------------------------------------------
Real GeoIP resolution via MaxMind's free GeoLite2 databases:
  - GeoLite2-Country.mmdb  → country name + ISO code
  - GeoLite2-City.mmdb     → city, region, latitude, longitude
  - GeoLite2-ASN.mmdb      → autonomous system number + organization

If a database file isn't present, that lookup layer returns "unavailable"
— never fabricated. Every result carries `available: bool` so the
frontend can conditionally display data.

To enable:
  1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
  2. Download the .mmdb files
  3. Place them in backend/geoip/
  4. pip install geoip2 (already in requirements.txt)
 ------------------------------------------------------------------------
"""

import sys
import os
import ipaddress
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEOIP_DB_PATH, GEOIP_CITY_DB_PATH, GEOIP_ASN_DB_PATH  # noqa: E402

_country_reader = None
_city_reader = None
_asn_reader = None
_load_attempted = False
_load_errors = []


def _get_readers():
    global _country_reader, _city_reader, _asn_reader, _load_attempted, _load_errors
    if _load_attempted:
        return
    _load_attempted = True
    try:
        import geoip2.database

        if os.path.exists(GEOIP_DB_PATH):
            try:
                _country_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            except Exception as e:
                _load_errors.append(f"Country: {e}")
        else:
            _load_errors.append(f"Country DB not found at {GEOIP_DB_PATH}")

        if os.path.exists(GEOIP_CITY_DB_PATH):
            try:
                _city_reader = geoip2.database.Reader(GEOIP_CITY_DB_PATH)
            except Exception as e:
                _load_errors.append(f"City: {e}")
        else:
            _load_errors.append(f"City DB not found at {GEOIP_CITY_DB_PATH}")

        if os.path.exists(GEOIP_ASN_DB_PATH):
            try:
                _asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)
            except Exception as e:
                _load_errors.append(f"ASN: {e}")
        else:
            _load_errors.append(f"ASN DB not found at {GEOIP_ASN_DB_PATH}")

    except ImportError:
        _load_errors.append("geoip2 package not installed")
    except Exception as e:
        _load_errors.append(str(e))


def is_geoip_available() -> bool:
    _get_readers()
    return _country_reader is not None


def is_geoip_city_available() -> bool:
    _get_readers()
    return _city_reader is not None


def is_geoip_asn_available() -> bool:
    _get_readers()
    return _asn_reader is not None


def geoip_status_message() -> str:
    _get_readers()
    parts = []
    if _country_reader:
        parts.append("Country")
    if _city_reader:
        parts.append("City")
    if _asn_reader:
        parts.append("ASN")
    if parts:
        return f"Loaded: {', '.join(parts)}"
    return _load_errors[0] if _load_errors else "No GeoIP databases configured"


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return True


def resolve_country(ip: str) -> dict:
    """Returns {available, country, countryCode}."""
    if not ip or _is_private(ip):
        return {"available": False, "country": "Location unavailable", "countryCode": None}

    _get_readers()
    if _country_reader is None:
        return {"available": False, "country": "Location unavailable", "countryCode": None}

    try:
        resp = _country_reader.country(ip)
        name = resp.country.name
        code = resp.country.iso_code
        if not name or not code:
            return {"available": False, "country": "Location unavailable", "countryCode": None}
        return {"available": True, "country": name, "countryCode": code}
    except Exception:
        return {"available": False, "country": "Location unavailable", "countryCode": None}


def resolve_city(ip: str) -> dict:
    """Returns {available, city, region, latitude, longitude}."""
    if not ip or _is_private(ip):
        return {"available": False, "city": None, "region": None, "latitude": None, "longitude": None}

    _get_readers()
    if _city_reader is None:
        return {"available": False, "city": None, "region": None, "latitude": None, "longitude": None}

    try:
        resp = _city_reader.city(ip)
        city = resp.city.name
        region = resp.subdivisions.most_specific.name if resp.subdivisions else None
        lat = resp.location.latitude
        lon = resp.location.longitude
        if lat is not None and (isinstance(lat, float) and (math.isnan(lat) or math.isinf(lat))):
            lat = None
        if lon is not None and (isinstance(lon, float) and (math.isnan(lon) or math.isinf(lon))):
            lon = None
        return {
            "available": bool(city),
            "city": city,
            "region": region,
            "latitude": lat,
            "longitude": lon,
        }
    except Exception:
        return {"available": False, "city": None, "region": None, "latitude": None, "longitude": None}


def resolve_asn(ip: str) -> dict:
    """Returns {available, asn, organization}."""
    if not ip or _is_private(ip):
        return {"available": False, "asn": None, "organization": None}

    _get_readers()
    if _asn_reader is None:
        return {"available": False, "asn": None, "organization": None}

    try:
        resp = _asn_reader.asn(ip)
        asn_num = resp.autonomous_system_number
        if asn_num is not None and (isinstance(asn_num, float) and (math.isnan(asn_num) or math.isinf(asn_num))):
            asn_num = None
        return {
            "available": True,
            "asn": asn_num,
            "organization": resp.autonomous_system_organization,
        }
    except Exception:
        return {"available": False, "asn": None, "organization": None}


def resolve_full(ip: str) -> dict:
    """Combined lookup returning country, city, and ASN data."""
    country = resolve_country(ip)
    city = resolve_city(ip)
    asn = resolve_asn(ip)
    return {
        "country": country.get("country"),
        "countryCode": country.get("countryCode"),
        "city": city.get("city"),
        "region": city.get("region"),
        "latitude": city.get("latitude"),
        "longitude": city.get("longitude"),
        "asn": asn.get("asn"),
        "organization": asn.get("organization"),
        "geoAvailable": country.get("available") or city.get("available"),
    }
