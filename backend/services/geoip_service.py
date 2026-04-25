"""
GeoIP lookup helpers with safe fallbacks.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import json
from urllib.error import URLError, HTTPError
from urllib.request import urlopen


@dataclass
class GeoLookupResult:
    city: str | None
    country: str | None
    lat: float | None
    lng: float | None
    provider: str
    is_precise: bool


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = ip_address(value.strip())
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_reserved
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
    )


def lookup_public_ip_geo(ip_value: str | None, timeout_seconds: float = 2.5) -> GeoLookupResult | None:
    """
    Resolve geolocation for a public IP.
    Returns None when IP is private/invalid or provider fails.
    """
    if not _is_public_ip(ip_value):
        return None

    endpoint = f"http://ip-api.com/json/{ip_value}?fields=status,country,city,lat,lon,query"
    try:
        with urlopen(endpoint, timeout=timeout_seconds) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError, OSError, ValueError):
        return None

    if payload.get("status") != "success":
        return None

    lat = payload.get("lat")
    lon = payload.get("lon")
    city = payload.get("city")
    country = payload.get("country")
    if lat is None or lon is None or not city or not country:
        return None

    return GeoLookupResult(
        city=str(city),
        country=str(country),
        lat=float(lat),
        lng=float(lon),
        provider="ip-api",
        is_precise=True,
    )
