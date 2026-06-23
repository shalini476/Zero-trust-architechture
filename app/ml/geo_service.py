"""
Zero Trust Security Platform — IP Geolocation & VPN Detection Service
Zerofox

Provides real geolocation data (city, region, country, timezone, ISP, lat/lon)
and VPN/proxy/hosting detection using free public IP intelligence APIs.

Primary source  : ip-api.com  (free, no key, 45 req/min)
Secondary source: ipinfo.io   (free tier, 50k req/month)
Fallback        : intelligent defaults (never crashes the login flow)

Results are cached in-process (1-hour TTL) so repeated logins from the same
IP do not consume API quota. Each unique IP is looked up at most once per hour.
"""

import logging
import time
import math
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process cache:  {ip_str: (timestamp_float, result_dict)}
# ---------------------------------------------------------------------------
_GEO_CACHE: dict = {}
_CACHE_TTL = 3600  # seconds (1 hour)

# IPs that are always local — never hit external API
_LOCAL_IPS = {'127.0.0.1', '::1', 'localhost', '0.0.0.0'}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip: str) -> dict:
    """
    Return geolocation and VPN/proxy intelligence for *ip*.

    Always returns a dict with these guaranteed keys (never raises):
        ip          str   — the queried IP
        city        str   — e.g. "Chennai"
        region      str   — e.g. "Tamil Nadu"
        country     str   — e.g. "India"
        country_code str  — e.g. "IN"
        timezone    str   — e.g. "Asia/Kolkata"
        isp         str   — e.g. "Jio Fiber"
        org         str   — autonomous-system org name
        latitude    float — decimal degrees (None if unavailable)
        longitude   float — decimal degrees (None if unavailable)
        is_vpn      bool  — True if VPN/proxy/Tor detected
        is_proxy    bool  — True if proxy detected
        is_hosting  bool  — True if datacenter/cloud IP
        location_str str  — human-readable "City, Region, CC"
        source      str   — "ip-api" | "ipinfo" | "local" | "fallback"
    """
    # Localhost shortcut
    if not ip or ip in _LOCAL_IPS or ip.startswith('192.168.') or ip.startswith('10.') or _is_rfc1918(ip):
        return _local_result(ip)

    # Cache hit?
    cached = _GEO_CACHE.get(ip)
    if cached:
        ts, data = cached
        if time.time() - ts < _CACHE_TTL:
            return data

    # Try primary → secondary → fallback
    result = _query_ipapi(ip) or _query_ipinfo(ip) or _fallback_result(ip)

    _GEO_CACHE[ip] = (time.time(), result)
    return result


def haversine_km(lat1: Optional[float], lon1: Optional[float],
                 lat2: Optional[float], lon2: Optional[float]) -> Optional[float]:
    """
    Calculate great-circle distance in kilometres between two coordinates.
    Returns None if any coordinate is missing.
    """
    if None in (lat1, lon1, lat2, lon2):
        return None
    R = 6371.0  # Earth radius km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_rfc1918(ip: str) -> bool:
    """Return True for private/link-local IPv4 ranges."""
    try:
        parts = list(map(int, ip.split('.')))
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168) or
            (parts[0] == 169 and parts[1] == 254)   # link-local
        )
    except Exception:
        return False


def _local_result(ip: str) -> dict:
    return {
        'ip': ip or '127.0.0.1',
        'city': 'Local Network',
        'region': '',
        'country': 'Development',
        'country_code': 'LO',
        'timezone': 'UTC',
        'isp': 'Localhost',
        'org': 'Localhost',
        'latitude': None,
        'longitude': None,
        'is_vpn': False,
        'is_proxy': False,
        'is_hosting': False,
        'location_str': 'Local Network (Development)',
        'source': 'local',
    }


def _fallback_result(ip: str) -> dict:
    """Intelligent fallback when all APIs are unavailable."""
    return {
        'ip': ip,
        'city': 'Unknown',
        'region': 'Unknown',
        'country': 'Unknown',
        'country_code': 'XX',
        'timezone': 'UTC',
        'isp': f'Network ({ip})',
        'org': f'AS-UNKNOWN ({ip})',
        'latitude': None,
        'longitude': None,
        'is_vpn': False,
        'is_proxy': False,
        'is_hosting': False,
        'location_str': f'Unknown ({ip})',
        'source': 'fallback',
    }


def _query_ipapi(ip: str) -> Optional[dict]:
    """
    Query ip-api.com (free, no API key, 45 req/min).
    Fields requested: status, city, regionName, country, countryCode,
    timezone, isp, org, lat, lon, proxy, hosting, query
    """
    try:
        import requests
        fields = 'status,message,city,regionName,country,countryCode,timezone,isp,org,lat,lon,proxy,hosting,query'
        url = f'http://ip-api.com/json/{ip}?fields={fields}'
        resp = requests.get(url, timeout=4)
        data = resp.json()

        if data.get('status') != 'success':
            logger.warning('[GeoService] ip-api.com returned non-success for %s: %s', ip, data.get('message'))
            return None

        city      = data.get('city', 'Unknown') or 'Unknown'
        region    = data.get('regionName', '') or ''
        country   = data.get('country', 'Unknown') or 'Unknown'
        cc        = data.get('countryCode', 'XX') or 'XX'
        tz        = data.get('timezone', 'UTC') or 'UTC'
        isp       = data.get('isp', 'Unknown ISP') or 'Unknown ISP'
        org       = data.get('org', isp) or isp
        lat       = data.get('lat')
        lon       = data.get('lon')
        is_proxy  = bool(data.get('proxy', False))
        is_host   = bool(data.get('hosting', False))
        is_vpn    = is_proxy or is_host

        # Build location string
        parts = [p for p in [city, region, cc] if p]
        loc_str = ', '.join(parts) if parts else f'Unknown ({ip})'

        return {
            'ip': ip,
            'city': city,
            'region': region,
            'country': country,
            'country_code': cc,
            'timezone': tz,
            'isp': isp,
            'org': org,
            'latitude': float(lat) if lat is not None else None,
            'longitude': float(lon) if lon is not None else None,
            'is_vpn': is_vpn,
            'is_proxy': is_proxy,
            'is_hosting': is_host,
            'location_str': loc_str,
            'source': 'ip-api',
        }

    except Exception as exc:
        logger.warning('[GeoService] ip-api.com query failed for %s: %s', ip, exc)
        return None


def _query_ipinfo(ip: str) -> Optional[dict]:
    """
    Secondary fallback: ipinfo.io (free tier, 50k/month, no key required).
    """
    try:
        import requests
        url = f'https://ipinfo.io/{ip}/json'
        resp = requests.get(url, timeout=4)
        data = resp.json()

        if 'error' in data:
            return None

        city    = data.get('city', 'Unknown') or 'Unknown'
        region  = data.get('region', '') or ''
        country = data.get('country', 'XX') or 'XX'
        tz      = data.get('timezone', 'UTC') or 'UTC'
        org     = data.get('org', 'Unknown ISP') or 'Unknown ISP'
        # ipinfo.io org is like "AS12345 Jio Fiber" — strip the ASN prefix
        isp     = org.split(' ', 1)[1] if ' ' in org else org

        # ipinfo.io free tier doesn't provide proxy detection
        is_vpn    = False
        is_proxy  = False
        is_host   = False

        # lat/lon from "loc": "12.9762,77.6033"
        lat, lon = None, None
        loc_raw = data.get('loc', '')
        if loc_raw and ',' in loc_raw:
            try:
                lat, lon = map(float, loc_raw.split(','))
            except ValueError:
                pass

        parts = [p for p in [city, region, country] if p]
        loc_str = ', '.join(parts) if parts else f'Unknown ({ip})'

        return {
            'ip': ip,
            'city': city,
            'region': region,
            'country': country,
            'country_code': country,
            'timezone': tz,
            'isp': isp,
            'org': org,
            'latitude': lat,
            'longitude': lon,
            'is_vpn': is_vpn,
            'is_proxy': is_proxy,
            'is_hosting': is_host,
            'location_str': loc_str,
            'source': 'ipinfo',
        }

    except Exception as exc:
        logger.warning('[GeoService] ipinfo.io query failed for %s: %s', ip, exc)
        return None
