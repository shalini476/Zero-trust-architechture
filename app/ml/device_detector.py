"""
Zero Trust Security Platform — Real-Time Device & Context Detector
Zerofox

Extracts real browser, OS, device type, and location information
from HTTP requests. Used across the platform to populate activity logs
with genuine telemetry instead of simulated data.
"""

import re
from flask import request


def parse_user_agent(ua_string: str) -> dict:
    """
    Parse a User-Agent string to extract browser name, version, OS, and device type.
    
    Returns:
        {
            'browser': str,       e.g. 'Chrome 125.0'
            'os': str,            e.g. 'Windows 11'
            'device_type': str,   e.g. 'Desktop', 'Mobile', 'Tablet'
            'raw': str            the original User-Agent string
        }
    """
    if not ua_string:
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device_type': 'Unknown',
            'raw': ''
        }

    browser = 'Unknown'
    os_name = 'Unknown'
    device_type = 'Desktop'

    # ── Detect Browser ─────────────────────────────────────────────
    # Order matters: check Edge/Opera/Brave before Chrome (they include "Chrome" in UA)
    if 'Edg/' in ua_string or 'Edge/' in ua_string:
        match = re.search(r'Edg[e]?/([\d.]+)', ua_string)
        version = match.group(1).split('.')[0] if match else ''
        browser = f'Edge {version}'.strip()
    elif 'OPR/' in ua_string or 'Opera/' in ua_string:
        match = re.search(r'OPR/([\d.]+)', ua_string)
        version = match.group(1).split('.')[0] if match else ''
        browser = f'Opera {version}'.strip()
    elif 'Brave' in ua_string:
        browser = 'Brave'
    elif 'Firefox/' in ua_string:
        match = re.search(r'Firefox/([\d.]+)', ua_string)
        version = match.group(1).split('.')[0] if match else ''
        browser = f'Firefox {version}'.strip()
    elif 'Safari/' in ua_string and 'Chrome/' not in ua_string:
        match = re.search(r'Version/([\d.]+)', ua_string)
        version = match.group(1).split('.')[0] if match else ''
        browser = f'Safari {version}'.strip()
    elif 'Chrome/' in ua_string:
        match = re.search(r'Chrome/([\d.]+)', ua_string)
        version = match.group(1).split('.')[0] if match else ''
        browser = f'Chrome {version}'.strip()

    # ── Detect OS ──────────────────────────────────────────────────
    if 'Windows NT 10.0' in ua_string:
        # Windows 11 also reports as NT 10.0 but with higher build numbers
        if 'Windows NT 10.0; Win64' in ua_string:
            # Check for Windows 11 build markers (build >= 22000)
            build_match = re.search(r'Windows NT 10\.0.*?(\d{5,})', ua_string)
            if build_match and int(build_match.group(1)) >= 22000:
                os_name = 'Windows 11'
            else:
                os_name = 'Windows 10'
        else:
            os_name = 'Windows 10'
    elif 'Windows NT 6.3' in ua_string:
        os_name = 'Windows 8.1'
    elif 'Windows NT 6.1' in ua_string:
        os_name = 'Windows 7'
    elif 'Mac OS X' in ua_string:
        match = re.search(r'Mac OS X ([\d_]+)', ua_string)
        version = match.group(1).replace('_', '.') if match else ''
        os_name = f'macOS {version}'.strip()
    elif 'Android' in ua_string:
        match = re.search(r'Android ([\d.]+)', ua_string)
        version = match.group(1) if match else ''
        os_name = f'Android {version}'.strip()
    elif 'iPhone' in ua_string or 'iPad' in ua_string:
        match = re.search(r'OS ([\d_]+)', ua_string)
        version = match.group(1).replace('_', '.') if match else ''
        os_name = f'iOS {version}'.strip()
    elif 'Linux' in ua_string:
        if 'Ubuntu' in ua_string:
            os_name = 'Ubuntu Linux'
        else:
            os_name = 'Linux'
    elif 'CrOS' in ua_string:
        os_name = 'Chrome OS'

    # ── Detect Device Type ─────────────────────────────────────────
    mobile_keywords = ['Mobile', 'Android', 'iPhone', 'iPod', 'Opera Mini', 'IEMobile']
    tablet_keywords = ['iPad', 'Tablet', 'Nexus 7', 'Nexus 10']

    if any(kw in ua_string for kw in tablet_keywords):
        device_type = 'Tablet'
    elif any(kw in ua_string for kw in mobile_keywords):
        device_type = 'Mobile'
    else:
        device_type = 'Desktop'

    return {
        'browser': browser,
        'os': os_name,
        'device_type': device_type,
        'raw': ua_string
    }


def get_real_ip():
    """
    Get the real client IP address, with three resolution tiers:

    1. Flask session 'client_real_ip' — set by /auth/store-client-ip when
       JavaScript detects the browser's public IP via api.ipify.org.
       This solves localhost-VPN detection: the server sees 127.0.0.1 but the
       browser reports its real public IP (which may be a VPN exit node).

    2. X-Forwarded-For header — used when Flask sits behind a reverse proxy
       (nginx, Cloudflare, etc.).

    3. request.remote_addr — direct connection fallback.
    """
    try:
        from flask import session as flask_session
        client_ip = flask_session.get('client_real_ip', '')
        if client_ip and client_ip not in ('127.0.0.1', '::1', '0.0.0.0'):
            return client_ip
    except RuntimeError:
        pass  # Outside request context — ignore

    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()

    return request.remote_addr or '127.0.0.1'



def get_request_context():
    """
    Build a complete real-time context dict from the current Flask request.
    Calls geo_service.lookup_ip() to obtain real city, region, country,
    timezone, ISP, lat/lon, and VPN/proxy detection for external IPs.

    Returns:
        {
            'ip_address': str,
            'browser': str,
            'os': str,
            'device_type': str,
            'user_agent': str,
            'location': str,        -- human-readable "City, Region, CC"
            'timestamp': str,
            # Enriched geo fields (always present):
            'city': str,
            'region': str,
            'country': str,
            'country_code': str,
            'timezone': str,
            'isp': str,
            'latitude': float|None,
            'longitude': float|None,
            'is_vpn': bool,
            'is_proxy': bool,
            'is_hosting': bool,
            'geo_source': str,      -- 'ip-api' | 'ipinfo' | 'local' | 'fallback'
        }
    """
    from datetime import datetime
    from app.ml.geo_service import lookup_ip

    ua_string = request.headers.get('User-Agent', '')
    ua_info = parse_user_agent(ua_string)
    ip = get_real_ip()

    # Resolve geolocation (cached; never raises)
    geo = lookup_ip(ip)

    return {
        'ip_address':   ip,
        'browser':      ua_info['browser'],
        'os':           ua_info['os'],
        'device_type':  ua_info['device_type'],
        'user_agent':   ua_info['raw'],
        'location':     geo['location_str'],
        'timestamp':    datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        # Enriched geo fields
        'city':         geo['city'],
        'region':       geo['region'],
        'country':      geo['country'],
        'country_code': geo['country_code'],
        'timezone':     geo['timezone'],
        'isp':          geo['isp'],
        'latitude':     geo['latitude'],
        'longitude':    geo['longitude'],
        'is_vpn':       geo['is_vpn'],
        'is_proxy':     geo['is_proxy'],
        'is_hosting':   geo['is_hosting'],
        'geo_source':   geo['source'],
    }

