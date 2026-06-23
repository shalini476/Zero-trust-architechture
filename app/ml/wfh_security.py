"""
Zero Trust Security Platform — WFH Security Module
Zerofox

Implements Work-From-Home risk checks using REAL data:
  - Device recognition          → KnownDevice table
  - Login time analysis         → BehaviorProfile.usual_login_hours
  - Trusted network / VPN       → geo_service (ip-api.com, no random)
  - Impossible travel detection → haversine distance between WFHLoginHistory rows
  - Dynamic risk scoring        → weighted multi-factor score (0-100)
  - Full history persistence    → WFHLoginHistory table per login

No random values. No hardcoded ISP names. No simulated VPN flags.
"""

import logging
from datetime import datetime, timedelta

from flask import request as flask_request

from app.extensions import db
from app.models import KnownDevice, BehaviorProfile, ActivityLog, WFHLoginHistory
from app.ml.trust_engine import trust_engine
from app.ml.device_detector import parse_user_agent, get_real_ip, get_request_context
from app.ml.geo_service import lookup_ip, haversine_km

logger = logging.getLogger(__name__)

# Maximum plausible travel speed in km/h (commercial aviation ceiling).
# Logins faster than this between two different locations → impossible travel.
MAX_TRAVEL_SPEED_KMH = 900.0

# ---------------------------------------------------------------------------
# Risk score weights (additive; capped at 100)
# ---------------------------------------------------------------------------
RISK_WEIGHTS = {
    'vpn_detected':        25,   # VPN or proxy IP detected
    'hosting_detected':    20,   # Datacenter / cloud IP (likely VPN relay)
    'untrusted_network':   15,   # Not a known private/trusted network
    'impossible_travel':   30,   # Coordinates imply superhuman speed
    'new_device':          20,   # Device fingerprint never seen before
    'untrusted_device':    25,   # Device exists but marked is_trusted=False
    'unusual_time':        15,   # Outside user's normal login hours
    'off_hours':           10,   # Corporate off-hours (< 8 or > 20)
    'failed_logins_low':    5,   # 1-2 recent failed logins
    'failed_logins_mid':   12,   # 3-4 recent failed logins
    'failed_logins_high':  20,   # 5+ recent failed logins
    'otp_failures_low':     5,   # 1-2 recent OTP failures
    'otp_failures_high':   15,   # 3+ recent OTP failures
    'new_ip':              10,   # IP not in user's last-5 login IPs
    'location_change':     10,   # City/country changed from last login
}


# ---------------------------------------------------------------------------
# Geolocation context builder (real, never random)
# ---------------------------------------------------------------------------

def get_real_login_context() -> dict:
    """
    Capture real-time login context from the current HTTP request.

    Returns a dict with all fields from get_request_context() plus
    network_name, is_trusted_network, and computed VPN/proxy flags
    sourced entirely from ip-api.com (or its fallback chain).

    Never uses random values.
    """
    ctx = get_request_context()
    ip  = ctx['ip_address']

    # Network classification
    if ip in ('127.0.0.1', '::1') or ip.startswith('192.168.') or ip.startswith('10.'):
        network_name       = 'Local Network'
        is_trusted_network = True
    else:
        network_name       = 'External Network'
        is_trusted_network = False

    # VPN/proxy/hosting already resolved by geo_service inside get_request_context()
    is_vpn     = ctx.get('is_vpn', False)
    is_proxy   = ctx.get('is_proxy', False)
    is_hosting = ctx.get('is_hosting', False)

    return {
        # Core fields (same as before for backward compatibility)
        'ip_address':        ip,
        'location':          ctx['location'],
        'browser':           ctx['browser'],
        'os':                ctx['os'],
        'device_type':       ctx['device_type'],
        'user_agent':        ctx.get('user_agent', ''),
        'network_name':      network_name,
        'is_trusted_network': is_trusted_network,
        'is_vpn':            is_vpn,
        'is_proxy':          is_proxy,
        'is_hosting':        is_hosting,
        'isp':               ctx.get('isp', 'Unknown'),
        # Geo detail fields
        'city':              ctx.get('city', 'Unknown'),
        'region':            ctx.get('region', ''),
        'country':           ctx.get('country', 'Unknown'),
        'country_code':      ctx.get('country_code', 'XX'),
        'timezone':          ctx.get('timezone', 'UTC'),
        'latitude':          ctx.get('latitude'),
        'longitude':         ctx.get('longitude'),
        'geo_source':        ctx.get('geo_source', 'fallback'),
        # Impossible travel — computed later in evaluate_login_security()
        'is_impossible_travel': False,
    }


def simulate_login_context(scenario: str = 'random') -> dict:
    """
    Admin-triggered attack simulation only.
    Normal logins always use get_real_login_context().
    """
    ctx = get_real_login_context()
    if scenario == 'suspicious':
        ctx['is_vpn']             = True
        ctx['is_impossible_travel'] = True
        ctx['network_name']       = 'Public WiFi'
        ctx['is_trusted_network'] = False
        ctx['location']           = 'Berlin, Berlin, DE'
        ctx['city']               = 'Berlin'
        ctx['country']            = 'Germany'
        ctx['country_code']       = 'DE'
    return ctx


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_known_device(user, device_fingerprint: str, browser: str = None) -> tuple[bool, str]:
    """
    Check whether this device fingerprint is already known for this user.
    Registers new devices and fires the 'new_device' trust event if unseen.

    Returns (is_known, message).
    """
    existing = KnownDevice.query.filter_by(
        user_id=user.id, device_fingerprint=device_fingerprint
    ).first()

    if existing:
        existing.last_seen = datetime.utcnow()
        db.session.commit()
        return True, 'Known device recognized.'

    new_device = KnownDevice(
        user_id=user.id,
        device_fingerprint=device_fingerprint,
        browser=browser,
        is_trusted=False,
    )
    db.session.add(new_device)
    db.session.commit()

    trust_engine.apply_trust_event(
        user, 'new_device',
        detail=f'New device fingerprint registered: {device_fingerprint}',
    )
    return False, 'New device detected — trust score reduced.'


def check_login_time(user, login_dt: datetime = None) -> tuple[bool, str]:
    """
    Compare the current login hour against BehaviorProfile.usual_login_hours.
    Fires 'unusual_time' trust event if outside.

    Returns (is_normal_time, message).
    """
    login_dt   = login_dt or datetime.utcnow()
    hour       = login_dt.hour
    profile    = BehaviorProfile.query.filter_by(user_id=user.id).first()
    usual_hours = profile.get_usual_login_hours() if profile else []

    if usual_hours and hour not in usual_hours:
        trust_engine.apply_trust_event(
            user, 'unusual_time',
            detail=f'Login at unusual hour: {hour}:00',
        )
        return False, f'Unusual login time ({hour}:00).'

    return True, 'Login time within normal hours.'


def check_network_and_vpn(user, context: dict) -> list[str]:
    """
    Apply trust events for VPN detection and untrusted network.
    Uses REAL data from geo_service — no random values.

    Returns a list of human-readable flag messages.
    """
    messages = []

    if context['is_vpn'] or context['is_proxy']:
        trust_engine.apply_trust_event(
            user, 'vpn_detected',
            detail=f"VPN/Proxy detected on IP {context['ip_address']} (ISP: {context.get('isp', '?')})",
            ip_address=context['ip_address'],
        )
        messages.append('VPN/Proxy detected.')

    if not context['is_trusted_network']:
        trust_engine.apply_trust_event(
            user, 'untrusted_network',
            detail=f"Login from untrusted network: {context['network_name']}",
            ip_address=context['ip_address'],
        )
        messages.append(f"Untrusted network: {context['network_name']}.")

    return messages


def check_impossible_travel(user, context: dict) -> tuple[list[str], bool]:
    """
    Detect impossible travel by comparing the current login's geolocation
    against the user's most recent WFHLoginHistory entry.

    Uses haversine distance and time delta to compute travel speed.
    Flags if speed exceeds MAX_TRAVEL_SPEED_KMH (900 km/h).

    Returns (messages, is_impossible_travel).
    """
    messages = []
    is_impossible = False

    lat_now = context.get('latitude')
    lon_now = context.get('longitude')

    if lat_now is None or lon_now is None:
        # Cannot determine coordinates → skip travel check
        return messages, False

    prev = (
        WFHLoginHistory.query
        .filter_by(user_id=user.id)
        .filter(WFHLoginHistory.latitude.isnot(None))
        .order_by(WFHLoginHistory.timestamp.desc())
        .first()
    )

    if prev and prev.latitude is not None and prev.longitude is not None:
        distance_km = haversine_km(prev.latitude, prev.longitude, lat_now, lon_now)

        if distance_km is not None and distance_km > 50:  # ignore sub-50 km noise
            elapsed_hours = max(
                (datetime.utcnow() - prev.timestamp).total_seconds() / 3600.0,
                0.0167,   # floor at 1 minute to avoid div-by-zero
            )
            speed_kmh = distance_km / elapsed_hours

            if speed_kmh > MAX_TRAVEL_SPEED_KMH:
                is_impossible = True
                trust_engine.apply_trust_event(
                    user, 'impossible_travel',
                    detail=(
                        f'Impossible travel: {distance_km:.0f} km in '
                        f'{elapsed_hours * 60:.0f} min '
                        f'({speed_kmh:.0f} km/h). '
                        f'Previous: {prev.city}, {prev.country_code} → '
                        f'Current: {context.get("city", "?")}, {context.get("country_code", "?")}'
                    ),
                    ip_address=context['ip_address'],
                )
                messages.append(
                    f'Impossible travel detected: '
                    f'{prev.city} → {context.get("city", "?")} '
                    f'({distance_km:.0f} km in {elapsed_hours * 60:.0f} min).'
                )

    context['is_impossible_travel'] = is_impossible
    return messages, is_impossible


# ---------------------------------------------------------------------------
# Dynamic multi-factor risk scorer
# ---------------------------------------------------------------------------

def calculate_wfh_risk_score(user, context: dict, device_fingerprint: str) -> tuple[float, list[str]]:
    """
    Compute a WFH risk score (0–100) from multiple weighted factors:

        VPN/proxy detection        25 pts
        Hosting/datacenter IP      20 pts
        Untrusted network          15 pts
        Impossible travel          30 pts
        New device                 20 pts
        Untrusted device           25 pts
        Unusual login time         15 pts
        Corporate off-hours        10 pts
        Failed login count          5/12/20 pts
        OTP failure count           5/15 pts
        New IP address             10 pts
        Location change            10 pts

    Score is clamped to [0, 100].
    Returns (score, list_of_flag_strings).
    """
    score = 0.0
    flags = []
    now   = datetime.utcnow()

    # ── VPN / Proxy / Hosting ─────────────────────────────────────────
    if context.get('is_vpn') or context.get('is_proxy'):
        score += RISK_WEIGHTS['vpn_detected']
        flags.append(f"VPN/Proxy detected (ISP: {context.get('isp', '?')})")

    if context.get('is_hosting'):
        score += RISK_WEIGHTS['hosting_detected']
        flags.append(f"Datacenter/hosting IP detected (ISP: {context.get('isp', '?')})")

    # ── Network trust ────────────────────────────────────────────────
    if not context.get('is_trusted_network', True):
        score += RISK_WEIGHTS['untrusted_network']
        flags.append(f"Untrusted network: {context.get('network_name', 'External')}")

    # ── Impossible travel (already computed in context) ───────────────
    if context.get('is_impossible_travel'):
        score += RISK_WEIGHTS['impossible_travel']
        flags.append('Impossible travel pattern detected')

    # ── Device recognition ────────────────────────────────────────────
    device = KnownDevice.query.filter_by(
        user_id=user.id, device_fingerprint=device_fingerprint
    ).first()
    if not device:
        score += RISK_WEIGHTS['new_device']
        flags.append('New/unrecognized device')
    elif not device.is_trusted:
        score += RISK_WEIGHTS['untrusted_device']
        flags.append('Blocked/untrusted device detected')

    # ── Login time ────────────────────────────────────────────────────
    hour = now.hour
    profile = BehaviorProfile.query.filter_by(user_id=user.id).first()
    usual_hours = profile.get_usual_login_hours() if profile else []

    if hour < 8 or hour > 20:
        score += RISK_WEIGHTS['off_hours']
        flags.append(f'Login outside corporate hours ({hour}:00 UTC)')

    if usual_hours and hour not in usual_hours:
        score += RISK_WEIGHTS['unusual_time']
        flags.append(f'Unusual login hour for this user ({hour}:00 UTC)')

    # ── Recent failed logins (last 24 h) ─────────────────────────────
    cutoff_24h = now - timedelta(hours=24)
    failed_count = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action.in_(['LOGIN_CREDENTIALS', 'LOGIN_ATTEMPT']),
        ActivityLog.status == 'FAILED',
        ActivityLog.timestamp >= cutoff_24h,
    ).count()

    if failed_count >= 5:
        score += RISK_WEIGHTS['failed_logins_high']
        flags.append(f'High failed login count ({failed_count} in 24 h)')
    elif failed_count >= 3:
        score += RISK_WEIGHTS['failed_logins_mid']
        flags.append(f'Multiple failed logins ({failed_count} in 24 h)')
    elif failed_count > 0:
        score += RISK_WEIGHTS['failed_logins_low']
        flags.append(f'{failed_count} failed login(s) in 24 h')

    # ── Recent OTP failures (last 24 h) ──────────────────────────────
    from app.models import OTPRecord
    otp_fail_count = OTPRecord.query.filter(
        OTPRecord.user_id == user.id,
        OTPRecord.attempts >= 1,
        OTPRecord.created_at >= cutoff_24h,
    ).count()

    if otp_fail_count >= 3:
        score += RISK_WEIGHTS['otp_failures_high']
        flags.append(f'High OTP failure count ({otp_fail_count} in 24 h)')
    elif otp_fail_count > 0:
        score += RISK_WEIGHTS['otp_failures_low']
        flags.append(f'{otp_fail_count} OTP failure(s) in 24 h')

    # ── New IP not in recent history ──────────────────────────────────
    ip_now = context['ip_address']
    if ip_now not in ('127.0.0.1', '::1'):
        recent_ips = [
            row.ip_address
            for row in ActivityLog.query
            .filter_by(user_id=user.id)
            .filter(ActivityLog.timestamp >= now - timedelta(days=30))
            .order_by(ActivityLog.timestamp.desc())
            .limit(10)
            .all()
        ]
        if recent_ips and ip_now not in recent_ips:
            score += RISK_WEIGHTS['new_ip']
            flags.append(f'New IP address not in 30-day history ({ip_now})')

    # ── Location change from last successful login ─────────────────────
    prev_wfh = (
        WFHLoginHistory.query
        .filter_by(user_id=user.id)
        .order_by(WFHLoginHistory.timestamp.desc())
        .first()
    )
    if prev_wfh:
        current_city    = context.get('city', 'Unknown')
        current_country = context.get('country_code', 'XX')
        if (prev_wfh.country_code != 'LO' and   # skip localhost
                (prev_wfh.city != current_city or prev_wfh.country_code != current_country)):
            score += RISK_WEIGHTS['location_change']
            flags.append(
                f'Location changed: {prev_wfh.city}, {prev_wfh.country_code} → '
                f'{current_city}, {current_country}'
            )

    return min(100.0, score), flags


# ---------------------------------------------------------------------------
# Master orchestrator
# ---------------------------------------------------------------------------

def evaluate_login_security(user, device_fingerprint: str, browser: str = None,
                             scenario: str = 'random') -> dict:
    """
    Run all WFH security checks for a login and persist the results.

    Sequence:
      1. Capture real login context (geo, ISP, VPN — from geo_service)
      2. Detect impossible travel against WFHLoginHistory
      3. Run device / time / network / history checks
      4. Compute dynamic risk score (0–100)
      5. Write ActivityLog entry (WFH_SECURITY_CHECK)
      6. Write WFHLoginHistory entry (for future travel/location checks)
      7. Return result dict

    Returns:
        {
            'trust_score': int,
            'risk_level': str,        # 'trusted' / 'medium_risk' / 'high_risk'
            'wfh_risk_score': float,  # dynamic 0-100 score
            'requires_otp': bool,
            'requires_alert': bool,
            'messages': list[str],
            'flags': list[str],
            'context': dict,
        }
    """
    # 1. Capture context (real geo + VPN data)
    if scenario == 'suspicious':
        context = simulate_login_context(scenario='suspicious')
    else:
        context = get_real_login_context()

    messages = []

    # 2. Impossible travel detection (mutates context['is_impossible_travel'])
    travel_msgs, _ = check_impossible_travel(user, context)
    messages.extend(travel_msgs)

    # 3. Individual trust-event checks (device + time + network)
    _, device_msg = check_known_device(user, device_fingerprint, browser)
    messages.append(device_msg)

    _, time_msg = check_login_time(user)
    messages.append(time_msg)

    messages.extend(check_network_and_vpn(user, context))

    # 4. Dynamic risk score
    db.session.refresh(user)   # pick up trust_score after all events above
    risk_score, flags = calculate_wfh_risk_score(user, context, device_fingerprint)

    # 5. Determine log status
    has_flags  = bool(flags)
    log_status = 'FAILED' if has_flags else 'SUCCESS'

    # Build enriched browser info string
    vpn_tag     = 'VPN:Yes' if context.get('is_vpn') else 'VPN:No'
    browser_detail = (
        f"{context.get('browser', browser or 'Unknown')} | "
        f"{context.get('os', 'Unknown')} | "
        f"{context.get('device_type', 'Unknown')} | "
        f"{context.get('isp', 'Unknown')} | "
        f"{vpn_tag}"
    )

    # 6. Persist ActivityLog entry
    log_entry = ActivityLog(
        user_id=user.id,
        action='WFH_SECURITY_CHECK',
        status=log_status,
        ip_address=context['ip_address'],
        device_fingerprint=device_fingerprint,
        browser_info=browser_detail,
        location=context['location'],
        risk_score=risk_score,
    )
    db.session.add(log_entry)

    # 7. Persist WFHLoginHistory entry
    history_entry = WFHLoginHistory(
        user_id=user.id,
        ip_address=context['ip_address'],
        latitude=context.get('latitude'),
        longitude=context.get('longitude'),
        city=context.get('city', 'Unknown'),
        region=context.get('region', ''),
        country=context.get('country', 'Unknown'),
        country_code=context.get('country_code', 'XX'),
        timezone=context.get('timezone', 'UTC'),
        isp=context.get('isp', 'Unknown'),
        is_vpn=context.get('is_vpn', False),
        is_proxy=context.get('is_proxy', False),
        is_hosting=context.get('is_hosting', False),
        risk_score=risk_score,
    )
    history_entry.set_flags(flags)
    db.session.add(history_entry)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error('[WFHSecurity] DB commit failed: %s', exc)

    risk_level = trust_engine.get_trust_level(user.trust_score)

    return {
        'trust_score':    user.trust_score,
        'risk_level':     risk_level,
        'wfh_risk_score': risk_score,
        'requires_otp':   risk_level in ('medium_risk', 'high_risk'),
        'requires_alert': risk_level == 'high_risk',
        'messages':       messages,
        'flags':          flags,
        'context':        context,
    }