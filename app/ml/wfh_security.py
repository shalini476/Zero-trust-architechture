"""
Zero Trust Security Platform — WFH Security Module
Zerofox

Implements Work-From-Home risk checks:
  - Device recognition (known vs new device)
  - Login time analysis (normal vs unusual hours)
  - Trusted network verification (simulated)
  - VPN/proxy detection (simulated)
  - Impossible travel detection (simulated)

NOTE on simulation: live VPN/IP-geolocation detection normally requires an
external API (e.g. ipapi.co, IPQualityScore) with signup + API key. Per
project decision, this module SIMULATES that data instead — fine for a
demo/certification project, but not real security telemetry. Swap
simulate_login_context() for a real API call later if needed.

This module is currently STANDALONE — it is not yet wired into the real
login flow because app/auth/routes.py hasn't been shared yet. Once you
upload it, the actual call site (replacing/extending whatever already
handles login there) needs to call evaluate_login_security() below.
"""

import random
from datetime import datetime

from app.extensions import db
from app.models import KnownDevice, BehaviorProfile, ActivityLog
from app.ml.trust_engine import trust_engine


# ── Simulated network/location data pools ──────────────────────────────────
FAKE_LOCATIONS = [
    "Bangalore, India", "Mumbai, India", "Chennai, India",
    "Berlin, Germany", "Singapore", "New York, USA", "London, UK",
]
FAKE_NETWORKS = [
    "Home WiFi", "Office WiFi", "Mobile Hotspot",
    "Coffee Shop WiFi", "Airport WiFi", "Public WiFi",
]
TRUSTED_NETWORK_NAMES = {"Home WiFi", "Office WiFi"}


def simulate_login_context(scenario: str = "random") -> dict:
    """
    Generate a fake login context for demo purposes.

    Args:
        scenario: "safe" forces a low-risk context (known-pattern network,
                  no VPN, no impossible travel). "suspicious" forces a
                  high-risk context. "random" picks randomly each call.

    Returns:
        dict with keys: ip_address, location, network_name,
        is_trusted_network, is_vpn, is_impossible_travel
    """
    if scenario == "safe":
        network_name = random.choice(["Home WiFi", "Office WiFi"])
        is_vpn = False
        is_impossible_travel = False
    elif scenario == "suspicious":
        network_name = random.choice(["Public WiFi", "Airport WiFi", "Coffee Shop WiFi"])
        is_vpn = True
        is_impossible_travel = True
    else:  # random
        network_name = random.choice(FAKE_NETWORKS)
        is_vpn = random.random() < 0.25
        is_impossible_travel = random.random() < 0.1

    return {
        "ip_address": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "location": random.choice(FAKE_LOCATIONS),
        "network_name": network_name,
        "is_trusted_network": network_name in TRUSTED_NETWORK_NAMES,
        "is_vpn": is_vpn,
        "is_impossible_travel": is_impossible_travel,
    }


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
        return True, "Known device recognized."

    new_device = KnownDevice(
        user_id=user.id,
        device_fingerprint=device_fingerprint,
        browser=browser,
        is_trusted=False,
    )
    db.session.add(new_device)
    db.session.commit()

    trust_engine.apply_trust_event(
        user, "new_device",
        detail=f"New device fingerprint registered: {device_fingerprint}",
    )
    return False, "New device detected — trust score reduced."


def check_login_time(user, login_dt: datetime = None) -> tuple[bool, str]:
    """
    Compare the current login hour against the user's usual_login_hours
    from BehaviorProfile. Fires 'unusual_time' trust event if outside.

    Returns (is_normal_time, message).
    """
    login_dt = login_dt or datetime.utcnow()
    hour = login_dt.hour

    profile = BehaviorProfile.query.filter_by(user_id=user.id).first()
    usual_hours = profile.get_usual_login_hours() if profile else []

    if usual_hours and hour not in usual_hours:
        trust_engine.apply_trust_event(
            user, "unusual_time",
            detail=f"Login at unusual hour: {hour}:00",
        )
        return False, f"Unusual login time ({hour}:00)."

    return True, "Login time within normal hours."


def check_network_and_vpn(user, context: dict) -> list[str]:
    """
    Apply trust events for VPN detection and untrusted network, based on
    a simulated (or real, if you swap the source later) context dict.

    Returns a list of human-readable messages for any flags raised.
    """
    messages = []

    if context["is_vpn"]:
        trust_engine.apply_trust_event(
            user, "vpn_detected",
            detail=f"VPN/Proxy detected on IP {context['ip_address']}",
            ip_address=context["ip_address"],
        )
        messages.append("VPN/Proxy detected.")

    if not context["is_trusted_network"]:
        trust_engine.apply_trust_event(
            user, "untrusted_network",
            detail=f"Login from untrusted network: {context['network_name']}",
            ip_address=context["ip_address"],
        )
        messages.append(f"Untrusted network: {context['network_name']}.")

    return messages


def check_impossible_travel(user, context: dict) -> list[str]:
    """
    Fires the 'impossible_travel' trust event if the simulated context
    flags it. (Simulated only — no real distance/time calculation.)
    """
    messages = []
    if context["is_impossible_travel"]:
        trust_engine.apply_trust_event(
            user, "impossible_travel",
            detail=f"Impossible travel pattern detected — location: {context['location']}",
            ip_address=context["ip_address"],
        )
        messages.append(f"Impossible travel detected (claimed location: {context['location']}).")
    return messages


def evaluate_login_security(user, device_fingerprint: str, browser: str = None,
                             scenario: str = "random") -> dict:
    """
    Master orchestrator — runs all WFH checks for a login attempt and
    returns the resulting trust score, risk level, and required actions.

    This is the function meant to be called from the login route in
    app/auth/routes.py once it's wired in.

    Returns:
        {
            'trust_score': int,
            'risk_level': str,        # 'trusted' / 'medium_risk' / 'high_risk'
            'requires_otp': bool,
            'requires_alert': bool,
            'messages': list[str],
            'context': dict,          # the simulated network/location data used
        }
    """
    context = simulate_login_context(scenario=scenario)
    messages = []

    _, device_msg = check_known_device(user, device_fingerprint, browser)
    messages.append(device_msg)

    _, time_msg = check_login_time(user)
    messages.append(time_msg)

    messages.extend(check_network_and_vpn(user, context))
    messages.extend(check_impossible_travel(user, context))

    # Log a summary entry for this evaluation
    db.session.refresh(user)  # pick up the latest trust_score after all events above
    log_entry = ActivityLog(
        user_id=user.id,
        action="WFH_SECURITY_CHECK",
        status="SUCCESS",
        ip_address=context["ip_address"],
        device_fingerprint=device_fingerprint,
        browser_info=browser,
        location=context["location"],
        risk_score=100 - user.trust_score,
    )
    db.session.add(log_entry)
    db.session.commit()

    risk_level = trust_engine.get_trust_level(user.trust_score)

    return {
        "trust_score": user.trust_score,
        "risk_level": risk_level,
        "requires_otp": risk_level in ("medium_risk", "high_risk"),
        "requires_alert": risk_level == "high_risk",
        "messages": messages,
        "context": context,
    }