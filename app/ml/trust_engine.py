"""
Zero Trust Security Platform — Trust Score Engine
Zerofox

Manages dynamic trust scores for all users.
Trust scores (0-100) are updated whenever a notable event occurs.
Events can increase or decrease the score, clamped to [0, 100].

Trust events and their score deltas:
    login_success          +5   — successful authentication
    failed_login           -10  — each failed login attempt
    new_device             -15  — login from an unrecognised device
    unusual_time            -5  — login outside business hours
    mfa_passed              +10 — multi-factor authentication passed
    honeypot_access        -50  — accessed a honeypot resource (critical penalty)
    insider_threat          -40 — bulk sensitive resource access (insider threat pattern)
    resource_access          -2 — accessing sensitive resources (per access, small penalty)
    account_inactive          -5 — not logged in for >14 days
    security_review         +20 — admin manually vouches for the user
    password_changed          +5 — user changed their password
    otp_failed              -10  — failed OTP attempt
"""

import logging
from datetime import datetime, timezone

from app.extensions import db

logger = logging.getLogger(__name__)

# ── Trust event delta map ──────────────────────────────────────────────────────
TRUST_EVENTS = {
    'login_success':   +5,
    'failed_login':    -5,
    'new_device':      -5,
    'unusual_time':    -10,
    'mfa_passed':      +10,
    'honeypot_access': -25,
    'insider_threat':  -40,
    'resource_access': -2,
    'account_inactive':-5,
    'security_review': +20,
    'password_changed':+5,
    'otp_failed':      -10,
    'vpn_detected':    -30,  # WFH: VPN/proxy detected on login network
    'untrusted_network': -25,  # WFH: login from a network not on the user's trusted list
    'impossible_travel': -40,  # WFH: simulated geolocation jump too fast to be real
}

# Trust tier thresholds
TRUST_TIER_HIGH    = 75  # >= 75  → trusted (green)
TRUST_TIER_MEDIUM  = 40  # 40-74  → medium_risk (yellow)
# < 40  → high_risk (red)


class TrustEngine:
    """
    Singleton service that calculates and updates user trust scores.

    All updates go through apply_trust_event() to ensure consistent clamping
    and audit-trail creation.
    """

    def apply_trust_event(self, user, event: str, detail: str = '', ip_address: str = 'SYSTEM') -> int:
        """
        Apply a named trust event to the user, update the DB, and return the new score.

        Args:
            user: SQLAlchemy User model instance.
            event: Key from TRUST_EVENTS dict (e.g. 'honeypot_access').
            detail: Optional human-readable context logged alongside the change.
            ip_address: IP address associated with the triggering request.
                Defaults to 'SYSTEM' for events not tied to a specific request
                (e.g. scheduled recalculation), since ActivityLog.ip_address
                is a required (non-nullable) column.

        Returns:
            New trust_score after the event (0-100).
        """
        from app.models import ActivityLog  # Deferred to avoid circular imports

        if event not in TRUST_EVENTS:
            logger.warning("[TrustEngine] Unknown event '%s' — no score change applied.", event)
            return user.trust_score

        delta = TRUST_EVENTS[event]
        old_score = user.trust_score
        new_score = max(0, min(100, old_score + delta))

        user.trust_score = new_score

        # Persist via the ORM (the caller is responsible for committing the session
        # so that multiple events in one request can be batched into a single commit)
        try:
            db.session.add(user)

            # Optionally log the trust change as an activity entry
            change_detail = (
                f"Trust score changed: {old_score} → {new_score} "
                f"(event={event}, delta={delta:+d}). {detail}"
            ).strip()

            # NOTE: ActivityLog has no 'detail' column — the closest existing
            # field is 'resource_accessed' (Text-ish String(200)), used here
            # to store the human-readable change description instead.
            # ip_address is NOT NULL on this model, so it must always be set.
            log_entry = ActivityLog(
                user_id=user.id,
                action='TRUST_SCORE_UPDATE',
                status='SUCCESS',
                ip_address=ip_address,
                resource_accessed=change_detail,
            )
            db.session.add(log_entry)
            db.session.commit()

            logger.info(
                "[TrustEngine] user=%s event=%s %d→%d",
                user.username, event, old_score, new_score,
            )
        except Exception as exc:
            db.session.rollback()
            logger.error("[TrustEngine] DB error applying trust event: %s", exc)

        return new_score

    def get_trust_level(self, score: int) -> str:
        """Return the human-readable trust tier for a given score."""
        if score >= TRUST_TIER_HIGH:
            return 'trusted'
        elif score >= TRUST_TIER_MEDIUM:
            return 'medium_risk'
        else:
            return 'high_risk'

    def get_trust_color(self, score: int) -> str:
        """Return Bootstrap colour class for a trust score."""
        level = self.get_trust_level(score)
        return {'trusted': 'success', 'medium_risk': 'warning', 'high_risk': 'danger'}.get(
            level, 'secondary'
        )

    def recalculate_from_activity(self, user) -> int:
        """
        Recompute trust score from scratch using recent activity history.
        Used for periodic recalibration. Starts at 100, applies all events
        from the past 30 days in chronological order.

        Returns the newly calculated score.
        """
        from app.models import ActivityLog
        from datetime import timedelta

        base_score = 100
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)

        logs = (
            ActivityLog.query
            .filter(
                ActivityLog.user_id == user.id,
                ActivityLog.timestamp >= cutoff,
            )
            .order_by(ActivityLog.timestamp.asc())
            .all()
        )

        # Map activity actions to trust events
        action_event_map = {
            'LOGIN_SUCCESS':          'login_success',
            'LOGIN_FAILED':           'failed_login',
            'HONEYPOT_ACCESS':        'honeypot_access',
            'NEW_DEVICE':             'new_device',
            'MFA_SUCCESS':            'mfa_passed',
            'RESOURCE_ACCESS':        'resource_access',
        }

        score = base_score
        for log in logs:
            event_key = action_event_map.get(log.action)
            if event_key and event_key in TRUST_EVENTS:
                score = max(0, min(100, score + TRUST_EVENTS[event_key]))

        user.trust_score = score
        try:
            db.session.add(user)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.error("[TrustEngine] Recalculation DB error: %s", exc)

        return score


# ── Global singleton ───────────────────────────────────────────────────────────
trust_engine = TrustEngine()


def adjust_trust_score(user, event: str, detail: str = '', ip_address: str = 'SYSTEM') -> int:
    """
    Module-level convenience wrapper around trust_engine.apply_trust_event(),
    so code that does `from app.ml.trust_engine import adjust_trust_score`
    (e.g. app/auth/routes.py) has a function to import.

    NOTE: signature is inferred — I haven't seen the actual call site in
    routes.py. If this raises a TypeError about arguments, that means the
    real call passes different arguments (e.g. a raw integer delta instead
    of an event name) — share the exact call line from routes.py and I'll
    match this signature exactly.
    """
    return trust_engine.apply_trust_event(user, event, detail=detail, ip_address=ip_address)