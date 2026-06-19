from datetime import datetime
import json
from app.models import User, BehaviorProfile, KnownDevice, ActivityLog
from app.extensions import db

def analyze_user_behavior(user, ip_address, device_fingerprint, browser_info, timestamp=None):
    """
    Evaluates current login context against historical baseline to calculate
    a Behavioral Risk Score (0-100).
    """
    if timestamp is None:
        timestamp = datetime.utcnow()
        
    # Get or create behavior profile
    profile = BehaviorProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        profile = BehaviorProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
        
    risk_score = 0
    reasons = []
    
    # 1. Login Time Pattern (Max 25 pts)
    hour = timestamp.hour
    usual_hours = profile.get_usual_login_hours()
    
    # Check if outside corporate hours (8 AM to 8 PM)
    if hour < 8 or hour > 20:
        # If user has historically logged in at this hour, mitigate
        if usual_hours and hour not in usual_hours:
            risk_score += 25
            reasons.append("Login outside standard working hours (Midnight/Off-hours)")
        elif not usual_hours:
            risk_score += 20
            reasons.append("Login outside standard working hours")
    elif usual_hours and hour not in usual_hours:
        # Business hours, but not the user's usual hours
        risk_score += 10
        reasons.append("Login at unusual hour for this user")
        
    # 2. Device Recognition (Max 30 pts)
    # Check if fingerprint exists in known devices
    device = KnownDevice.query.filter_by(user_id=user.id, device_fingerprint=device_fingerprint).first()
    if not device:
        risk_score += 30
        reasons.append("Login attempt from a new unrecognized device")
    elif not device.is_trusted:
        risk_score += 30
        reasons.append("Login attempt from a blocked/untrusted device")
        
    # 3. Login Frequency/Velocity (Max 20 pts)
    # Check failed login attempts in last 24h
    recent_failed = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action == 'LOGIN_ATTEMPT',
        ActivityLog.status == 'FAILED',
        ActivityLog.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    
    if recent_failed >= 5:
        risk_score += 20
        reasons.append(f"Excessive login failures ({recent_failed} failures in last 24 hours)")
    elif recent_failed >= 3:
        risk_score += 15
        reasons.append("Multiple failed login attempts detected")
    elif recent_failed > 0:
        risk_score += 5
        
    # 4. Location Consistency / IP (Max 25 pts)
    # For a local prototype, we can simulate location changes.
    # If the user logs in from an IP different from their last 3 IPs, we flag it.
    past_logs = ActivityLog.query.filter_by(user_id=user.id, action='LOGIN_SUCCESS').order_by(ActivityLog.timestamp.desc()).limit(5).all()
    past_ips = [log.ip_address for log in past_logs if log.ip_address]
    
    if past_ips and ip_address not in past_ips:
        risk_score += 25
        reasons.append(f"Login from new IP address/location ({ip_address})")

    # Clamping between 0 and 100
    risk_score = min(100, risk_score)
    
    # Determine Risk Level
    # 0-30 = Low/Normal, 31-60 = Medium/Suspicious, 61-100 = High Risk
    if risk_score <= 30:
        risk_level = "normal"
    elif risk_score <= 60:
        risk_level = "suspicious"
    else:
        risk_level = "high_risk"
        
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'reasons': reasons
    }

def update_user_baseline(user, ip_address, device_fingerprint, resource_accessed=None):
    """
    Updates user behavioral baseline statistics after a successful login or access event.
    """
    profile = BehaviorProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        profile = BehaviorProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
        
    # 1. Update usual hours
    current_hour = datetime.utcnow().hour
    usual_hours = profile.get_usual_login_hours()
    if current_hour not in usual_hours:
        usual_hours.append(current_hour)
        profile.set_usual_login_hours(usual_hours)
        
    # 2. Update common devices
    common_devices = profile.get_common_devices()
    if device_fingerprint not in common_devices:
        common_devices.append(device_fingerprint)
        profile.set_common_devices(common_devices)
        
    # 3. Update common resources
    if resource_accessed:
        common_resources = profile.get_common_resources()
        if resource_accessed not in common_resources:
            common_resources.append(resource_accessed)
            profile.set_common_resources(common_resources)
            
    # 4. Update avg daily logins
    success_logins_today = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action == 'LOGIN_SUCCESS',
        ActivityLog.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    profile.avg_daily_logins = float(max(profile.avg_daily_logins, success_logins_today))
    
    profile.last_updated = datetime.utcnow()
    db.session.commit()
