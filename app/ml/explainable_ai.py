def generate_xai_explanations(login_hour, failed_attempts_24h, is_new_device, is_unusual_time, trust_score, resource_access_frequency, honeypot_accessed):
    """
    Translates feature inputs into human-readable reasons explaining the AI's risk rating.
    This fulfills the Explainable AI (XAI) requirements for security audits.
    """
    reasons = []
    
    if honeypot_accessed:
        reasons.append("⚠ CRITICAL: Accessed a forbidden honeypot resource trap.")
        
    if is_new_device:
        reasons.append("⚠ Unrecognized device fingerprint or browser user-agent.")
        
    if is_unusual_time:
        reasons.append(f"⚠ Activity occurred during off-hours ({login_hour:02d}:00 UTC). Standard hours are 08:00 - 20:00.")
        
    if failed_attempts_24h >= 6:
        reasons.append(f"⚠ Critical security risk: {failed_attempts_24h} failed login attempts in 24 hours (possible brute-force).")
    elif failed_attempts_24h >= 3:
        reasons.append(f"⚠ Suspicious log: {failed_attempts_24h} failed login attempts in 24 hours.")
        
    if resource_access_frequency > 15:
        reasons.append(f"⚠ Abnormal resource access speed: {resource_access_frequency} requests in this session (potential data harvesting).")
    elif resource_access_frequency > 8:
        reasons.append(f"⚠ High resource access count: {resource_access_frequency} requests in this session.")
        
    if trust_score < 50:
        reasons.append(f"⚠ Critical trust posture: Trust score is severely degraded ({trust_score}/100).")
    elif trust_score < 80:
        reasons.append(f"⚠ Degraded trust posture: Trust score is below safe threshold ({trust_score}/100).")
        
    if not reasons:
        reasons.append("✓ Access parameters correlate with standard established baselines.")
        
    return reasons
