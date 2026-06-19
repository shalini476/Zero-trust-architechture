from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import func

from app.extensions import db
from app.models import User, Alert, ActivityLog, MLPrediction
from app.auth.decorators import admin_required

api_bp = Blueprint('api', __name__)

@api_bp.route('/stats')
@login_required
@admin_required
def stats():
    """General dashboard summary metrics."""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    unresolved_alerts = Alert.query.filter_by(is_resolved=False).count()
    critical_alerts = Alert.query.filter_by(is_resolved=False, severity='critical').count()
    
    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'unresolved_alerts': unresolved_alerts,
        'critical_alerts': critical_alerts
    })

@api_bp.route('/trust-distribution')
@login_required
@admin_required
def trust_distribution():
    """Counts users in different trust score brackets."""
    trusted = User.query.filter(User.trust_score >= 80).count()
    medium_risk = User.query.filter(User.trust_score >= 50, User.trust_score < 80).count()
    high_risk = User.query.filter(User.trust_score < 50).count()
    
    return jsonify({
        'labels': ['Trusted (80-100)', 'Medium Risk (50-79)', 'High Risk (<50)'],
        'data': [trusted, medium_risk, high_risk]
    })

@api_bp.route('/threat-classification-stats')
@login_required
@admin_required
def threat_classification_stats():
    """Retreives counts of ML threat prediction results."""
    normal = MLPrediction.query.filter_by(threat_classification='normal').count()
    suspicious = MLPrediction.query.filter_by(threat_classification='suspicious').count()
    high_risk = MLPrediction.query.filter_by(threat_classification='high_risk').count()
    
    # Fallback to defaults if no predictions yet
    if normal == 0 and suspicious == 0 and high_risk == 0:
        normal, suspicious, high_risk = 5, 0, 0
        
    return jsonify({
        'labels': ['Normal', 'Suspicious', 'High Risk'],
        'data': [normal, suspicious, high_risk]
    })

@api_bp.route('/login-trends')
@login_required
@admin_required
def login_trends():
    """Retrieves daily login successes vs failures for the last 7 days."""
    today = datetime.utcnow().date()
    dates = [today - timedelta(days=i) for i in range(6, -1, -1)]
    
    success_counts = []
    failed_counts = []
    labels = []
    
    for date in dates:
        start_time = datetime.combine(date, datetime.min.time())
        end_time = datetime.combine(date, datetime.max.time())
        
        success = ActivityLog.query.filter(
            ActivityLog.action.like('LOGIN%'),
            ActivityLog.status == 'SUCCESS',
            ActivityLog.timestamp >= start_time,
            ActivityLog.timestamp <= end_time
        ).count()
        
        failed = ActivityLog.query.filter(
            ActivityLog.action.like('LOGIN%'),
            ActivityLog.status == 'FAILED',
            ActivityLog.timestamp >= start_time,
            ActivityLog.timestamp <= end_time
        ).count()
        
        success_counts.append(success)
        failed_counts.append(failed)
        labels.append(date.strftime('%b %d'))
        
    return jsonify({
        'labels': labels,
        'success': success_counts,
        'failed': failed_counts
    })
