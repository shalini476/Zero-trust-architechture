from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from app.models import User, Alert, ActivityLog, MLPrediction, KnownDevice
from app.auth.decorators import admin_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    """Redirects the user to their appropriate dashboard based on their role."""
    if current_user.role == 'admin':
        return redirect(url_for('dashboard.admin_dashboard'))
    return redirect(url_for('dashboard.user_dashboard'))

@dashboard_bp.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Main Administrator Dashboard showing system-wide security metrics."""
    users = User.query.all()
    recent_alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.timestamp.desc()).limit(5).all()
    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(5).all()
    
    # Calculate some summary stats
    total_users = len(users)
    active_users = sum(1 for u in users if u.is_active)
    unresolved_count = Alert.query.filter_by(is_resolved=False).count()
    
    # Calculate average trust score
    avg_trust = int(sum(u.trust_score for u in users) / total_users) if total_users > 0 else 100
    
    return render_template(
        'dashboard/admin_dashboard.html',
        users=users,
        recent_alerts=recent_alerts,
        recent_logs=recent_logs,
        total_users=total_users,
        active_users=active_users,
        unresolved_count=unresolved_count,
        avg_trust=avg_trust
    )

@dashboard_bp.route('/user')
@login_required
def user_dashboard():
    """User Personal Security Dashboard showing their security standing."""
    # Retrieve user's personal logs
    personal_logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Retrieve user's personal alerts
    personal_alerts = Alert.query.filter_by(user_id=current_user.id, is_resolved=False).order_by(Alert.timestamp.desc()).all()
    
    # Retrieve user's registered devices
    devices = KnownDevice.query.filter_by(user_id=current_user.id).all()
    
    # Retrieve user's latest ML evaluation profile
    latest_ml = MLPrediction.query.filter_by(user_id=current_user.id).order_by(MLPrediction.timestamp.desc()).first()
    
    # Determine general security status text
    if current_user.trust_score >= 80:
        status_text = "TRUSTED"
        status_class = "success"
    elif current_user.trust_score >= 50:
        status_text = "RISK_WARNING"
        status_class = "warning"
    else:
        status_text = "SUSPENDED_THREAT"
        status_class = "danger"
        
    return render_template(
        'dashboard/user_dashboard.html',
        personal_logs=personal_logs,
        personal_alerts=personal_alerts,
        devices=devices,
        latest_ml=latest_ml,
        status_text=status_text,
        status_class=status_class
    )
