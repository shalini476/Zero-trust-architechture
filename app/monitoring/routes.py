from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime

from app.extensions import db
from app.models import ActivityLog, Alert, User
from app.auth.decorators import admin_required

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/logs')
@login_required
@admin_required
def logs():
    """Lists all security activity logs for audit purposes."""
    # Add pagination since logs can grow large
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Query logs in descending order (latest first)
    logs_pagination = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template(
        'monitoring/activity_logs.html', 
        logs=logs_pagination.items, 
        pagination=logs_pagination
    )

@monitoring_bp.route('/alerts')
@login_required
@admin_required
def alerts():
    """Lists all generated security alerts."""
    # Query unresolved alerts first, sorted by timestamp
    unresolved_alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.timestamp.desc()).all()
    resolved_alerts = Alert.query.filter_by(is_resolved=True).order_by(Alert.timestamp.desc()).limit(30).all()
    
    return render_template(
        'monitoring/alerts.html',
        unresolved=unresolved_alerts,
        resolved=resolved_alerts
    )

@monitoring_bp.route('/alerts/resolve/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
def resolve_alert(alert_id):
    """Admin endpoint to mark an alert as resolved."""
    alert = Alert.query.get_or_404(alert_id)
    alert.is_resolved = True
    alert.resolved_by = current_user.id
    
    # Log the resolution action
    log = ActivityLog(
        user_id=current_user.id,
        action='ALERT_RESOLVE',
        status='SUCCESS',
        ip_address=request.remote_addr,
        resource_accessed=f"Alert ID: {alert_id}"
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f"Alert #{alert_id} ({alert.alert_type}) has been resolved.", "success")
    return redirect(url_for('monitoring.alerts'))
