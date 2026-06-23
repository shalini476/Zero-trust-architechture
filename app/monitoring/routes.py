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
    page = request.args.get('page', 1, type=int)
    per_page = 25

    logs_pagination = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Also fetch WFH-specific logs for the WFH section
    wfh_logs = (
        ActivityLog.query
        .filter(ActivityLog.action == 'WFH_SECURITY_CHECK')
        .order_by(ActivityLog.timestamp.desc())
        .limit(20)
        .all()
    )

    return render_template(
        'monitoring/activity_logs.html',
        logs=logs_pagination.items,
        wfh_logs=wfh_logs,
        pagination=logs_pagination
    )


@monitoring_bp.route('/wfh-logs')
@login_required
@admin_required
def wfh_logs():
    """
    Dedicated page showing only WFH_SECURITY_CHECK activity log entries.
    Displays VPN detection, network trust, location, ISP, and risk score
    for every login that passed through the WFH security module.
    """
    page = request.args.get('page', 1, type=int)
    per_page = 25

    wfh_pagination = (
        ActivityLog.query
        .filter(ActivityLog.action == 'WFH_SECURITY_CHECK')
        .order_by(ActivityLog.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    # Summary counts across ALL WFH logs (not just current page)
    total_checks  = ActivityLog.query.filter(ActivityLog.action == 'WFH_SECURITY_CHECK').count()
    flagged_count = ActivityLog.query.filter(
        ActivityLog.action == 'WFH_SECURITY_CHECK',
        ActivityLog.status == 'FAILED'
    ).count()
    clean_count = total_checks - flagged_count

    return render_template(
        'monitoring/wfh_logs.html',
        logs=wfh_pagination.items,
        pagination=wfh_pagination,
        total_checks=total_checks,
        flagged_count=flagged_count,
        clean_count=clean_count,
    )


@monitoring_bp.route('/alerts')
@login_required
@admin_required
def alerts():
    """Lists all generated security alerts."""
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