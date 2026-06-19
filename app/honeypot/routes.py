from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from datetime import datetime
import os
import csv

from app.extensions import db
from app.models import ActivityLog, HoneypotAccess, Alert
from app.ml.trust_engine import adjust_trust_score

honeypot_bp = Blueprint('honeypot', __name__)

@honeypot_bp.route('/')
@login_required
def index():
    """Confidential resources portal which includes honeypot trap files."""
    return render_template('honeypot/resources.html')

def trigger_honeypot_trap(resource_name):
    """Utility helper to trigger honeypot intrusion logic."""
    # Log to honeypot accesses table
    access = HoneypotAccess(
        user_id=current_user.id,
        resource_name=resource_name,
        ip_address=request.remote_addr
    )
    db.session.add(access)
    
    # Log to general activity log
    log = ActivityLog(
        user_id=current_user.id,
        action='HONEYPOT_TRIGGER',
        status='BLOCKED',
        ip_address=request.remote_addr,
        resource_accessed=resource_name,
        risk_score=100.0
    )
    db.session.add(log)
    
    # Deduct trust score (-50) and create critical Alert
    adjust_trust_score(
        user=current_user,
        event='honeypot_access',
        ip_address=request.remote_addr,
        detail=resource_name
    )
    
    # Commit changes
    db.session.commit()

# --- SAFE FILE ACCESS LOGGING ---
def log_safe_file_access(resource_name):
    """Logs normal, authorized file accesses and performs basic insider threat rate checks."""
    # 1. Log authorized file access
    log = ActivityLog(
        user_id=current_user.id,
        action='FILE_ACCESS',
        status='SUCCESS',
        ip_address=request.remote_addr,
        resource_accessed=resource_name,
        risk_score=10.0 # Low risk
    )
    db.session.add(log)
    db.session.commit()
    
    # 2. Check for Insider Threat: Excessive file accesses (> 10 accesses in past hour)
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    access_count = ActivityLog.query.filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.action == 'FILE_ACCESS',
        ActivityLog.timestamp >= one_hour_ago
    ).count()
    
    if access_count > 10:
        # Trigger Insider Threat alert
        adjust_trust_score(
            user=current_user,
            event='insider_threat',
            ip_address=request.remote_addr,
            detail=f"Excessive file access detected ({access_count} downloads in 1 hour)"
        )

from datetime import timedelta # Explicitly import timedelta for insider threat check

@honeypot_bp.route('/Employee_Handbook.pdf')
@login_required
def employee_handbook():
    log_safe_file_access('Employee_Handbook.pdf')
    flash('File Downloaded: Employee_Handbook.pdf (Authorized Access)', 'success')
    return redirect(url_for('honeypot.index'))

@honeypot_bp.route('/Asset_Guidelines.pdf')
@login_required
def asset_guidelines():
    log_safe_file_access('Asset_Guidelines.pdf')
    flash('File Downloaded: Asset_Guidelines.pdf (Authorized Access)', 'success')
    return redirect(url_for('honeypot.index'))

# --- HONEYPOT FILE ROUTE TRAPS ---
@honeypot_bp.route('/Salary_Data_2026.xlsx')
@login_required
def salary_data():
    """Honeypot trap that displays the file content while logging the access as suspicious."""
    trigger_honeypot_trap('Salary_Data_2026.xlsx')
    
    # Read and display the salary data file
    file_path = os.path.join(os.path.dirname(__file__), 'Salary_Data_2026.xlsx.csv')
    rows = []
    headers = []
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                headers = next(reader)  # Get headers
                rows = list(reader)  # Get all rows
    except Exception as e:
        flash(f'Error reading file: {str(e)}', 'danger')
        return redirect(url_for('honeypot.index'))
    
    return render_template('honeypot/salary_viewer.html', headers=headers, rows=rows)

@honeypot_bp.route('/Employee_Payroll.pdf')
@login_required
def employee_payroll():
    trigger_honeypot_trap('Employee_Payroll.pdf')
    flash('SECURITY EXCEPTION: Access denied. This incident has been logged and reported to the security administrators.', 'danger')
    return redirect(url_for('honeypot.index'))

@honeypot_bp.route('/Financial_Records.pdf')
@login_required
def financial_records():
    trigger_honeypot_trap('Financial_Records.pdf')
    flash('SECURITY EXCEPTION: Access denied. This incident has been logged and reported to the security administrators.', 'danger')
    return redirect(url_for('honeypot.index'))

@honeypot_bp.route('/CEO_Strategic_Plan.docx')
@login_required
def ceo_plan():
    trigger_honeypot_trap('CEO_Strategic_Plan.docx')
    flash('SECURITY EXCEPTION: Access denied. This incident has been logged and reported to the security administrators.', 'danger')
    return redirect(url_for('honeypot.index'))
