from flask import Blueprint, render_template, flash, redirect, url_for, Response, send_file
from flask_login import login_required, current_user
import csv
import io
from datetime import datetime, timedelta
import os

from app.extensions import db
from app.models import ActivityLog, Alert, User
from app.auth.decorators import admin_required

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/')
@login_required
@admin_required
def index():
    """Renders the reports center page."""
    return render_template('reports/reports.html')

@reports_bp.route('/export/csv')
@login_required
@admin_required
def export_csv():
    """Generates and downloads a CSV export of all security activity logs."""
    # Create string buffer
    si = io.StringIO()
    cw = csv.writer(si)
    
    # Write header
    cw.writerow([
        'Log ID', 'Timestamp', 'Username', 'User Role', 
        'Action Type', 'Status', 'IP Address', 
        'Device Fingerprint', 'Browser/Client Info', 
        'Target Resource', 'Behavior Risk Score'
    ])
    
    # Fetch all activity logs
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    
    # Write rows
    for log in logs:
        username = log.user.username if log.user else 'System'
        role = log.user.role if log.user else 'N/A'
        cw.writerow([
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            username,
            role,
            log.action,
            log.status,
            log.ip_address,
            log.device_fingerprint or '',
            log.browser_info or '',
            log.resource_accessed or '',
            log.risk_score
        ])
        
    response = Response(si.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=technova_security_audit_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    return response

@reports_bp.route('/export/pdf')
@login_required
@admin_required
def export_pdf():
    """Generates and downloads a structured PDF security report using ReportLab."""
    # Create byte buffer
    buffer = io.BytesIO()
    
    # Setup document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # Define custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0b0f19'), # Dark corporate background color
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#4facfe'), # Neon primary
        spaceAfter=30
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#0b0f19'),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#4b5563'),
        spaceAfter=10
    )
    
    bold_body = ParagraphStyle(
        'DocBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    # --- Header ---
    story.append(Paragraph("TECHNOVA SOLUTIONS", title_style))
    story.append(Paragraph(f"Zero Trust Security Platform — Weekly Security Report & Audit Summary", subtitle_style))
    story.append(Spacer(1, 10))
    
    # --- Platform Summary Statistics ---
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    unresolved_alerts = Alert.query.filter_by(is_resolved=False).count()
    total_logs = ActivityLog.query.count()
    
    story.append(Paragraph("1. Executive Security Metrics Summary", section_heading))
    story.append(Paragraph(
        f"This report summarizes security audit operations and dynamic trust posture evaluations. "
        f"The TechNova network directory comprises <strong>{total_users}</strong> registered users, "
        f"with <strong>{active_users}</strong> currently marked active by the PDP engine.",
        body_style
    ))
    
    # Summary Table
    summary_data = [
        [Paragraph('<b>Metric Detail</b>', bold_body), Paragraph('<b>Current Value</b>', bold_body), Paragraph('<b>Status Evaluation</b>', bold_body)],
        [Paragraph('Registered Employees', body_style), Paragraph(str(total_users), body_style), Paragraph('Standard baselines configured', body_style)],
        [Paragraph('Active Verified Accounts', body_style), Paragraph(str(active_users), body_style), Paragraph('Authentication enabled', body_style)],
        [Paragraph('Unresolved Security Alerts', body_style), Paragraph(str(unresolved_alerts), body_style), Paragraph('HIGH RISK - Actions required' if unresolved_alerts > 0 else 'All systems operational', body_style)],
        [Paragraph('Logged Security Events (Total)', body_style), Paragraph(str(total_logs), body_style), Paragraph('Audit trails complete', body_style)]
    ]
    
    t_summary = Table(summary_data, colWidths=[2.5*inch, 1.5*inch, 2.8*inch])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e5e7eb')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 20))
    
    # --- Alerts Summary ---
    story.append(Paragraph("2. Active Unresolved Security Exceptions", section_heading))
    active_alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.timestamp.desc()).limit(5).all()
    
    if active_alerts:
        alert_data = [
            [Paragraph('<b>Severity</b>', bold_body), Paragraph('<b>User</b>', bold_body), Paragraph('<b>Alert Type</b>', bold_body), Paragraph('<b>Description</b>', bold_body)]
        ]
        for alert in active_alerts:
            sev_color = '#ef4444' if alert.severity in ['high', 'critical'] else '#f59e0b'
            alert_data.append([
                Paragraph(f"<font color='{sev_color}'><b>{alert.severity.upper()}</b></font>", body_style),
                Paragraph(alert.user.username, body_style),
                Paragraph(alert.alert_type, body_style),
                Paragraph(alert.description, body_style)
            ])
            
        t_alerts = Table(alert_data, colWidths=[1.0*inch, 1.2*inch, 1.5*inch, 3.1*inch])
        t_alerts.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#fee2e2')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#fca5a5')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_alerts)
    else:
        story.append(Paragraph("✓ Clean Feed: No active unresolved security warnings detected in this period.", body_style))
        
    story.append(Spacer(1, 20))
    
    # --- Recent Activities Table ---
    story.append(Paragraph("3. Recent Access Audit Trail (Latest 10 Events)", section_heading))
    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    log_data = [
        [Paragraph('<b>Timestamp</b>', bold_body), Paragraph('<b>User</b>', bold_body), Paragraph('<b>Action</b>', bold_body), Paragraph('<b>Status</b>', bold_body), Paragraph('<b>Resource</b>', bold_body)]
    ]
    for log in recent_logs:
        username = log.user.username if log.user else 'System'
        status_color = '#22c55e' if log.status == 'SUCCESS' else '#ef4444'
        log_data.append([
            Paragraph(log.timestamp.strftime('%Y-%m-%d %H:%M'), body_style),
            Paragraph(username, body_style),
            Paragraph(log.action, body_style),
            Paragraph(f"<font color='{status_color}'><b>{log.status}</b></font>", body_style),
            Paragraph(log.resource_accessed or '-', body_style)
        ])
        
    t_logs = Table(log_data, colWidths=[1.4*inch, 1.2*inch, 1.3*inch, 1.0*inch, 1.9*inch])
    t_logs.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f3f4f6')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_logs)
    
    # --- Sign off Footer ---
    story.append(Spacer(1, 40))
    story.append(Paragraph(f"Report compiled on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC.", body_style))
    story.append(Paragraph("Authorizing Entity: TechNova Solutions Cybersecurity PDP Platform PEP Engine.", body_style))
    
    # Build document
    doc.build(story)
    
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"technova_security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf",
        mimetype='application/pdf'
    )
