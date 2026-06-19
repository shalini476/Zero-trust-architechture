from flask import Blueprint, render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import random

from app.extensions import db
from app.models import User, ActivityLog, Alert, HoneypotAccess, MLPrediction, Simulation
from app.auth.decorators import admin_required
from app.ml.trust_engine import adjust_trust_score
from app.ml.threat_engine import predict_threat_level
from app.ml.explainable_ai import generate_xai_explanations

simulation_bp = Blueprint('simulation', __name__)

@simulation_bp.route('/')
@login_required
@admin_required
def index():
    """Renders the threat simulation dashboard."""
    users = User.query.filter(User.role != 'admin').all()
    recent_simulations = Simulation.query.order_by(Simulation.timestamp.desc()).limit(10).all()
    return render_template('simulation/threat_simulator.html', users=users, simulations=recent_simulations)

@simulation_bp.route('/run', methods=['POST'])
@login_required
@admin_required
def run_simulation():
    """Handles triggering one of the simulated security attacks."""
    data = request.json or {}
    sim_type = data.get('type')
    target_id = data.get('target_user_id')
    
    if not sim_type or not target_id:
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400
        
    user = User.query.get(target_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'Target user not found'}), 404
        
    now = datetime.utcnow()
    ip_address = f"198.51.100.{random.randint(1, 254)}" # External/foreign IP address
    device_fp = f"SIM_FINGERPRINT_{random.randint(1000, 9999)}"
    
    result_details = {}
    
    try:
        # 1. BRUTE FORCE SIMULATION
        if sim_type == 'brute_force':
            # Generate 8 failed credential logins
            for i in range(8):
                log_time = now - timedelta(minutes=(8-i))
                log = ActivityLog(
                    user_id=user.id,
                    timestamp=log_time,
                    action='LOGIN_CREDENTIALS',
                    status='FAILED',
                    ip_address=ip_address,
                    device_fingerprint=device_fp,
                    browser_info='Chrome / Linux (Simulated Attack)'
                )
                db.session.add(log)
            
            # Deduct trust score and generate warning alerts
            adjust_trust_score(user, 'failed_login', ip_address=ip_address)
            
            # Evaluate with ML threat engine
            ml_res = predict_threat_level(
                login_hour=now.hour,
                failed_attempts_24h=8,
                is_new_device=1,
                is_unusual_time=1 if (now.hour < 8 or now.hour > 20) else 0,
                trust_score=user.trust_score,
                resource_access_frequency=0,
                honeypot_accessed=0
            )
            
            # Record ML prediction
            reasons = generate_xai_explanations(
                login_hour=now.hour,
                failed_attempts_24h=8,
                is_new_device=True,
                is_unusual_time=bool(now.hour < 8 or now.hour > 20),
                trust_score=user.trust_score,
                resource_access_frequency=0,
                honeypot_accessed=False
            )
            
            pred = MLPrediction(
                user_id=user.id,
                timestamp=now,
                behavioral_risk_score=ml_res['risk_score'],
                threat_classification=ml_res['classification'],
                final_security_score=100.0 - ml_res['risk_score']
            )
            pred.set_anomaly_reasons(reasons)
            db.session.add(pred)
            
            result_details = {
                'message': f"Brute force attack simulated on {user.username}. 8 failed logins injected.",
                'trust_score_after': user.trust_score,
                'ml_rating': ml_res['classification'].upper(),
                'reasons': reasons
            }

        # 2. CREDENTIAL THEFT SIMULATION
        elif sim_type == 'credential_theft':
            # Simulate a successful login but from high-risk context (unusual time + new device + foreign IP)
            log = ActivityLog(
                user_id=user.id,
                timestamp=now,
                action='LOGIN_SUCCESS',
                status='SUCCESS',
                ip_address=ip_address,
                device_fingerprint=device_fp,
                browser_info='Safari / macOS (Simulated Intruder)',
                risk_score=75.0
            )
            db.session.add(log)
            
            # Trust score penalties
            adjust_trust_score(user, 'new_device', ip_address=ip_address)
            adjust_trust_score(user, 'unusual_time', ip_address=ip_address)
            
            # Run ML
            ml_res = predict_threat_level(
                login_hour=3, # Midnight hour simulation
                failed_attempts_24h=0,
                is_new_device=1,
                is_unusual_time=1,
                trust_score=user.trust_score,
                resource_access_frequency=2,
                honeypot_accessed=0
            )
            
            reasons = generate_xai_explanations(
                login_hour=3,
                failed_attempts_24h=0,
                is_new_device=True,
                is_unusual_time=True,
                trust_score=user.trust_score,
                resource_access_frequency=2,
                honeypot_accessed=False
            )
            
            pred = MLPrediction(
                user_id=user.id,
                timestamp=now,
                behavioral_risk_score=ml_res['risk_score'],
                threat_classification=ml_res['classification'],
                final_security_score=100.0 - ml_res['risk_score']
            )
            pred.set_anomaly_reasons(reasons)
            db.session.add(pred)
            
            result_details = {
                'message': f"Credential theft simulated on {user.username}. Login from unknown device at midnight logged.",
                'trust_score_after': user.trust_score,
                'ml_rating': ml_res['classification'].upper(),
                'reasons': reasons
            }

        # 3. INSIDER THREAT SIMULATION
        elif sim_type == 'insider_threat':
            # Simulate rapid access to safe files (12 hits in 5 minutes)
            for i in range(12):
                log_time = now - timedelta(seconds=(12-i)*10)
                log = ActivityLog(
                    user_id=user.id,
                    timestamp=log_time,
                    action='FILE_ACCESS',
                    status='SUCCESS',
                    ip_address='192.168.1.15',
                    resource_accessed=f"Shared_Document_{i}.pdf",
                    risk_score=15.0
                )
                db.session.add(log)
                
            # Trigger insider threat deduction
            adjust_trust_score(
                user=user, 
                event='insider_threat', 
                ip_address='192.168.1.15', 
                detail="Excessive file access simulation (12 requests in 2 minutes)"
            )
            
            # Evaluate with ML
            ml_res = predict_threat_level(
                login_hour=now.hour,
                failed_attempts_24h=0,
                is_new_device=0,
                is_unusual_time=0,
                trust_score=user.trust_score,
                resource_access_frequency=12,
                honeypot_accessed=0
            )
            
            reasons = generate_xai_explanations(
                login_hour=now.hour,
                failed_attempts_24h=0,
                is_new_device=False,
                is_unusual_time=False,
                trust_score=user.trust_score,
                resource_access_frequency=12,
                honeypot_accessed=False
            )
            
            pred = MLPrediction(
                user_id=user.id,
                timestamp=now,
                behavioral_risk_score=ml_res['risk_score'],
                threat_classification=ml_res['classification'],
                final_security_score=100.0 - ml_res['risk_score']
            )
            pred.set_anomaly_reasons(reasons)
            db.session.add(pred)
            
            result_details = {
                'message': f"Insider threat simulated on {user.username}. 12 rapid file downloads injected.",
                'trust_score_after': user.trust_score,
                'ml_rating': ml_res['classification'].upper(),
                'reasons': reasons
            }

        # 4. HONEYPOT ACCESS SIMULATION
        elif sim_type == 'honeypot_access':
            # Log honeypot intrusion
            access = HoneypotAccess(
                user_id=user.id,
                resource_name='Employee_Payroll.pdf',
                timestamp=now,
                ip_address=ip_address
            )
            db.session.add(access)
            
            log = ActivityLog(
                user_id=user.id,
                timestamp=now,
                action='HONEYPOT_TRIGGER',
                status='BLOCKED',
                ip_address=ip_address,
                resource_accessed='Employee_Payroll.pdf',
                risk_score=100.0
            )
            db.session.add(log)
            
            # Penalize
            adjust_trust_score(
                user=user, 
                event='honeypot_access', 
                ip_address=ip_address, 
                detail='Employee_Payroll.pdf'
            )
            
            # Evaluate with ML
            ml_res = predict_threat_level(
                login_hour=now.hour,
                failed_attempts_24h=0,
                is_new_device=1,
                is_unusual_time=0,
                trust_score=user.trust_score,
                resource_access_frequency=1,
                honeypot_accessed=1
            )
            
            reasons = generate_xai_explanations(
                login_hour=now.hour,
                failed_attempts_24h=0,
                is_new_device=True,
                is_unusual_time=False,
                trust_score=user.trust_score,
                resource_access_frequency=1,
                honeypot_accessed=True
            )
            
            pred = MLPrediction(
                user_id=user.id,
                timestamp=now,
                behavioral_risk_score=ml_res['risk_score'],
                threat_classification=ml_res['classification'],
                final_security_score=100.0 - ml_res['risk_score']
            )
            pred.set_anomaly_reasons(reasons)
            db.session.add(pred)
            
            result_details = {
                'message': f"Honeypot resource trap triggered for {user.username}. Accessed Employee_Payroll.pdf.",
                'trust_score_after': user.trust_score,
                'ml_rating': ml_res['classification'].upper(),
                'reasons': reasons
            }
            
        else:
            return jsonify({'status': 'error', 'message': 'Unknown simulation type'}), 400
            
        # Log the simulation event
        sim_log = Simulation(
            admin_id=current_user.id,
            simulation_type=sim_type,
            target_user_id=user.id,
            timestamp=now
        )
        sim_log.set_result(result_details)
        db.session.add(sim_log)
        
        db.session.commit()
        return jsonify({'status': 'success', 'details': result_details})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
