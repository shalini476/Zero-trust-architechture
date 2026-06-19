import os
from flask import Flask
from flask_session import Session
from app.config import Config
from app.extensions import db, login_manager, mail

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Configure session to use the existing db instance
    app.config['SESSION_SQLALCHEMY'] = db
    
    # Initialize server-side session
    Session(app)
    
    # Import routes/blueprints inside factory to avoid circular imports
    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.monitoring.routes import monitoring_bp
    from app.simulation.routes import simulation_bp
    from app.reports.routes import reports_bp
    from app.honeypot.routes import honeypot_bp
    from app.api.routes import api_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(monitoring_bp, url_prefix='/monitoring')
    app.register_blueprint(simulation_bp, url_prefix='/simulation')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(honeypot_bp, url_prefix='/honeypot')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Redirect root to login or dashboard
    from flask import redirect, url_for
    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))
        
    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def page_not_found(e):
        from flask import render_template
        return render_template('errors/404.html'), 404
        
    @app.context_processor
    def inject_now():
        from datetime import datetime
        return {'now': datetime.utcnow()}
        
    # Create DB tables inside context if they don't exist
    with app.app_context():
        db.create_all()
        seed_database()
        
    return app

def seed_database():
    from app.models import User, ActivityLog, Alert, BehaviorProfile, MLPrediction
    
    # Check if database is already seeded
    if User.query.first() is None:
        print("[DATABASE SEED] Seeding initial employee security directory...")
        
        # Create baseline employee accounts
        admin = User(username='admin', email='vigneshdhandapani2023@gmail.com', role='admin', security_question="What was your first pet's name?")
        admin.set_password('password123')
        admin.set_security_answer('fluffy')
        
        alice = User(username='alice', email='alice@zerofox.com', role='hr', security_question="In what city were you born?")
        alice.set_password('password123')
        alice.set_security_answer('new york')
        
        bob = User(username='bob', email='bob@zerofox.com', role='finance', security_question="What is your mother's maiden name?")
        bob.set_password('password123')
        bob.set_security_answer('smith')
        
        charlie = User(username='charlie', email='charlie@zerofox.com', role='employee', security_question="What was the name of your first school?")
        charlie.set_password('password123')
        charlie.set_security_answer('lincoln')
        
        db.session.add_all([admin, alice, bob, charlie])
        db.session.commit()
        
        # Generate user behavior baselines (UBA profiles)
        for u in [admin, alice, bob, charlie]:
            profile = BehaviorProfile(user_id=u.id)
            profile.set_usual_login_hours([9, 10, 11, 14, 15, 16])
            profile.set_common_devices(['DEV_DEV_5A3B8C'])
            profile.set_common_resources(['Employee_Handbook.pdf'])
            profile.avg_daily_logins = 3.0
            db.session.add(profile)
        db.session.commit()
        
        # Generate some mock activity logs (last 3 days)
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        
        logs = [
            ActivityLog(user_id=charlie.id, timestamp=now - timedelta(days=2), action='LOGIN_SUCCESS', status='SUCCESS', ip_address='192.168.1.15', device_fingerprint='DEV_DEV_5A3B8C', risk_score=10.0),
            ActivityLog(user_id=charlie.id, timestamp=now - timedelta(days=2), action='FILE_ACCESS', status='SUCCESS', ip_address='192.168.1.15', resource_accessed='Employee_Handbook.pdf', risk_score=5.0),
            ActivityLog(user_id=bob.id, timestamp=now - timedelta(days=1), action='LOGIN_SUCCESS', status='SUCCESS', ip_address='192.168.1.22', device_fingerprint='DEV_DEV_92A1B2', risk_score=12.0),
            ActivityLog(user_id=alice.id, timestamp=now - timedelta(hours=4), action='LOGIN_SUCCESS', status='SUCCESS', ip_address='192.168.1.10', device_fingerprint='DEV_DEV_E53D8F', risk_score=15.0),
            
            # Simulated Failed Login logs
            ActivityLog(user_id=charlie.id, timestamp=now - timedelta(hours=2), action='LOGIN_CREDENTIALS', status='FAILED', ip_address='203.0.113.5', risk_score=45.0),
            ActivityLog(user_id=charlie.id, timestamp=now - timedelta(hours=1, minutes=58), action='LOGIN_CREDENTIALS', status='FAILED', ip_address='203.0.113.5', risk_score=50.0),
        ]
        db.session.add_all(logs)
        db.session.commit()
        
        # Seed mock alerts (1 resolved, 1 active)
        alerts = [
            Alert(user_id=charlie.id, timestamp=now - timedelta(hours=2), alert_type='FAILED_LOGIN', severity='medium', description='Multiple failed login attempts from IP 203.0.113.5', is_resolved=False),
            Alert(user_id=bob.id, timestamp=now - timedelta(days=3), alert_type='NEW_DEVICE', severity='low', description='User logged in using unrecognized browser (Firefox) from IP 192.168.1.22', is_resolved=True, resolved_by=admin.id),
        ]
        db.session.add_all(alerts)
        db.session.commit()
        
        # Seed ML Prediction summaries
        preds = [
            MLPrediction(user_id=charlie.id, timestamp=now - timedelta(days=2), behavioral_risk_score=10.0, threat_classification='normal', anomaly_reasons='[]', final_security_score=96.0),
            MLPrediction(user_id=bob.id, timestamp=now - timedelta(days=1), behavioral_risk_score=15.0, threat_classification='normal', anomaly_reasons='[]', final_security_score=94.0),
            MLPrediction(user_id=alice.id, timestamp=now - timedelta(hours=4), behavioral_risk_score=12.0, threat_classification='normal', anomaly_reasons='[]', final_security_score=95.0),
        ]
        db.session.add_all(preds)
        db.session.commit()
        
        print("[DATABASE SEED] Seeding complete.")

