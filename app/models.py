import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.extensions import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='employee', nullable=False) # admin, hr, finance, employee
    trust_score = db.Column(db.Integer, default=100, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Adaptive Verification Parameters
    security_question = db.Column(db.Text, nullable=False)
    security_answer_hash = db.Column(db.String(256), nullable=False)
    backup_email = db.Column(db.String(120), nullable=True)
    
    # Relationships
    otp_records = db.relationship('OTPRecord', backref='user', lazy=True, cascade="all, delete-orphan")
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True, cascade="all, delete-orphan")
    behavior_profile = db.relationship('BehaviorProfile', backref='user', uselist=False, lazy=True, cascade="all, delete-orphan")
    alerts = db.relationship('Alert', foreign_keys='Alert.user_id', backref='user', lazy=True, cascade="all, delete-orphan")
    known_devices = db.relationship('KnownDevice', backref='user', lazy=True, cascade="all, delete-orphan")
    honeypot_accesses = db.relationship('HoneypotAccess', backref='user', lazy=True, cascade="all, delete-orphan")
    ml_predictions = db.relationship('MLPrediction', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def set_security_answer(self, answer):
        # Normalize to ignore casing/whitespaces
        normalized = "".join(answer.lower().split())
        self.security_answer_hash = generate_password_hash(normalized)
        
    def check_security_answer(self, answer):
        normalized = "".join(answer.lower().split())
        return check_password_hash(self.security_answer_hash, normalized)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'trust_score': self.trust_score,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class OTPRecord(db.Model):
    __tablename__ = 'otp_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(100), nullable=False) # LOGIN_ATTEMPT, FILE_ACCESS, OTP_VERIFY, etc.
    status = db.Column(db.String(20), nullable=False) # SUCCESS, FAILED, BLOCKED
    ip_address = db.Column(db.String(45), nullable=False)
    device_fingerprint = db.Column(db.String(256), nullable=True)
    browser_info = db.Column(db.String(256), nullable=True)
    location = db.Column(db.String(100), default='Unknown')
    resource_accessed = db.Column(db.String(200), nullable=True)
    risk_score = db.Column(db.Float, default=0.0)


class BehaviorProfile(db.Model):
    __tablename__ = 'behavior_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    usual_login_hours = db.Column(db.Text, default='[]') # Saved as JSON string (list of hours)
    avg_daily_logins = db.Column(db.Float, default=0.0)
    common_devices = db.Column(db.Text, default='[]') # Saved as JSON string (list of fingerprints)
    common_resources = db.Column(db.Text, default='[]') # Saved as JSON string (list of resources)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_usual_login_hours(self, hours_list):
        self.usual_login_hours = json.dumps(hours_list)

    def get_usual_login_hours(self):
        try:
            return json.loads(self.usual_login_hours)
        except Exception:
            return []

    def set_common_devices(self, devices_list):
        self.common_devices = json.dumps(devices_list)

    def get_common_devices(self):
        try:
            return json.loads(self.common_devices)
        except Exception:
            return []

    def set_common_resources(self, resources_list):
        self.common_resources = json.dumps(resources_list)

    def get_common_resources(self):
        try:
            return json.loads(self.common_resources)
        except Exception:
            return []


class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(100), nullable=False) # e.g. BRUTE_FORCE, HONEYPOT_ACCESS, OUT_OF_HOURS, COMPROMISED_DEVICE
    severity = db.Column(db.String(20), default='medium', nullable=False) # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    is_resolved = db.Column(db.Boolean, default=False, nullable=False)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Resolve relationship
    resolver = db.relationship('User', foreign_keys=[resolved_by])


class KnownDevice(db.Model):
    __tablename__ = 'known_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    device_fingerprint = db.Column(db.String(256), nullable=False)
    browser = db.Column(db.String(100), nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_trusted = db.Column(db.Boolean, default=True, nullable=False)


class HoneypotAccess(db.Model):
    __tablename__ = 'honeypot_accesses'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    resource_name = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)


class MLPrediction(db.Model):
    __tablename__ = 'ml_predictions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    behavioral_risk_score = db.Column(db.Float, default=0.0) # 0 to 100
    threat_classification = db.Column(db.String(20), default='normal') # normal, suspicious, high_risk
    anomaly_reasons = db.Column(db.Text, default='[]') # Saved as JSON string list of explanations
    final_security_score = db.Column(db.Float, default=100.0) # Evaluated composite score

    def set_anomaly_reasons(self, reasons):
        self.anomaly_reasons = json.dumps(reasons)

    def get_anomaly_reasons(self):
        try:
            return json.loads(self.anomaly_reasons)
        except Exception:
            return []


class WFHLoginHistory(db.Model):
    """
    Per-login WFH telemetry record.
    Created by evaluate_login_security() on every successful login.
    Stores real geolocation coordinates so impossible travel can be
    detected by computing haversine distance between successive records.
    """
    __tablename__ = 'wfh_login_history'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address   = db.Column(db.String(45), nullable=False)
    latitude     = db.Column(db.Float, nullable=True)
    longitude    = db.Column(db.Float, nullable=True)
    city         = db.Column(db.String(100), default='Unknown')
    region       = db.Column(db.String(100), default='')
    country      = db.Column(db.String(100), default='Unknown')
    country_code = db.Column(db.String(10), default='XX')
    timezone     = db.Column(db.String(80), default='UTC')
    isp          = db.Column(db.String(200), default='Unknown')
    is_vpn       = db.Column(db.Boolean, default=False, nullable=False)
    is_proxy     = db.Column(db.Boolean, default=False, nullable=False)
    is_hosting   = db.Column(db.Boolean, default=False, nullable=False)
    risk_score   = db.Column(db.Float, default=0.0)
    flags        = db.Column(db.Text, default='[]')   # JSON list of flag strings

    def set_flags(self, flags_list):
        import json
        self.flags = json.dumps(flags_list)

    def get_flags(self):
        import json
        try:
            return json.loads(self.flags)
        except Exception:
            return []


class Simulation(db.Model):
    __tablename__ = 'simulations'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    simulation_type = db.Column(db.String(100), nullable=False) # brute_force, compromised_device, insider_threat, honeypot_access
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.Column(db.Text, default='{}') # JSON details of simulated outcome

    def set_result(self, res_dict):
        self.result = json.dumps(res_dict)

    def get_result(self):
        try:
            return json.loads(self.result)
        except Exception:
            return {}
