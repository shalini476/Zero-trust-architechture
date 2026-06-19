from flask import Blueprint, render_template, redirect, url_for, flash, request, session, Response
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import secrets
from flask_mail import Message
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import io
import random
import string

from app.extensions import db, mail
from app.models import User, OTPRecord, ActivityLog, KnownDevice
from app.auth.forms import LoginForm, RegisterForm, OTPForm, SecurityQuestionForm
from app.ml.behavior_analyzer import analyze_user_behavior, update_user_baseline
from app.ml.trust_engine import adjust_trust_score

auth_bp = Blueprint('auth', __name__)

def generate_otp(user):
    """Generates a secure 6-digit OTP, saves it to the database, and returns it."""
    # Deactivate existing OTPs for the user
    OTPRecord.query.filter_by(user_id=user.id, is_used=False).update({'is_used': True})
    
    otp_code = f"{secrets.randbelow(900000) + 100000}" # 6-digit numeric OTP
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    
    otp_record = OTPRecord(
        user_id=user.id,
        otp_code=otp_code,
        expires_at=expires_at,
        is_used=False,
        attempts=0
    )
    db.session.add(otp_record)
    db.session.commit()
    return otp_code

def send_otp_email(user, otp_code, email_address=None):
    """Sends OTP exclusively via Flask-Mail. Returns True on success, False on failure."""
    target_email = email_address or user.email
    subject = "Zerofox Security - One-Time Verification Code"
    body = f"""Hello {user.username},

Your security verification code is: {otp_code}

This code was requested for a login attempt to your Zerofox account.
It will expire in 5 minutes and can only be used once.

If you did not request this, please change your password and contact security immediately.

Regards,
Zerofox Security Team
"""
    from flask import current_app
    smtp_configured = current_app.config.get('MAIL_USERNAME') and current_app.config.get('MAIL_PASSWORD')
    
    if not smtp_configured:
        print(f"\n[ERROR] SMTP not configured. Cannot send OTP to {target_email}. "
              f"Please set MAIL_USERNAME and MAIL_PASSWORD in your .env file.")
        return False
    
    try:
        msg = Message(
            subject=subject,
            recipients=[target_email],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"\n[ERROR] SMTP Mail failed to send to {target_email}. Exception: {e}")
        return False

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
        
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            security_question=form.security_question.data,
            backup_email=form.backup_email.data if form.backup_email.data else None
        )
        user.set_password(form.password.data)
        user.set_security_answer(form.security_answer.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Initialize behavior baseline
        update_user_baseline(user, request.remote_addr, 'INITIAL_REGISTRATION')
        
        flash('Account registered successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        # CAPTCHA validation check
        captcha_input = form.captcha.data.strip().upper()
        captcha_correct = session.get('captcha_text', '').strip().upper()
        session.pop('captcha_text', None) # Clear immediately
        
        if captcha_input != captcha_correct:
            flash('Invalid CAPTCHA code. Please try again.', 'danger')
            return render_template('auth/login.html', form=form)

        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated by security administrators.', 'danger')
                return redirect(url_for('auth.login'))
                
            # Log successful Step-1 credential verification
            activity = ActivityLog(
                user_id=user.id,
                action='LOGIN_STEP1',
                status='SUCCESS',
                ip_address=request.remote_addr,
                browser_info=request.headers.get('User-Agent', '')
            )
            db.session.add(activity)
            db.session.commit()
            
            # Step 1 Complete: Save state in session and generate OTP
            session['pre_otp_user_id'] = user.id
            otp_code = generate_otp(user)
            
            # Send OTP exclusively via email
            sent_via_email = send_otp_email(user, otp_code)
            if sent_via_email:
                flash('A 6-digit security code has been sent to your registered email address.', 'info')
            else:
                # Email delivery failed — do not proceed to OTP page
                flash('Security verification code could not be sent. Please ensure the administrator has configured the SMTP email server.', 'danger')
                session.pop('pre_otp_user_id', None)
                return redirect(url_for('auth.login'))
                
            # Store device fingerprint info passed from frontend
            session['login_fingerprint'] = request.form.get('device_fingerprint', 'unknown_fingerprint')
            session['login_browser'] = request.form.get('browser_name', 'unknown_browser')
            
            return redirect(url_for('auth.verify_otp'))
            
        else:
            # Login failed
            if user:
                # Deduct trust score and log failed attempt
                adjust_trust_score(user, 'failed_login', ip_address=request.remote_addr)
            
            # General audit logging of failed attempt
            dummy_id = user.id if user else 0
            activity = ActivityLog(
                user_id=dummy_id,
                action='LOGIN_CREDENTIALS',
                status='FAILED',
                ip_address=request.remote_addr,
                browser_info=request.headers.get('User-Agent', '')
            )
            db.session.add(activity)
            db.session.commit()
            
            flash('Invalid username or password.', 'danger')
            
    return render_template('auth/login.html', form=form)

@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('pre_otp_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
        
    user = User.query.get(user_id)
    form = OTPForm()
    
    if form.validate_on_submit():
        otp_record = OTPRecord.query.filter_by(
            user_id=user.id, 
            otp_code=form.otp_code.data, 
            is_used=False
        ).first()
        
        if otp_record:
            # Check expiry
            if datetime.utcnow() > otp_record.expires_at:
                new_otp = generate_otp(user)
                resent = send_otp_email(user, new_otp)
                if resent:
                    flash('The verification code has expired. A new code has been sent to your email.', 'warning')
                else:
                    flash('The verification code has expired and a new code could not be sent. Please check SMTP configuration.', 'danger')
                    session.pop('pre_otp_user_id', None)
                    return redirect(url_for('auth.login'))
                return redirect(url_for('auth.verify_otp'))
                
            # Mark OTP as used
            otp_record.is_used = True
            db.session.commit()
            
            # Log OTP verification success
            log = ActivityLog(
                user_id=user.id,
                action='OTP_VERIFY',
                status='SUCCESS',
                ip_address=request.remote_addr,
                device_fingerprint=session.get('login_fingerprint'),
                browser_info=session.get('login_browser')
            )
            db.session.add(log)
            db.session.commit()
            
            # Run User Behavior Analytics (UBA)
            uba_results = analyze_user_behavior(
                user=user,
                ip_address=request.remote_addr,
                device_fingerprint=session.get('login_fingerprint', 'unknown_fingerprint'),
                browser_info=session.get('login_browser', 'unknown_browser')
            )
            
            # Save risk details
            session['behavioral_risk_score'] = uba_results['risk_score']
            session['risk_level'] = uba_results['risk_level']
            session['risk_reasons'] = uba_results['reasons']
            
            # Check if trust score is too low or behavior risk is high/medium
            trust_score = user.trust_score
            
            # Decide access flow:
            # Low Risk: trust_score >= 80 and risk_level == 'normal' -> Grant access directly
            if trust_score >= 80 and uba_results['risk_level'] == 'normal':
                # Register new device if not seen
                device_fp = session.get('login_fingerprint', 'unknown_fingerprint')
                existing_device = KnownDevice.query.filter_by(user_id=user.id, device_fingerprint=device_fp).first()
                if not existing_device:
                    new_device = KnownDevice(
                        user_id=user.id,
                        device_fingerprint=device_fp,
                        browser=session.get('login_browser', 'unknown_browser')
                    )
                    db.session.add(new_device)
                
                # Update trust score (+5 for successful login)
                adjust_trust_score(user, 'success_login', ip_address=request.remote_addr)
                
                # Update user behavior baseline
                update_user_baseline(user, request.remote_addr, device_fp)
                
                # Update last login time
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                # Clean session keys
                session.pop('pre_otp_user_id', None)
                
                login_user(user)
                flash(f'Welcome back, {user.username}! Access granted.', 'success')
                return redirect(url_for('dashboard.index'))
            else:
                # Medium/High Risk or Low Trust score: Trigger Adaptive Two-Step Verification
                session['adaptive_user_id'] = user.id
                session.pop('pre_otp_user_id', None)
                
                # Deduct trust score for anomalies
                if uba_results['risk_level'] == 'high_risk':
                    adjust_trust_score(user, 'ml_high_risk', ip_address=request.remote_addr, detail=", ".join(uba_results['reasons']))
                elif 'Login attempt from a new unrecognized device' in uba_results['reasons']:
                    adjust_trust_score(user, 'new_device', ip_address=request.remote_addr)
                elif 'Login outside standard working hours' in uba_results['reasons'] or 'Login outside standard working hours (Midnight/Off-hours)' in uba_results['reasons']:
                    adjust_trust_score(user, 'unusual_time', ip_address=request.remote_addr)
                
                flash('Suspicious behavior or unrecognized login context detected. Step-up security verification required.', 'warning')
                return redirect(url_for('auth.adaptive_verify'))
        else:
            # Invalid OTP
            # Get current active OTP for counting attempts
            active_otp = OTPRecord.query.filter_by(user_id=user.id, is_used=False).first()
            attempts = 1
            if active_otp:
                active_otp.attempts += 1
                attempts = active_otp.attempts
                if active_otp.attempts >= 3:
                    active_otp.is_used = True # Expire it
                    db.session.commit()
                    session.pop('pre_otp_user_id', None)
                    flash('Maximum verification attempts exceeded. Please try logging in again.', 'danger')
                    return redirect(url_for('auth.login'))
                db.session.commit()
                
            adjust_trust_score(user, 'otp_failed')
            flash(f'Invalid verification code. Attempt {attempts} of 3.', 'danger')
            
    return render_template('auth/otp_verify.html', form=form, user=user)

@auth_bp.route('/adaptive-verify', methods=['GET', 'POST'])
def adaptive_verify():
    user_id = session.get('adaptive_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
        
    user = User.query.get(user_id)
    form = SecurityQuestionForm()
    
    if form.validate_on_submit():
        if user.check_security_answer(form.security_answer.data):
            # Log success
            log = ActivityLog(
                user_id=user.id,
                action='ADAPTIVE_VERIFY',
                status='SUCCESS',
                ip_address=request.remote_addr,
                device_fingerprint=session.get('login_fingerprint'),
                browser_info=session.get('login_browser')
            )
            db.session.add(log)
            
            # Register device
            device_fp = session.get('login_fingerprint', 'unknown_fingerprint')
            existing_device = KnownDevice.query.filter_by(user_id=user.id, device_fingerprint=device_fp).first()
            if not existing_device:
                new_device = KnownDevice(
                    user_id=user.id,
                    device_fingerprint=device_fp,
                    browser=session.get('login_browser', 'unknown_browser')
                )
                db.session.add(new_device)
                
            # Log successful login and add trust score (+5)
            adjust_trust_score(user, 'success_login', ip_address=request.remote_addr)
            update_user_baseline(user, request.remote_addr, device_fp)
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Clean session keys
            session.pop('adaptive_user_id', None)
            
            login_user(user)
            flash('Identity verified successfully. Access granted.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            # Failed answer
            adjust_trust_score(user, 'failed_login', ip_address=request.remote_addr)
            
            log = ActivityLog(
                user_id=user.id,
                action='ADAPTIVE_VERIFY',
                status='FAILED',
                ip_address=request.remote_addr,
                device_fingerprint=session.get('login_fingerprint')
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Incorrect security answer. Access blocked.', 'danger')
            return redirect(url_for('auth.login'))
            
    return render_template('auth/adaptive_verify.html', form=form, user=user)

@auth_bp.route('/captcha.png')
def captcha():
    """Generates a dynamic CAPTCHA image with noise lines and background dots."""
    # Generate 5 random alphanumeric characters
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    session['captcha_text'] = captcha_text
    
    # Create background image
    width, height = 160, 60
    image = Image.new('RGB', (width, height), color=(11, 15, 25))
    draw = ImageDraw.Draw(image)
    
    # Add random pixel noise
    for _ in range(500):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(50, 150), random.randint(50, 150), random.randint(50, 255)))
        
    # Add random lines noise
    for _ in range(4):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line((x1, y1, x2, y2), fill=(random.randint(50, 180), random.randint(50, 180), random.randint(50, 255)), width=1)
        
    # Draw string with spacing
    font = None
    try:
        font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
    except Exception:
        font = ImageFont.load_default()
        
    for i, char in enumerate(captcha_text):
        x = 18 + i * 26 + random.randint(-3, 3)
        y = 12 + random.randint(-4, 4)
        # Select bright cybersecurity neon coloring
        color = random.choice([(0, 242, 254), (79, 172, 254), (0, 230, 118)])
        draw.text((x, y), char, fill=color, font=font)
        
    # Smooth to slightly blur noise
    image = image.filter(ImageFilter.SMOOTH)
    
    # Output to PNG stream
    buf = io.BytesIO()
    image.save(buf, 'PNG')
    buf.seek(0)
    
    return Response(buf.read(), mimetype='image/png')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
