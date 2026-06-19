"""
Zero Trust Security Platform — ML Blueprint Routes
TechNova Solutions

Provides web views and JSON endpoints for the Machine Learning sub-system:
  - ML model status overview
  - On-demand behavioral predictions
  - Admin trust restoration
  - Model reload endpoint

Blueprint: 'ml'  (registered in app/__init__.py with url_prefix='/ml', name='ml')
"""

from datetime import datetime, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from functools import wraps

from app.extensions import db
from app.models import User
from app.ml.threat_engine import threat_engine

# Blueprint — app/__init__.py imports this as 'ml_bp' and registers with name='ml'
ml_bp = Blueprint('ml_bp', __name__)


# ── Local RBAC guard ───────────────────────────────────────────────────────────

def _admin_required(f):
    """Simple admin guard for ML routes (avoids circular import with decorators.py)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Administrator access required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


# ── ML Model Status ────────────────────────────────────────────────────────────

@ml_bp.route('/')
@ml_bp.route('/status')
@login_required
@_admin_required
def ml_status():
    """
    Display ML model status: whether models are loaded, file sizes,
    and training instructions if models are missing.
    """
    from pathlib import Path
    MODEL_DIR = Path(__file__).resolve().parent.parent.parent / 'ml_models'

    iso_path = MODEL_DIR / 'isolation_forest.pkl'
    rf_path = MODEL_DIR / 'random_forest.pkl'
    scaler_path = MODEL_DIR / 'scaler.pkl'

    def _size(p):
        return f'{p.stat().st_size / 1024:.1f} KB' if p.exists() else 'N/A'

    model_info = {
        'models_loaded': threat_engine.models_loaded,
        'model_dir': str(MODEL_DIR),
        'isolation_forest_exists': iso_path.exists(),
        'random_forest_exists': rf_path.exists(),
        'scaler_exists': scaler_path.exists(),
        'iso_size': _size(iso_path),
        'rf_size': _size(rf_path),
        'scaler_size': _size(scaler_path),
    }

    # Gather per-user predictions for the status table
    users = User.query.filter(User.role != 'admin').all()
    user_predictions = []
    now_hour = datetime.now(timezone.utc).hour
    for u in users:
        pred = threat_engine.predict(u, login_hour=now_hour, is_new_device=0)
        user_predictions.append({
            'user': u,
            'classification': pred.get('classification', 'unknown'),
            'ml_risk_score': pred.get('ml_risk_score', 0),
            'method': pred.get('method', 'heuristic'),
        })

    return render_template(
        'ml/status.html',
        title='ML Model Status',
        model_info=model_info,
        user_predictions=user_predictions,
    )


# ── On-Demand Prediction (JSON) ────────────────────────────────────────────────

@ml_bp.route('/predict/<int:user_id>')
@login_required
def predict_user(user_id: int):
    """
    Run an ML prediction for a user and return JSON.
    Non-admins may only query their own data.
    """
    if current_user.role != 'admin' and current_user.id != user_id:
        return jsonify({'error': 'Forbidden'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    login_hour = request.args.get('hour', datetime.now(timezone.utc).hour, type=int)
    is_new_device = request.args.get('new_device', 0, type=int)

    result = threat_engine.predict(
        user=user,
        login_hour=login_hour,
        is_new_device=is_new_device,
        resource_count=0,
        honeypot_flag=0,
    )

    return jsonify({
        'user_id': user_id,
        'username': user.username,
        'trust_score': user.trust_score,
        **result,
    })


# ── Model Reload ───────────────────────────────────────────────────────────────

@ml_bp.route('/reload', methods=['POST'])
@login_required
@_admin_required
def reload_models():
    """Force-reload ML model artefacts from disk (useful after retraining)."""
    threat_engine._load_models()
    return jsonify({
        'success': True,
        'models_loaded': threat_engine.models_loaded,
        'message': (
            'Models successfully reloaded from disk.' if threat_engine.models_loaded
            else 'Model files not found. Run python app/ml/train_model.py first.'
        ),
    })


# ── Admin Trust Restoration ────────────────────────────────────────────────────

@ml_bp.route('/restore-trust/<int:user_id>', methods=['POST'])
@login_required
@_admin_required
def restore_trust(user_id: int):
    """Admin action: apply a +20 trust boost to a flagged user."""
    from app.trust_engine import trust_engine as te
    user = User.query.get_or_404(user_id)
    new_score = te.apply_trust_event(user, 'security_review',
                                     detail='Trust restored by admin.')
    flash(
        f'Trust score restored for {user.username}. New score: {new_score}/100',
        'success',
    )
    return redirect(request.referrer or url_for('ml_bp.ml_status'))
