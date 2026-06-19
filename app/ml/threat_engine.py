import os
import numpy as np
import joblib

# Load models and scaler lazily
_scaler = None
_rf_model = None
_iso_forest = None

def _load_models():
    global _scaler, _rf_model, _iso_forest
    if _scaler is None or _rf_model is None or _iso_forest is None:
        # Resolve path relative to this file
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        models_dir = os.path.join(base_dir, 'ml_models')
        
        scaler_path = os.path.join(models_dir, 'scaler.pkl')
        rf_path = os.path.join(models_dir, 'random_forest.pkl')
        iso_path = os.path.join(models_dir, 'isolation_forest.pkl')
        
        if not (os.path.exists(scaler_path) and os.path.exists(rf_path) and os.path.exists(iso_path)):
            raise FileNotFoundError("Machine Learning models are not trained yet. Run train_model.py first.")
            
        _scaler = joblib.load(scaler_path)
        _rf_model = joblib.load(rf_path)
        _iso_forest = joblib.load(iso_path)

def predict_threat_level(login_hour, failed_attempts_24h, is_new_device, is_unusual_time, trust_score, resource_access_frequency, honeypot_accessed):
    """
    Predicts threat classification and anomaly status using the trained ML models.
    Returns:
        dict: {
            'classification': 'normal' | 'suspicious' | 'high_risk',
            'classification_code': 0 | 1 | 2,
            'probabilities': [prob_normal, prob_suspicious, prob_high_risk],
            'is_anomaly': bool (from Isolation Forest),
            'risk_score': float (0-100 derived from probabilities)
        }
    """
    _load_models()
    
    # 1. Prepare feature vector (must match training feature order)
    features = np.array([[
        login_hour,
        failed_attempts_24h,
        is_new_device,
        is_unusual_time,
        trust_score,
        resource_access_frequency,
        honeypot_accessed
    ]])
    
    # 2. Scale features for Random Forest
    features_scaled = _scaler.transform(features)
    
    # 3. Supervised Classification (Random Forest)
    class_code = int(_rf_model.predict(features_scaled)[0])
    probs = _rf_model.predict_proba(features_scaled)[0].tolist()
    
    # 4. Unsupervised Anomaly Detection (Isolation Forest)
    # Isolation Forest predict returns 1 for inliers, -1 for outliers
    iso_pred = _iso_forest.predict(features)[0]
    is_anomaly = bool(iso_pred == -1)
    
    # Map class code to string label
    class_labels = {0: 'normal', 1: 'suspicious', 2: 'high_risk'}
    classification = class_labels.get(class_code, 'normal')
    
    # Compute a continuous ML risk score (0-100) based on weighted probabilities
    # 0 * prob_normal + 50 * prob_suspicious + 100 * prob_high_risk
    risk_score = (probs[1] * 50.0) + (probs[2] * 100.0)
    
    return {
        'classification': classification,
        'classification_code': class_code,
        'probabilities': probs,
        'is_anomaly': is_anomaly,
        'risk_score': risk_score
    }
