import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score

def train_models(data_path, models_dir):
    """
    Trains and saves the Random Forest Classifier and Isolation Forest models.
    """
    os.makedirs(models_dir, exist_ok=True)
    
    # Check if dataset exists
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Run generate_dataset.py first.")
        
    print(f"[ML TRAINING] Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)
    
    # Separate features and target label
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split into train/test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # 1. Scale Features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save Scaler
    scaler_path = os.path.join(models_dir, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    print(f"[ML TRAINING] Saved StandardScaler to {scaler_path}")
    
    # 2. Train Random Forest Classifier (Supervised)
    print("[ML TRAINING] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate Random Forest
    rf_preds = rf_model.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"[ML TRAINING] Random Forest Accuracy: {rf_acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, rf_preds, target_names=['Normal', 'Suspicious', 'High Risk']))
    
    # Save Random Forest model
    rf_path = os.path.join(models_dir, 'random_forest.pkl')
    joblib.dump(rf_model, rf_path)
    print(f"[ML TRAINING] Saved Random Forest model to {rf_path}")
    
    # 3. Train Isolation Forest (Unsupervised Anomaly Detection)
    print("[ML TRAINING] Training Isolation Forest...")
    # Isolation Forest is trained on all features to capture outlier structures.
    # We set contamination based on the percentage of anomalies in our dataset (~35%)
    iso_forest = IsolationForest(contamination=0.35, random_state=42, n_estimators=100)
    iso_forest.fit(X.values) # Train on unscaled features (Isolation Forest is tree-based and scale-invariant)
    
    # Save Isolation Forest model
    iso_path = os.path.join(models_dir, 'isolation_forest.pkl')
    joblib.dump(iso_forest, iso_path)
    print(f"[ML TRAINING] Saved Isolation Forest model to {iso_path}")
    
    print("[ML TRAINING] Model training completed successfully.")

if __name__ == '__main__':
    # Define absolute paths
    base_dir = 'C:/Users/shali/OneDrive/Dokumen/zero threat'
    train_models(
        os.path.join(base_dir, 'data/sample_dataset.csv'),
        os.path.join(base_dir, 'ml_models')
    )
