"""
app/ml/__init__.py — Machine Learning Sub-package
Zerofox — Zero Trust Security Platform

This package contains:
  - trust_engine.py   : Adaptive Trust Score Engine
  - behavior_analyzer.py : User Behavior Analytics (UBA)
  - explainable_ai.py : Human-readable risk explanations (XAI)
  - routes.py         : Flask Blueprint for ML-related views

No blueprint is defined here — the ml_bp Blueprint lives in routes.py
and is imported by the app factory in app/__init__.py.
"""
