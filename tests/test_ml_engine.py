import unittest
from app import create_app
from app.extensions import db
from app.ml.threat_engine import predict_threat_level
from app.ml.explainable_ai import generate_xai_explanations
from app.config import Config

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_TYPE = 'filesystem'

class MLTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.ctx = self.app.app_context()
        self.ctx.push()
        # No DB tables needed for stateless ML inference tests,
        # but we call create_all just in case.
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_normal_behavior_prediction(self):
        """Tests that normal behavioral parameters evaluate to 'normal' class."""
        res = predict_threat_level(
            login_hour=10,               # Working hours
            failed_attempts_24h=0,       # No failures
            is_new_device=0,             # Known device
            is_unusual_time=0,           # Usual time
            trust_score=100,             # Full trust
            resource_access_frequency=2, # standard downloads
            honeypot_accessed=0          # No trap triggered
        )
        
        self.assertEqual(res['classification'], 'normal')
        self.assertLess(res['risk_score'], 15.0)

    def test_critical_honeypot_threat_prediction(self):
        """Tests that a honeypot trigger is immediately flagged as high_risk."""
        res = predict_threat_level(
            login_hour=2,                # Off-hours
            failed_attempts_24h=5,       # High failures
            is_new_device=1,             # Unknown device
            is_unusual_time=1,
            trust_score=20,              # Low trust
            resource_access_frequency=25,# High file access rate
            honeypot_accessed=1          # Honeypot triggered
        )
        
        self.assertEqual(res['classification'], 'high_risk')
        self.assertGreater(res['risk_score'], 75.0)

    def test_explainable_ai_reasons(self):
        """Tests that XAI reason generator produces correct reasoning tags."""
        reasons = generate_xai_explanations(
            login_hour=23,
            failed_attempts_24h=4,
            is_new_device=True,
            is_unusual_time=True,
            trust_score=70,
            resource_access_frequency=12,
            honeypot_accessed=False
        )
        
        # Verify that specific warnings were logged
        self.assertTrue(any("unrecognized device" in r.lower() for r in reasons))
        self.assertTrue(any("off-hours" in r.lower() for r in reasons))
        self.assertTrue(any("failed login attempts" in r.lower() for r in reasons))
        self.assertTrue(any("degraded trust posture" in r.lower() for r in reasons))
        self.assertTrue(any("high resource access" in r.lower() for r in reasons))

if __name__ == '__main__':
    # Since these tests load the serialized model files, they depend
    # on train_model.py having run successfully.
    unittest.main()
