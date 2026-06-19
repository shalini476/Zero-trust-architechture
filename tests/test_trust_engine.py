import unittest
from app import create_app
from app.extensions import db
from app.models import User, Alert
from app.ml.trust_engine import adjust_trust_score
from app.config import Config

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_TYPE = 'filesystem'

class TrustTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()
        
        # Create test user
        self.user = User(username='test_user', email='u@t.com', security_question='Q')
        self.user.set_password('pass')
        self.user.set_security_answer('A')
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_initial_trust_score(self):
        """Tests that a new user starts with a Trust Score of 100."""
        self.assertEqual(self.user.trust_score, 100)

    def test_trust_score_penalties(self):
        """Tests that events deduct trust score and trigger warnings."""
        # Failed login: -10
        adjust_trust_score(self.user, 'failed_login', ip_address='1.1.1.1')
        self.assertEqual(self.user.trust_score, 90)
        
        # Unusual time: -15
        adjust_trust_score(self.user, 'unusual_time', ip_address='1.1.1.1')
        self.assertEqual(self.user.trust_score, 75)
        
        # New device: -20
        adjust_trust_score(self.user, 'new_device', ip_address='1.1.1.1')
        self.assertEqual(self.user.trust_score, 55)
        
        # Check alerts generated
        alerts = Alert.query.filter_by(user_id=self.user.id).all()
        self.assertEqual(len(alerts), 3)

    def test_honeypot_critical_penalty(self):
        """Tests that a honeypot trigger deducts 50 score and creates critical alert."""
        adjust_trust_score(self.user, 'honeypot_access', ip_address='1.1.1.1', description='Salary_Data_2026.xlsx')
        
        self.assertEqual(self.user.trust_score, 50)
        alert = Alert.query.filter_by(user_id=self.user.id, alert_type='HONEYPOT_ACCESS').first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, 'critical')

    def test_clamping_behavior(self):
        """Tests that the trust score is clamped at 0."""
        self.user.trust_score = 10
        db.session.commit()
        
        # Penalty of -50 should clamp to 0, not -40
        adjust_trust_score(self.user, 'honeypot_access', ip_address='1.1.1.1')
        self.assertEqual(self.user.trust_score, 0)

if __name__ == '__main__':
    unittest.main()
