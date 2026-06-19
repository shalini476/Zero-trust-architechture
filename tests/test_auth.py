import unittest
from datetime import datetime, timedelta
from app import create_app
from app.extensions import db
from app.models import User, OTPRecord, KnownDevice
from app.config import Config

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_TYPE = 'filesystem' # Simple filesystem sessions for tests

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_user_registration(self):
        """Tests that user registration correctly hashes password and security questions."""
        response = self.client.post('/auth/register', data={
            'username': 'testuser',
            'email': 'test@zerofox.com',
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'employee',
            'security_question': 'What was your first pet\'s name?',
            'security_answer': 'Fluffy'
        }, follow_redirects=True)
        
        user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'test@zerofox.com')
        self.assertEqual(user.role, 'employee')
        self.assertTrue(user.check_password('password123'))
        self.assertTrue(user.check_security_answer('Fluffy'))
        # Test case-insensitivity
        self.assertTrue(user.check_security_answer('fluffy'))

    def test_captcha_generator_route(self):
        """Tests that the CAPTCHA image generator route returns a PNG image."""
        response = self.client.get('/auth/captcha.png')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'image/png')
        
        # Check that captcha text was set in session
        with self.client.session_transaction() as sess:
            self.assertIn('captcha_text', sess)
            self.assertEqual(len(sess['captcha_text']), 5)

    def test_login_fails_with_invalid_captcha(self):
        """Tests that login fails if an incorrect CAPTCHA code is submitted."""
        # Create user
        user = User(username='bob_test2', email='bob_test2@zerofox.com', role='finance', security_question="Q")
        user.set_password('pass')
        user.set_security_answer('A')
        db.session.add(user)
        db.session.commit()
        
        # Set CAPTCHA in session
        with self.client.session_transaction() as sess:
            sess['captcha_text'] = 'ABCDE'
            
        # Post wrong CAPTCHA
        response = self.client.post('/auth/login', data={
            'username': 'bob_test2',
            'password': 'pass',
            'captcha': 'WRONG'
        }, follow_redirects=True)
        
        self.assertIn(b'Invalid CAPTCHA code', response.data)

    def test_login_credential_check(self):
        """Tests that correct credentials and CAPTCHA initialize login Step-1."""
        # Create user
        user = User(username='bob_test', email='bob_test@zerofox.com', role='finance', security_question="Q")
        user.set_password('pass')
        user.set_security_answer('A')
        db.session.add(user)
        db.session.commit()
        
        # Set CAPTCHA in session
        with self.client.session_transaction() as sess:
            sess['captcha_text'] = 'ABCDE'
            
        # Post correct credentials and CAPTCHA
        response = self.client.post('/auth/login', data={
            'username': 'bob_test',
            'password': 'pass',
            'captcha': 'ABCDE'
        })
        
        # Should redirect to OTP verification page
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/auth/verify-otp' in response.headers['Location'])
        
        # Check that OTP record was created in DB
        otp = OTPRecord.query.filter_by(user_id=user.id).first()
        self.assertIsNotNone(otp)
        self.assertFalse(otp.is_used)

if __name__ == '__main__':
    unittest.main()
