import unittest
import json
from app import create_app
from app.extensions import db
from app.models import User, ActivityLog, Alert, Simulation
from app.config import Config

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_TYPE = 'filesystem'

class SimulationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()
        
        # Create admin user
        self.admin = User(username='admin_test', email='ad@t.com', role='admin', security_question='Q')
        self.admin.set_password('pass')
        self.admin.set_security_answer('A')
        
        # Create normal employee
        self.employee = User(username='charlie_test', email='ch@t.com', role='employee', security_question='Q')
        self.employee.set_password('pass')
        self.employee.set_security_answer('A')
        
        db.session.add_all([self.admin, self.employee])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_run_simulation_auth_restriction(self):
        """Tests that non-admins are blocked from running threat simulations (RBAC check)."""
        # Log in as normal employee
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.employee.id)
            sess['_fresh'] = True
            
        response = self.client.post('/simulation/run', data=json.dumps({
            'type': 'brute_force',
            'target_user_id': self.employee.id
        }), content_type='application/json')
        
        # Should return 403 Forbidden
        self.assertEqual(response.status_code, 403)

    def test_run_brute_force_simulation(self):
        """Tests that admin running brute force simulation injects logs and alerts."""
        # Log in as Admin
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)
            sess['_fresh'] = True
            
        response = self.client.post('/simulation/run', data=json.dumps({
            'type': 'brute_force',
            'target_user_id': self.employee.id
        }), content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertTrue('Brute force' in data['details']['message'])
        
        # Verify 8 failed login logs were added to DB for employee
        logs_count = ActivityLog.query.filter_by(
            user_id=self.employee.id, 
            action='LOGIN_CREDENTIALS', 
            status='FAILED'
        ).count()
        self.assertEqual(logs_count, 8)
        
        # Verify employee trust score was degraded
        employee_updated = User.query.get(self.employee.id)
        self.assertLess(employee_updated.trust_score, 100)
        
        # Verify simulation run was logged in DB
        sim = Simulation.query.first()
        self.assertIsNotNone(sim)
        self.assertEqual(sim.admin_id, self.admin.id)
        self.assertEqual(sim.simulation_type, 'brute_force')

if __name__ == '__main__':
    unittest.main()
