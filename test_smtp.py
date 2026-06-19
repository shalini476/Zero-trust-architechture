"""Test sending email through Flask-Mail within app context."""
import sys
sys.path.insert(0, '.')

from app import create_app
from app.extensions import mail
from flask_mail import Message

app = create_app()

with app.app_context():
    print("Flask-Mail config:")
    print(f"  MAIL_SERVER: {app.config['MAIL_SERVER']}")
    print(f"  MAIL_PORT: {app.config['MAIL_PORT']}")
    print(f"  MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
    print(f"  MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
    print(f"  MAIL_USE_SSL: {app.config['MAIL_USE_SSL']}")
    print(f"  MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}")
    print()
    
    try:
        msg = Message(
            subject="Zerofox OTP Test via Flask-Mail",
            recipients=[app.config['MAIL_USERNAME']],  # send to self
            body="If you receive this, Flask-Mail SMTP is working correctly!"
        )
        mail.send(msg)
        print("SUCCESS - Email sent via Flask-Mail!")
    except Exception as e:
        print(f"FAILED - {type(e).__name__}: {e}")
