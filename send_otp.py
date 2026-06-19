"""
Standalone OTP email sender — mirrors the zerothreat .env mail config.
Run this locally (not in a sandboxed/restricted network) to test sending
a 6-digit OTP to your Gmail via Gmail's SMTP server.
"""
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Load config from .env (or set directly for a quick test) ---
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USERNAME = "zerofox.tech@gmail.com"      # the Gmail account sending the OTP
MAIL_PASSWORD = "kzbgqksndtrppvnq"            # 16-char App Password (no spaces)
MAIL_DEFAULT_SENDER = "zerofox.tech@gmail.com"

RECIPIENT = "vigneshdhandapani2023@gmail.com"  # sending the OTP to yourself for this test


def generate_otp(length: int = 6) -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(length))


def send_otp_email(recipient: str, otp: str) -> None:
    msg = MIMEMultipart()
    msg["From"] = MAIL_DEFAULT_SENDER
    msg["To"] = recipient
    msg["Subject"] = "Zerofox Zero Trust — Your OTP Code"

    body = f"""\
Your Zerofox Zero Trust verification code is: {otp}

This code expires in 5 minutes. Do not share it with anyone.
"""
    msg.attach(MIMEText(body, "plain"))

    print(f"Connecting to {MAIL_SERVER}:{MAIL_PORT} ...")
    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=15) as server:
        server.set_debuglevel(0)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_DEFAULT_SENDER, recipient, msg.as_string())
    print("SUCCESS — OTP email sent.")


if __name__ == "__main__":
    code = generate_otp()
    print(f"Generated OTP: {code}")
    try:
        send_otp_email(RECIPIENT, code)
    except Exception as e:
        print(f"FAILED — {type(e).__name__}: {e}")
