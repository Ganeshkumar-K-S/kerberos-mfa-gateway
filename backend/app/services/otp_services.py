import random

def generate_otp(length: int = 6):
    return ''.join(str(random.randint(0, 9)) for _ in range(length))

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_FROM


def send_email_otp(to_email: str, otp: str):
    try:
        subject = "Your OTP Code"
        body = f"""
        Hello,

        Your OTP for authentication is: {otp}

        This OTP is valid for a short time. Do not share it with anyone.

        Regards,
        Security Team
        """

        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        print(msg)

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        return True

    except Exception as e:
        print("Email error:", e)
        return False