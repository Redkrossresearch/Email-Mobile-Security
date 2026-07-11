import random
import smtplib
import os
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from config.settings import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM

OTP_STORE = {}

def generate_otp(length=6):
    return str(random.randint(10**(length-1), 10**length - 1))

def store_otp(key, otp, ttl_minutes=5):
    OTP_STORE[key] = {"otp": otp, "expires_at": datetime.utcnow() + timedelta(minutes=ttl_minutes), "verified": False}

def verify_otp(key, otp):
    entry = OTP_STORE.get(key)
    if not entry or datetime.utcnow() > entry["expires_at"]:
        OTP_STORE.pop(key, None)
        return False
    if entry["otp"] == otp:
        OTP_STORE.pop(key, None)
        return True
    return False

def send_email_otp(to_email, otp):
    subject = "CyberShield SOC — Your OTP Code"
    body = f"""Your One-Time Password (OTP) is: {otp}

This code expires in 5 minutes. Do not share it with anyone.

— CyberShield SOC Security Team"""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    if SMTP_HOST and SMTP_USER:
        try:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) if SMTP_PORT == 465 else smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            if SMTP_PORT != 465: server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
            server.quit()
            return True, f"OTP sent to {to_email}"
        except Exception as e:
            return False, f"SMTP error: {str(e)}"
    print(f"[OTP] Email to {to_email}: {otp}")
    return True, f"OTP {otp} (console)"

def send_sms_otp(to_phone, otp):
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    twilio_from = os.environ.get("TWILIO_FROM", "")
    if account_sid and auth_token and twilio_from:
        try:
            from twilio.rest import Client
            Client(account_sid, auth_token).messages.create(body=f"CyberShield OTP: {otp}", from_=twilio_from, to=to_phone)
            return True, f"OTP sent to {to_phone}"
        except Exception as e:
            return False, f"Twilio error: {str(e)}"
    print(f"[OTP] SMS to {to_phone}: {otp}")
    return True, f"OTP {otp} (console)"
