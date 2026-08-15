import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "")
SMTP_HOST = os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "465"))


def send_email(subject, to_email, body_html, from_name="CyberShield SOC"):
    """Send an HTML email via Gmail SMTP (port 465 / SSL).

    Uses EMAIL_USER and EMAIL_APP_PASSWORD from environment (.env).
    Falls back to console mode (prints the body) when SMTP is not configured
    so the platform remains fully usable in demo mode.
    """
    if not to_email:
        return False, "No recipient email provided"

    if not EMAIL_USER or not EMAIL_APP_PASSWORD:
        print(f"[EMAIL][CONSOLE] To: {to_email} | Subject: {subject}\n{body_html}")
        return True, f"OTP logged to console (SMTP not configured) for {to_email}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{EMAIL_USER}>"
    msg["To"] = to_email
    msg.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.login(EMAIL_USER, EMAIL_APP_PASSWORD)
            server.send_message(msg)
        return True, f"Email sent to {to_email}"
    except Exception as e:
        print(f"[EMAIL][ERROR] Failed to send to {to_email}: {e}")
        print(f"[EMAIL][FALLBACK] OTP/content for {to_email}:\n{body_html}")
        return False, f"SMTP error: {str(e)}"
