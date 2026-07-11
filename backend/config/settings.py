import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports_output")

JWT_SECRET = os.getenv("JWT_SECRET", "cybershield-soc-secret-key-2026!!!")
JWT_ALGO = "HS256"
JWT_EXPIRY_HOURS = 24

AES_KEY = (os.getenv("AES_KEY", "CyberShieldAES256KeyForEncryption2026!")).encode()[:32].ljust(32, b'\0')
AES_IV = (os.getenv("AES_IV", "CybershieldIV00")).encode()[:12].ljust(12, b'\0')

SALT_API_KEY = os.getenv("SALT_API_KEY", "cs-salt-api-key-2026")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

GMAIL_CREDENTIALS_JSON = os.getenv("GMAIL_CREDENTIALS_JSON", "")
GMAIL_TOKEN_JSON = os.getenv("GMAIL_TOKEN_JSON", "")
GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID", "")
GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID", "")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET", "")

OMIT_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com", "icloud.com"]

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "noreply@cybershield.com")
