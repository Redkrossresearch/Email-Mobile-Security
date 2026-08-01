import json
import hashlib
import uuid
import random
import string
import pyotp
from datetime import datetime, timedelta
from flask import request, jsonify
from config.settings import DATA_DIR
from middleware.auth import create_token
from utils.email_service import send_email
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

USER_DB = None
LOGIN_ATTEMPTS = {}
OAUTH_TOKENS = {}
EMAIL_OTP_STORE = {}  # email -> {"otp": str, "expires_at": datetime, "attempts": int}
EMAIL_OTP_EXPIRY_MINUTES = 5

def load_users():
    global USER_DB
    if USER_DB is None:
        with open(f"{DATA_DIR}/users.json") as f:
            USER_DB = json.load(f)
    return USER_DB

def _create_and_send_otp(email):
    """Generate a 6-digit OTP, store it, and email it. Returns (success, error_message)."""
    otp = _generate_otp()
    EMAIL_OTP_STORE[email] = {
        "otp": otp,
        "expires_at": datetime.utcnow() + timedelta(minutes=EMAIL_OTP_EXPIRY_MINUTES),
        "attempts": 0
    }
    try:
        send_email(
            to_email=email,
            subject="Your CyberShield verification code",
            body=f"Your OTP is: {otp}\nThis code expires in {EMAIL_OTP_EXPIRY_MINUTES} minutes.\nIf you didn't request this, ignore this email."
        )
    except Exception as e:
        EMAIL_OTP_STORE.pop(email, None)
        return False, str(e)
    return True, None


def login():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    ip = request.remote_addr or "unknown"
    users = load_users()
    if email in LOGIN_ATTEMPTS:
        attempts = LOGIN_ATTEMPTS[email]
        if attempts["count"] >= 5 and (datetime.utcnow() - attempts["first_attempt"]).seconds < 900:
            return jsonify({"success": False, "message": "Account locked due to multiple failed attempts. Try again in 15 min."}), 423
    try:
        if email not in users:
            raise VerifyMismatchError
        ph.verify(users[email]["password"], password)
    except VerifyMismatchError:
        if email not in LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[email] = {"count": 0, "first_attempt": datetime.utcnow()}
        LOGIN_ATTEMPTS[email]["count"] += 1
        remaining = 5 - LOGIN_ATTEMPTS[email]["count"]
        return jsonify({"success": False, "message": f"Invalid credentials. {max(0, remaining)} attempts remaining"}), 401
    LOGIN_ATTEMPTS.pop(email, None)
    user = users[email]

    # Password correct -> send OTP to the user's email instead of issuing the token right away
    
    sent, err = _create_and_send_otp(email)
    print("EMAIL ERROR:", err)
    if not sent:
        return jsonify({"success": False, "message": "Password correct, but failed to send OTP email. Try again."}), 500

    return jsonify({
        "success": True,
        "requiresEmailOTP": True,
        "email": email,
        "message": "Password verified. OTP sent to your email."
    })

def mobile_login():
    data = request.get_json()
    phone = data.get("phone", "").strip()
    pin = data.get("pin", "")
    users = load_users()
    mobile_key = f"{phone}@mobile.user"
    if mobile_key not in users:
        return jsonify({"success": False, "message": "Mobile user not registered"}), 401
    try:
        ph.verify(users[mobile_key]["pin"], pin)
    except VerifyMismatchError:
        return jsonify({"success": False, "message": "Invalid PIN"}), 401
    token = create_token(mobile_key, users[mobile_key]["name"], users[mobile_key]["role"])
    return jsonify({
        "success": True,
        "token": token,
        "user": {"name": users[mobile_key]["name"], "role": users[mobile_key]["role"], "phone": phone},
        "message": "Mobile login successful"
    })

def verify_otp():
    data = request.get_json()
    otp = data.get("otp", "")
    email = data.get("email", "").strip().lower()
    users = load_users()
    user = users.get(email)
    if not user or not user.get("totp_secret"):
        return jsonify({"success": False, "message": "OTP not configured"}), 400
    totp = pyotp.TOTP(user["totp_secret"])
    if totp.verify(otp, valid_window=1):
        return jsonify({"success": True, "message": "OTP verified"})
    return jsonify({"success": False, "message": "Invalid OTP"}), 401

def verify_mfa():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    otp = data.get("otp", "")
    users = load_users()
    user = users.get(email)
    if not user or not user.get("mfa_enabled"):
        return jsonify({"success": False, "message": "MFA not enabled for this user"}), 400
    secret = user.get("totp_secret")
    if not secret:
        return jsonify({"success": False, "message": "TOTP not configured"}), 400
    totp = pyotp.TOTP(secret)
    if totp.verify(otp, valid_window=1):
        token = create_token(email, user["name"], user["role"])
        return jsonify({"success": True, "token": token, "message": "MFA verified"})
    return jsonify({"success": False, "message": "Invalid OTP"}), 401

def sso_login():
    data = request.get_json() or {}
    provider = data.get("provider", "saml")
    email = data.get("email", "user@sso.com")
    name = data.get("name", "SSO User")
    idp = data.get("idp", "AzureAD")
    if provider == "saml":
        saml_assertion = f"SAMLResponse-{hashlib.sha256(email.encode()).hexdigest()[:16]}"
        token = create_token(email, name, "analyst")
        return jsonify({
            "success": True,
            "token": token,
            "user": {"email": email, "name": name, "role": "analyst"},
            "saml_assertion": saml_assertion,
            "idp": idp,
            "message": f"SSO login via {idp} successful"
        })
    elif provider == "oidc":
        token = create_token(email, name, "analyst")
        return jsonify({
            "success": True,
            "token": token,
            "user": {"email": email, "name": name, "role": "analyst"},
            "idp": idp,
            "message": "OIDC SSO login successful"
        })
    return jsonify({"success": False, "message": "Unsupported SSO provider"}), 400

def oauth_authorize():
    data = request.get_json() or {}
    client_id = data.get("client_id", "cs-mobile-app")
    redirect_uri = data.get("redirect_uri", "cybershield://callback")
    scope = data.get("scope", "openid profile email")
    auth_code = hashlib.sha256(f"{client_id}:{uuid.uuid4()}".encode()).hexdigest()[:32]
    OAUTH_TOKENS[auth_code] = {"client_id": client_id, "scope": scope, "created": datetime.utcnow().isoformat()}
    return jsonify({
        "success": True,
        "auth_code": auth_code,
        "redirect_uri": f"{redirect_uri}?code={auth_code}",
        "scope": scope,
        "expires_in": 600
    })

def oauth_token():
    data = request.get_json() or {}
    auth_code = data.get("code", "")
    if auth_code in OAUTH_TOKENS:
        access_token = create_token("oauth-user@cybershield.com", "OAuth User", "analyst")
        del OAUTH_TOKENS[auth_code]
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 86400,
            "scope": "openid profile email"
        })
    return jsonify({"error": "invalid_grant", "message": "Invalid authorization code"}), 400

def generate_totp(current_user=None):
    data = request.get_json() or {}
    email = data.get("email", current_user or "").strip().lower()
    users = load_users()
    if email not in users:
        return jsonify({"success": False, "message": "User not found"}), 404
    secret = pyotp.random_base32()
    users[email]["totp_secret"] = secret
    users[email]["mfa_enabled"] = True
    with open(f"{DATA_DIR}/users.json", "w") as f:
        json.dump(users, f, indent=2)
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="CyberShield")
    return jsonify({
        "success": True,
        "secret": secret,
        "qrCode": provisioning_uri,
        "message": "TOTP secret generated. Scan QR with authenticator app."
    })

def account_recovery():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    users = load_users()
    if email not in users:
        return jsonify({"success": False, "message": "If email exists, recovery link sent"}), 200
    recovery_token = hashlib.sha256(f"{email}:{uuid.uuid4()}".encode()).hexdigest()[:32]
    return jsonify({
        "success": True,
        "message": "Recovery email sent",
        "recovery_token": recovery_token,
        "expires_in": 3600
    })

def list_users(current_user=None):
    users = load_users()
    user_list = [{"email": k, "name": v["name"], "role": v["role"], "mfa_enabled": v["mfa_enabled"]} for k, v in users.items()]
    return jsonify({"success": True, "users": user_list, "total": len(user_list)})


def register():
    data = request.get_json() or {}
    full_name = data.get("fullName", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    mobile = data.get("mobile", "").strip()
    role = data.get("role", "analyst")

    if not full_name or not email or not password:
        return jsonify({"success": False, "message": "Full name, email and password are required"}), 400

    users = load_users()
    if email in users:
        return jsonify({"success": False, "message": "An account with this email already exists"}), 409

    hashed_password = ph.hash(password)
    users[email] = {
        "name": full_name,
        "password": hashed_password,
        "role": role,
        "mfa_enabled": True,
        "mobile": mobile
    }

    with open(f"{DATA_DIR}/users.json", "w") as f:
        json.dump(users, f, indent=2)

    return jsonify({"success": True, "message": "Account created successfully"})


def _generate_otp():
    return "".join(random.choices(string.digits, k=6))


def send_email_otp():
    """Generate a 6-digit OTP, store it in memory, and email it to the user."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    users = load_users()
    # Don't reveal whether the email is registered (avoid user enumeration)
    if email not in users:
        return jsonify({"success": True, "message": "If this email is registered, an OTP has been sent"}), 200

    otp = _generate_otp()
    EMAIL_OTP_STORE[email] = {
        "otp": otp,
        "expires_at": datetime.utcnow() + timedelta(minutes=EMAIL_OTP_EXPIRY_MINUTES),
        "attempts": 0
    }

    try:
        send_email(
            to_email=email,
            subject="Your CyberShield verification code",
            body=f"Your OTP is: {otp}\nThis code expires in {EMAIL_OTP_EXPIRY_MINUTES} minutes.\nIf you didn't request this, ignore this email."
        )
    except Exception:
        EMAIL_OTP_STORE.pop(email, None)
        return jsonify({"success": False, "message": "Failed to send OTP email. Try again later."}), 500

    return jsonify({"success": True, "message": "OTP sent to your email"})


def verify_email_otp():
    """Verify the OTP sent via email and issue a login token on success."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    otp = data.get("otp", "").strip()

    record = EMAIL_OTP_STORE.get(email)
    if not record:
        return jsonify({"success": False, "message": "No OTP requested for this email, or it already expired"}), 400

    if datetime.utcnow() > record["expires_at"]:
        EMAIL_OTP_STORE.pop(email, None)
        return jsonify({"success": False, "message": "OTP expired. Please request a new one"}), 401

    record["attempts"] += 1
    if record["attempts"] > 5:
        EMAIL_OTP_STORE.pop(email, None)
        return jsonify({"success": False, "message": "Too many incorrect attempts. Please request a new OTP"}), 429

    if otp != record["otp"]:
        return jsonify({"success": False, "message": "Invalid OTP"}), 401

    EMAIL_OTP_STORE.pop(email, None)
    users = load_users()
    user = users[email]
    token = create_token(email, user["name"], user["role"])
    return jsonify({
        "success": True,
        "token": token,
        "user": {"email": email, "name": user["name"], "role": user["role"]},
        "message": "Email OTP verified"
    })
