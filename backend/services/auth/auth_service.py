import json
import hashlib
import uuid
import re
import pyotp
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from services._shared.jwt_middleware import create_token, revoke_session, PRIVATE_KEY, PUBLIC_KEY, JWT_ALGO
from services.auth.otp_service import verify_otp as check_otp
from services._shared.siem_logger import log_event
from config.settings import DATA_DIR

ph = PasswordHasher()
USER_DB = None
LOGIN_ATTEMPTS = {}
OAUTH_AUTH_CODES = {}
OAUTH_CLIENTS = {
    "cs-web-app": {"secret": "web-client-secret", "redirect_uris": ["http://localhost:5000/callback"], "name": "CyberShield Web App"},
    "cs-mobile-app": {"secret": "mobile-client-secret", "redirect_uris": ["cybershield://callback"], "name": "CyberShield Mobile App"}
}
PASSWORD_RESET_TOKENS = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_MINUTES = 15

def load_users():
    global USER_DB
    if USER_DB is None:
        with open(f"{DATA_DIR}/users.json") as f:
            USER_DB = json.load(f)
    return USER_DB

def save_users():
    global USER_DB
    with open(f"{DATA_DIR}/users.json", "w") as f:
        json.dump(USER_DB, f, indent=2)

def _check_lockout(email):
    if email in LOGIN_ATTEMPTS:
        a = LOGIN_ATTEMPTS[email]
        if a["count"] >= LOCKOUT_THRESHOLD and (datetime.utcnow() - a["first_attempt"]).seconds < LOCKOUT_WINDOW_MINUTES * 60:
            remaining = LOCKOUT_WINDOW_MINUTES * 60 - (datetime.utcnow() - a["first_attempt"]).seconds
            return round(remaining / 60, 1)
    return 0

def _record_failed_attempt(email):
    if email not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[email] = {"count": 0, "first_attempt": datetime.utcnow()}
    LOGIN_ATTEMPTS[email]["count"] += 1

def password_login(email, password, ip=None):
    users = load_users()
    lockout_min = _check_lockout(email)
    if lockout_min > 0:
        log_event("LOGIN_BLOCKED", "WARNING", "auth", {"email": email, "reason": "account_locked", "ip": ip}, email)
        return {"success": False, "message": f"Account locked. Try again in {lockout_min} min."}, 423
    if email not in users:
        _record_failed_attempt(email)
        log_event("LOGIN_FAILED", "INFO", "auth", {"email": email, "reason": "user_not_found", "ip": ip}, email)
        remaining = LOCKOUT_THRESHOLD - LOGIN_ATTEMPTS[email]["count"]
        return {"success": False, "message": f"Invalid credentials. {max(0, remaining)} attempts left"}, 401
    try:
        ph.verify(users[email]["password"], password)
        if ph.check_needs_rehash(users[email]["password"]):
            users[email]["password"] = ph.hash(password)
            save_users()
    except VerifyMismatchError:
        _record_failed_attempt(email)
        remaining = LOCKOUT_THRESHOLD - LOGIN_ATTEMPTS[email]["count"]
        log_event("LOGIN_FAILED", "INFO", "auth", {"email": email, "reason": "wrong_password", "ip": ip}, email)
        return {"success": False, "message": f"Invalid credentials. {max(0, remaining)} attempts left"}, 401
    LOGIN_ATTEMPTS.pop(email, None)
    log_event("LOGIN_SUCCESS", "INFO", "auth", {"email": email, "ip": ip}, email)
    user = users[email]
    roles = ["admin"] if user["role"] == "admin" else ["analyst"] if user["role"] == "analyst" else ["compliance"]
    if user.get("mfa_enabled"):
        return {"success": True, "requires2FA": True, "userId": email, "user": {"email": email, "name": user["name"], "role": user["role"], "mfa_enabled": True}}, 200
    token, refresh = create_token(email, user["name"], roles)
    return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": email, "name": user["name"], "role": user["role"]}}, 200

def verify_2fa(user_id, otp):
    if check_otp(f"otp:{user_id}", otp):
        users = load_users()
        user = users.get(user_id, {})
        roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
        token, refresh = create_token(user_id, user.get("name", user_id), roles)
        log_event("MFA_VERIFIED", "INFO", "auth", {"user_id": user_id, "method": "otp"}, user_id)
        return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": user_id, "name": user.get("name", user_id), "role": user.get("role", "analyst")}}, 200
    users = load_users()
    user = users.get(user_id)
    phone = user.get("phone") if user else None
    if user and check_otp(f"otp:{user_id}", otp):
        roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
        token, refresh = create_token(user_id, user.get("name", user_id), roles)
        log_event("MFA_VERIFIED", "INFO", "auth", {"user_id": user_id, "method": "otp"}, user_id)
        return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": user_id, "name": user.get("name", user_id), "role": user.get("role", "analyst")}}, 200
    if phone and check_otp(f"otp:{phone}", otp):
        roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
        token, refresh = create_token(user_id, user.get("name", user_id), roles)
        log_event("MFA_VERIFIED", "INFO", "auth", {"user_id": user_id, "method": "otp_sms"}, user_id)
        return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": user_id, "name": user.get("name", user_id), "role": user.get("role", "analyst")}}, 200
    if user and user.get("totp_secret"):
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(otp, valid_window=1):
            roles = ["admin"] if user["role"] == "admin" else ["analyst"] if user["role"] == "analyst" else ["compliance"]
            token, refresh = create_token(user_id, user["name"], roles)
            log_event("MFA_VERIFIED", "INFO", "auth", {"user_id": user_id, "method": "totp"}, user_id)
            return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": user_id, "name": user["name"], "role": user["role"]}}, 200
    log_event("MFA_FAILED", "WARNING", "auth", {"user_id": user_id, "reason": "invalid_otp"}, user_id)
    return {"success": False, "message": "Invalid OTP"}, 401

def generate_totp_secret(email):
    users = load_users()
    if email not in users:
        return {"success": False, "message": "User not found"}, 404
    secret = pyotp.random_base32()
    users[email]["totp_secret"] = secret
    users[email]["mfa_enabled"] = True
    save_users()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="CyberShield")
    return {"success": True, "secret": secret, "qrCode": provisioning_uri}, 200

def oauth_authorize(client_id, redirect_uri, scope, user_id=None):
    if client_id not in OAUTH_CLIENTS:
        return {"success": False, "message": "Unknown client"}, 400
    client = OAUTH_CLIENTS[client_id]
    if redirect_uri not in client["redirect_uris"]:
        return {"success": False, "message": "Invalid redirect URI"}, 400
    auth_code = hashlib.sha256(f"{client_id}:{uuid.uuid4()}:{user_id}".encode()).hexdigest()[:32]
    OAUTH_AUTH_CODES[auth_code] = {"client_id": client_id, "scope": scope, "user_id": user_id, "created": datetime.utcnow().isoformat()}
    return {"success": True, "auth_code": auth_code, "redirect_uri": f"{redirect_uri}?code={auth_code}&state={scope}"}, 200

def oauth_token(auth_code, client_id, client_secret):
    if auth_code not in OAUTH_AUTH_CODES:
        return {"success": False, "message": "Invalid auth code"}, 400
    code_data = OAUTH_AUTH_CODES[auth_code]
    if code_data["client_id"] != client_id:
        return {"success": False, "message": "Client mismatch"}, 400
    if OAUTH_CLIENTS.get(client_id, {}).get("secret") != client_secret:
        return {"success": False, "message": "Invalid client secret"}, 401
    user_id = code_data.get("user_id", "oauth-user@cybershield.com")
    user = load_users().get(user_id, {})
    roles = ["admin"] if user.get("role") == "admin" else ["analyst"]
    token, refresh = create_token(user_id, user.get("name", "OAuth User"), roles)
    del OAUTH_AUTH_CODES[auth_code]
    return {"access_token": token, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 900}, 200

def sso_saml_login(email, name, idp="AzureAD"):
    token, refresh = create_token(email, name, ["analyst"])
    saml_assertion = f"SAMLResponse-{hashlib.sha256(email.encode()).hexdigest()[:16]}"
    log_event("SSO_LOGIN", "INFO", "auth", {"email": email, "provider": "SAML", "idp": idp}, email)
    return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": email, "name": name, "role": "analyst"}, "saml_assertion": saml_assertion, "idp": idp}, 200

def sso_oidc_login(email, name, idp="Google"):
    token, refresh = create_token(email, name, ["analyst"])
    log_event("SSO_LOGIN", "INFO", "auth", {"email": email, "provider": "OIDC", "idp": idp}, email)
    return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": email, "name": name, "role": "analyst"}, "idp": idp}, 200

def initiate_password_reset(email):
    users = load_users()
    if email not in users:
        return {"success": False, "message": "If email exists, reset link sent"}, 200
    token = uuid.uuid4().hex
    PASSWORD_RESET_TOKENS[token] = {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)}
    log_event("PASSWORD_RESET", "INFO", "auth", {"email": email}, email)
    return {"success": True, "message": "Reset link sent", "reset_token": token, "expires_in": 3600}, 200

def reset_password(reset_token, new_password):
    if reset_token not in PASSWORD_RESET_TOKENS:
        return {"success": False, "message": "Invalid or expired reset token"}, 400
    data = PASSWORD_RESET_TOKENS[reset_token]
    if datetime.utcnow() > data["exp"]:
        del PASSWORD_RESET_TOKENS[reset_token]
        return {"success": False, "message": "Reset token expired"}, 400
    users = load_users()
    email = data["email"]
    if email in users:
        users[email]["password"] = ph.hash(new_password)
        save_users()
    del PASSWORD_RESET_TOKENS[reset_token]
    log_event("PASSWORD_CHANGED", "INFO", "auth", {"email": email}, email)
    return {"success": True, "message": "Password reset successful"}, 200

def register(username, email, password, name):
    users = load_users()
    if email in users:
        return {"success": False, "message": "Email already registered"}, 409
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"success": False, "message": "Invalid email format"}, 400
    if len(password) < 8:
        return {"success": False, "message": "Password must be 8+ characters"}, 400
    users[email] = {
        "password": ph.hash(password),
        "name": name or username or email.split("@")[0],
        "role": "analyst",
        "mfa_enabled": False,
        "mfa_method": "totp",
        "sso_enabled": False,
        "created": datetime.utcnow().isoformat() + "Z",
        "last_login": ""
    }
    save_users()
    log_event("USER_REGISTERED", "INFO", "auth", {"email": email, "name": name}, email)
    token, refresh = create_token(email, name, ["analyst"])
    return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": email, "name": name, "role": "analyst"}}, 201

def mobile_login(phone, pin):
    users = load_users()
    user_key = None
    for k, v in users.items():
        if v.get("phone", "").replace(" ", "") == phone.replace(" ", ""):
            user_key = k
            break
    if not user_key:
        return {"success": False, "message": "Invalid phone or PIN"}, 401
    user = users[user_key]
    try:
        ph.verify(user["pin"], pin)
    except (VerifyMismatchError, KeyError):
        log_event("MOBILE_LOGIN_FAILED", "INFO", "auth", {"phone": phone}, user_key)
        return {"success": False, "message": "Invalid phone or PIN"}, 401
    from services.auth.otp_service import generate_otp, store_otp, send_sms_otp
    otp = generate_otp()
    store_otp(f"otp:{phone}", otp)
    sent, msg = send_sms_otp(phone, otp)
    log_event("MOBILE_LOGIN_SUCCESS", "INFO", "auth", {"phone": phone, "otp_sent": sent}, user_key)
    return {"success": True, "requires2FA": True, "userId": user_key, "user": {"email": user_key, "name": user["name"], "role": user["role"], "phone": user.get("phone")}, "delivery": "sms"}, 200

def refresh_token(refresh_token_str):
    from services._shared.jwt_middleware import refresh_access_token
    result = refresh_access_token(refresh_token_str)
    if not result:
        return {"success": False, "message": "Invalid refresh token"}, 401
    token, new_refresh = result
    return {"success": True, "token": token, "refreshToken": new_refresh}, 200

def list_users():
    users = load_users()
    return [{"email": k, "name": v["name"], "role": v["role"], "mfa_enabled": v["mfa_enabled"]} for k, v in users.items()]
