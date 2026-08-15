import json
import hashlib
import uuid
import random
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
    otp, sent, smtp_msg = _issue_email_otp(email, user["name"])
    if not sent:
        log_event("EMAIL_OTP_SEND_FAILED", "WARNING", "auth", {"email": email, "reason": smtp_msg}, email)
    return {
        "success": True,
        "requiresEmailOTP": True,
        "email": email,
        "userId": email,
        "delivery": "email",
        "user": {"email": email, "name": user["name"], "role": user["role"], "mfa_enabled": user.get("mfa_enabled", False)},
        "message": f"Verification code sent to {email}"
    }, 200

def _check_email_otp(email, otp):
    """Check OTP against EMAIL_OTP_STORE (used by _issue_email_otp)."""
    record = EMAIL_OTP_STORE.get(email)
    if not record:
        return False
    if datetime.utcnow() > record["expires"]:
        EMAIL_OTP_STORE.pop(email, None)
        return False
    if record["attempts"] >= EMAIL_OTP_MAX_ATTEMPTS:
        EMAIL_OTP_STORE.pop(email, None)
        return False
    if record["otp"] == otp:
        EMAIL_OTP_STORE.pop(email, None)
        return True
    record["attempts"] += 1
    return False

def verify_2fa(user_id, otp):
    if check_otp(f"otp:{user_id}", otp):
        users = load_users()
        user = users.get(user_id, {})
        roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
        token, refresh = create_token(user_id, user.get("name", user_id), roles)
        log_event("MFA_VERIFIED", "INFO", "auth", {"user_id": user_id, "method": "otp"}, user_id)
        return {"success": True, "token": token, "refreshToken": refresh, "user": {"email": user_id, "name": user.get("name", user_id), "role": user.get("role", "analyst")}}, 200
    if _check_email_otp(user_id, otp):
        users = load_users()
        user = users.get(user_id, {})
        roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
        token, refresh = create_token(user_id, user.get("name", user_id), roles)
        log_event("MFA_VERIFIED", "INFO", "auth", {"user_id": user_id, "method": "email_otp"}, user_id)
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

def register(username, email, password, name, mobile="", role="analyst"):
    users = load_users()
    if email in users:
        return {"success": False, "message": "Email already registered"}, 409
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"success": False, "message": "Invalid email format"}, 400
    if len(password) < 8:
        return {"success": False, "message": "Password must be 8+ characters"}, 400
    if role not in ("admin", "analyst", "compliance"):
        role = "analyst"
    users[email] = {
        "password": ph.hash(password),
        "name": name or username or email.split("@")[0],
        "role": role,
        "mfa_enabled": False,
        "mfa_method": "totp",
        "sso_enabled": False,
        "mobile": mobile,
        "created": datetime.utcnow().isoformat() + "Z",
        "last_login": ""
    }
    save_users()
    log_event("USER_REGISTERED", "INFO", "auth", {"email": email, "name": name}, email)
    return {"success": True, "message": "Registration successful. Please login.", "user": {"email": email, "name": name or email.split("@")[0], "role": role}}, 201

def _find_user_by_phone(phone):
    """Find a user by phone number, trying multiple formats (with/without country code)."""
    users = load_users()
    phone_clean = phone.replace(" ", "").replace("-", "")
    for k, v in users.items():
        stored = (v.get("phone", "") or "").replace(" ", "").replace("-", "")
        if stored == phone_clean:
            return k, v
        if not stored.startswith("+91") and phone_clean.startswith("+91"):
            if stored == phone_clean[3:]:
                return k, v
        if stored.startswith("+91") and not phone_clean.startswith("+91") and len(phone_clean) == 10:
            if stored[3:] == phone_clean:
                return k, v
    return None, None

def mobile_login(phone, pin):
    users = load_users()
    user_key, user = _find_user_by_phone(phone)
    if not user_key:
        return {"success": False, "message": "Invalid phone or PIN"}, 401
    try:
        ph.verify(user["pin"], pin)
    except (VerifyMismatchError, KeyError):
        log_event("MOBILE_LOGIN_FAILED", "INFO", "auth", {"phone": phone}, user_key)
        return {"success": False, "message": "Invalid phone or PIN"}, 401
    otp, sent = _issue_mobile_otp(phone, user_key, user.get("name", "Mobile User"))
    log_event("MOBILE_LOGIN_SUCCESS", "INFO", "auth", {"phone": phone}, user_key)
    return {
        "success": True,
        "requiresOtp": True,
        "phone": phone,
        "delivery": "sms" if sent else "console",
        "message": "PIN verified. A 6-digit SMS code has been sent to your phone." if sent else "PIN verified. SMS delivery failed — check server console for the code."
    }, 200

MOBILE_OTP_STORE = {}
MOBILE_OTP_EXPIRY_MINUTES = 5
MOBILE_OTP_MAX_ATTEMPTS = 5

def _to_e164(phone):
    """Normalize a phone number to E.164 format for Twilio (assumes India +91
    if no country code is present)."""
    digits = re.sub(r"[^\d+]", "", phone or "")
    if digits.startswith("+"):
        return digits
    if len(digits) == 10:
        return f"+91{digits}"
    return f"+{digits}"

def _issue_mobile_otp(phone, user_key, user_name):
    from services.sms_service import send_sms, TWILIO_VERIFY_SID
    e164 = _to_e164(phone)

    if TWILIO_VERIFY_SID:
        sent, msg = send_sms(e164, "")
        if sent:
            print(f"[AUTH][MOBILE-OTP] Twilio Verify SMS sent to {phone} ({user_name})")
        else:
            print(f"[AUTH][MOBILE-OTP] Twilio Verify failed for {phone}: {msg}")
        MOBILE_OTP_STORE[phone] = {
            "otp": None,
            "twilio_verify": True,
            "expires_at": datetime.utcnow() + timedelta(minutes=MOBILE_OTP_EXPIRY_MINUTES),
            "attempts": 0
        }
        return "twilio", sent
    else:
        from services.auth.otp_service import generate_otp
        local_otp = generate_otp()
        sent, msg = send_sms(e164, local_otp)
        if sent:
            print(f"[AUTH][MOBILE-OTP] SMS sent to {phone} ({user_name}): {msg}")
        else:
            print(f"[AUTH][MOBILE-OTP] SMS failed for {phone}: {msg} — OTP: {local_otp}")
        MOBILE_OTP_STORE[phone] = {
            "otp": local_otp,
            "twilio_verify": False,
            "expires_at": datetime.utcnow() + timedelta(minutes=MOBILE_OTP_EXPIRY_MINUTES),
            "attempts": 0
        }
        return local_otp, sent

def send_mobile_otp(phone):
    """Resend the SMS code for a registered mobile number."""
    phone = (phone or "").strip()
    user_key, user = _find_user_by_phone(phone)
    if not user_key:
        return {"success": True, "message": "If this number is registered, a code has been sent"}, 200
    _issue_mobile_otp(phone, user_key, user.get("name", "Mobile User"))
    return {"success": True, "message": "SMS code sent", "delivery": "console"}, 200

def verify_mobile_otp(phone, otp):
    """Verify the SMS code and complete the mobile login (returns a token)."""
    phone = (phone or "").strip()
    otp = (otp or "").strip()

    entry = MOBILE_OTP_STORE.get(phone)
    if not entry:
        return {"success": False, "message": "No code requested or it has expired. Please login again."}, 400
    if datetime.utcnow() > entry["expires_at"]:
        del MOBILE_OTP_STORE[phone]
        return {"success": False, "message": "Code expired. Please login again."}, 400
    if entry["attempts"] >= MOBILE_OTP_MAX_ATTEMPTS:
        del MOBILE_OTP_STORE[phone]
        return {"success": False, "message": "Too many attempts. Please login again."}, 429

    if entry.get("twilio_verify"):
        from services.sms_service import verify_twilio_otp
        valid, msg = verify_twilio_otp(_to_e164(phone), otp)
    else:
        valid = entry.get("otp") == otp
        msg = "local match" if valid else "mismatch"

    if not valid:
        entry["attempts"] += 1
        return {"success": False, "message": "Invalid code"}, 401

    del MOBILE_OTP_STORE[phone]

    user_key, user = _find_user_by_phone(phone)
    if not user_key:
        return {"success": False, "message": "Mobile user not found"}, 401
    roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
    token, refresh = create_token(user_key, user["name"], roles)
    log_event("MOBILE_OTP_VERIFIED", "INFO", "auth", {"phone": phone}, user_key)
    return {
        "success": True,
        "token": token,
        "refreshToken": refresh,
        "user": {"email": user_key, "name": user["name"], "role": user["role"], "phone": phone}
    }, 200

def mobile_register(phone, name, pin):
    """Create a mobile account with a security PIN so the user can log in
    with phone + PIN on the mobile login tab. This is the "set your PIN" step."""
    phone = (phone or "").strip()
    name = (name or "").strip()
    pin = (pin or "").strip()

    if not name:
        return {"success": False, "message": "Name is required"}, 400
    if not phone:
        return {"success": False, "message": "Phone number is required"}, 400
    if not pin.isdigit() or not (4 <= len(pin) <= 6):
        return {"success": False, "message": "PIN must be 4-6 digits"}, 400

    users = load_users()
    mobile_key = f"{phone}@mobile.user"
    for k, v in users.items():
        if v.get("phone", "").replace(" ", "") == phone.replace(" ", ""):
            return {"success": False, "message": "This mobile number is already registered"}, 409

    users[mobile_key] = {
        "name": name,
        "phone": phone,
        "role": "analyst",
        "pin": ph.hash(pin),
        "mfa_enabled": False,
        "mfa_method": "pin",
        "created": datetime.utcnow().isoformat() + "Z",
        "last_login": ""
    }
    save_users()
    log_event("MOBILE_USER_REGISTERED", "INFO", "auth", {"phone": phone}, mobile_key)
    return {"success": True, "message": "Mobile account created. Log in with your phone number and PIN.", "phone": phone}, 201

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

EMAIL_OTP_STORE = {}
EMAIL_OTP_EXPIRY_MINUTES = 5
EMAIL_OTP_MAX_ATTEMPTS = 5

def _issue_email_otp(email, user_name=None):
    from services.auth.otp_service import generate_otp
    from utils.email_service import send_email
    otp = generate_otp()
    EMAIL_OTP_STORE[email] = {
        "otp": otp,
        "expires": datetime.utcnow() + timedelta(minutes=EMAIL_OTP_EXPIRY_MINUTES),
        "attempts": 0,
        "created": datetime.utcnow().isoformat()
    }
    body_html = f"""
    <div style="font-family:Arial,sans-serif;background:#04111e;padding:24px;color:#c9e8f5;">
      <h2 style="color:#00ffe7;letter-spacing:2px;margin:0 0 12px;">CYBERSHIELD SOC</h2>
      <p>Hello {user_name or 'Analyst'},</p>
      <p>Your one-time verification code is:</p>
      <div style="font-size:34px;font-weight:bold;letter-spacing:8px;color:#00ffe7;padding:14px 0;">{otp}</div>
      <p>This code expires in 5 minutes. Do not share it with anyone.</p>
      <p style="opacity:.6;font-size:12px;">— CyberShield Security Team</p>
    </div>"""
    sent, msg = send_email("[CyberShield] Your login verification code", email, body_html)
    if not sent:
        print(f"[AUTH][OTP] Email OTP for {email}: {otp} (SMTP unavailable: {msg})")
    return otp, sent, msg

def send_email_otp(email):
    users = load_users()
    if email not in users:
        return {"success": False, "message": "User not found"}, 404
    _issue_email_otp(email, users[email].get("name"))
    log_event("EMAIL_OTP_SENT", "INFO", "auth", {"email": email, "method": "email_otp"}, email)
    return {"success": True, "message": f"OTP sent to {email}", "delivery": "email"}, 200

def verify_email_otp(email, otp):
    record = EMAIL_OTP_STORE.get(email)
    if not record:
        return {"success": False, "message": "No OTP requested. Please log in again."}, 400
    if datetime.utcnow() > record["expires"]:
        EMAIL_OTP_STORE.pop(email, None)
        return {"success": False, "message": "OTP expired. Request a new one."}, 401
    record["attempts"] += 1
    if record["attempts"] > EMAIL_OTP_MAX_ATTEMPTS:
        EMAIL_OTP_STORE.pop(email, None)
        return {"success": False, "message": "Too many incorrect attempts. Request a new OTP."}, 401
    if str(record["otp"]) != str(otp).strip():
        remaining = EMAIL_OTP_MAX_ATTEMPTS - record["attempts"]
        log_event("EMAIL_OTP_FAILED", "WARNING", "auth", {"email": email, "reason": "invalid_otp"}, email)
        return {"success": False, "message": f"Invalid OTP. {remaining} attempts remaining"}, 401
    EMAIL_OTP_STORE.pop(email, None)
    users = load_users()
    user = users.get(email, {})
    roles = ["admin"] if user.get("role") == "admin" else ["analyst"] if user.get("role") == "analyst" else ["compliance"]
    token, refresh = create_token(email, user.get("name", email), roles)
    users[email]["last_login"] = datetime.utcnow().isoformat() + "Z"
    save_users()
    log_event("EMAIL_OTP_VERIFIED", "INFO", "auth", {"email": email, "method": "email_otp"}, email)
    return {
        "success": True,
        "token": token,
        "refreshToken": refresh,
        "user": {"email": email, "name": user.get("name", email), "role": user.get("role", "analyst")},
        "message": "Login successful"
    }, 200
