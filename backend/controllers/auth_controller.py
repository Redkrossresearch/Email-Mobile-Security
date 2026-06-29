import json
import hashlib
import uuid
import pyotp
from datetime import datetime
from flask import request, jsonify
from config.settings import DATA_DIR
from middleware.auth import create_token

USER_DB = None
LOGIN_ATTEMPTS = {}
OAUTH_TOKENS = {}

def load_users():
    global USER_DB
    if USER_DB is None:
        with open(f"{DATA_DIR}/users.json") as f:
            USER_DB = json.load(f)
    return USER_DB

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
    if email not in users or users[email]["password"] != password:
        if email not in LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[email] = {"count": 0, "first_attempt": datetime.utcnow()}
        LOGIN_ATTEMPTS[email]["count"] += 1
        remaining = 5 - LOGIN_ATTEMPTS[email]["count"]
        return jsonify({"success": False, "message": f"Invalid credentials. {max(0, remaining)} attempts remaining"}), 401
    LOGIN_ATTEMPTS.pop(email, None)
    user = users[email]
    token = create_token(email, user["name"], user["role"])
    resp = {
        "success": True,
        "token": token,
        "user": {"email": email, "name": user["name"], "role": user["role"], "mfa_enabled": user["mfa_enabled"]},
        "message": "Login successful"
    }
    if user.get("mfa_enabled") and user.get("totp_secret"):
        resp.update({
            "requires2FA": True,
            "userId": email,
            "qrCode": f"otpauth://totp/CyberShield:{email}?secret={user['totp_secret']}&issuer=CyberShield"
        })
    return jsonify(resp)

def mobile_login():
    data = request.get_json()
    phone = data.get("phone", "").strip()
    pin = data.get("pin", "")
    if pin != "123456":
        return jsonify({"success": False, "message": "Invalid PIN"}), 401
    token = create_token(f"{phone}@mobile.user", "Mobile User", "analyst")
    return jsonify({
        "success": True,
        "token": token,
        "user": {"name": "Mobile User", "role": "analyst", "phone": phone},
        "message": "Mobile login successful"
    })

def verify_otp():
    data = request.get_json()
    otp = data.get("otp", "")
    if otp == "123456":
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
