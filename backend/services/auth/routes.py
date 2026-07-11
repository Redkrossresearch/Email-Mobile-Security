from flask import Blueprint, request, jsonify, g
from services._shared.jwt_middleware import token_required, admin_required, verify_token, revoke_session
from services.auth.auth_service import (
    password_login, mobile_login, verify_2fa, generate_totp_secret,
    oauth_authorize, oauth_token,
    sso_saml_login, sso_oidc_login,
    initiate_password_reset, reset_password,
    register, refresh_token, list_users
)
from services.auth.otp_service import generate_otp, store_otp, verify_otp as check_otp, send_email_otp, send_sms_otp

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    ip = request.remote_addr
    result, status = password_login(email, password, ip)
    return jsonify(result), status

@auth_bp.route("/mobile-login", methods=["POST"])
def mobile_login_route():
    data = request.get_json() or {}
    result, status = mobile_login(data.get("phone", "").strip(), data.get("pin", ""))
    return jsonify(result), status

@auth_bp.route("/register", methods=["POST"])
def register_route():
    data = request.get_json() or {}
    result, status = register(data.get("username"), data.get("email", "").strip().lower(), data.get("password", ""), data.get("name"))
    return jsonify(result), status

@auth_bp.route("/verify-2fa", methods=["POST"])
def verify_2fa_route():
    data = request.get_json() or {}
    result, status = verify_2fa(data.get("userId", data.get("email", "")), data.get("otp", ""))
    return jsonify(result), status

@auth_bp.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    if not email and not phone:
        return jsonify({"success": False, "message": "Email or phone required"}), 400
    otp = generate_otp()
    if email:
        store_otp(f"otp:{email}", otp)
        sent, msg = send_email_otp(email, otp)
    else:
        store_otp(f"otp:{phone}", otp)
        sent, msg = send_sms_otp(phone, otp)
    if sent:
        return jsonify({"success": True, "message": msg})
    return jsonify({"success": False, "message": msg}), 500

@auth_bp.route("/verify-otp", methods=["POST"])
def verify_otp_route():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    user_id = data.get("userId", email or phone)
    valid = check_otp(f"otp:{user_id}", data.get("otp", ""))
    if valid:
        return jsonify({"success": True, "message": "OTP verified"})
    return jsonify({"success": False, "message": "Invalid or expired OTP"}), 401

@auth_bp.route("/totp/generate", methods=["POST"])
@token_required
def totp_generate():
    data = request.get_json() or {}
    email = data.get("email", g.current_user)
    result, status = generate_totp_secret(email)
    return jsonify(result), status

@auth_bp.route("/oauth/authorize", methods=["POST"])
def oauth_authorize_route():
    data = request.get_json() or {}
    auth_header = request.headers.get("Authorization", "")
    user_id = None
    if auth_header.startswith("Bearer "):
        payload = verify_token(auth_header[7:])
        if payload:
            user_id = payload["sub"]
    result, status = oauth_authorize(data.get("client_id"), data.get("redirect_uri"), data.get("scope", "openid profile"), user_id)
    return jsonify(result), status

@auth_bp.route("/oauth/token", methods=["POST"])
def oauth_token_route():
    data = request.get_json() or {}
    result, status = oauth_token(data.get("code"), data.get("client_id"), data.get("client_secret"))
    return jsonify(result), status

@auth_bp.route("/sso/saml", methods=["POST"])
def sso_saml():
    data = request.get_json() or {}
    result, status = sso_saml_login(data.get("email"), data.get("name", "SSO User"), data.get("idp", "AzureAD"))
    return jsonify(result), status

@auth_bp.route("/sso/oidc", methods=["POST"])
def sso_oidc():
    data = request.get_json() or {}
    result, status = sso_oidc_login(data.get("email"), data.get("name", "OIDC User"), data.get("idp", "Google"))
    return jsonify(result), status

@auth_bp.route("/password-reset", methods=["POST"])
def password_reset():
    data = request.get_json() or {}
    result, status = initiate_password_reset(data.get("email", "").strip().lower())
    return jsonify(result), status

@auth_bp.route("/password-reset/confirm", methods=["POST"])
def password_reset_confirm():
    data = request.get_json() or {}
    result, status = reset_password(data.get("token", ""), data.get("password", ""))
    return jsonify(result), status

@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json() or {}
    result, status = refresh_token(data.get("refreshToken", ""))
    return jsonify(result), status

@auth_bp.route("/me", methods=["GET"])
@token_required
def me():
    return jsonify({"success": True, "user": {"email": g.current_user, "roles": g.user_roles, "trust_score": g.trust_score}})

@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            import jwt as pyjwt
            from services._shared.jwt_middleware import PUBLIC_KEY
            payload = pyjwt.decode(auth_header[7:], PUBLIC_KEY, algorithms=["RS256"])
            revoke_session(payload.get("jti", ""))
        except Exception:
            pass
    return jsonify({"success": True, "message": "Logged out"})

@auth_bp.route("/users", methods=["GET"])
@token_required
@admin_required
def users_list():
    return jsonify({"success": True, "users": list_users(), "total": len(list_users())})
