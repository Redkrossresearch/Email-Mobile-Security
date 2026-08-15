from flask import Blueprint
from controllers.auth_controller import (
    login, mobile_login, register, verify_otp, verify_mfa,
    sso_login, oauth_authorize, oauth_token, account_recovery, list_users,
    generate_totp, send_otp, send_email_otp, verify_email_otp
)
from middleware.auth import token_required, admin_required

auth_bp = Blueprint("auth", __name__)

auth_bp.route("/login", methods=["POST"])(login)
auth_bp.route("/mobile-login", methods=["POST"])(mobile_login)
auth_bp.route("/register", methods=["POST"])(register)
auth_bp.route("/send-email-otp", methods=["POST"])(send_email_otp)
auth_bp.route("/verify-email-otp", methods=["POST"])(verify_email_otp)
auth_bp.route("/verify-otp", methods=["POST"])(verify_otp)
auth_bp.route("/verify-mfa", methods=["POST"])(verify_mfa)
auth_bp.route("/sso-login", methods=["POST"])(sso_login)
auth_bp.route("/oauth/authorize", methods=["POST"])(oauth_authorize)
auth_bp.route("/oauth/token", methods=["POST"])(oauth_token)
auth_bp.route("/recovery", methods=["POST"])(account_recovery)
auth_bp.route("/users", methods=["GET"])(token_required(admin_required(list_users)))
auth_bp.route("/generate-totp", methods=["POST"])(token_required(generate_totp))
auth_bp.route("/send-otp", methods=["POST"])(send_otp)
