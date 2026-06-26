from flask import Blueprint
from controllers.auth_controller import (
    login, mobile_login, verify_otp, verify_mfa,
    sso_login, oauth_authorize, oauth_token, account_recovery, list_users
)
from middleware.auth import token_required, admin_required

auth_bp = Blueprint("auth", __name__)

auth_bp.route("/login", methods=["POST"])(login)
auth_bp.route("/mobile-login", methods=["POST"])(mobile_login)
auth_bp.route("/verify-otp", methods=["POST"])(verify_otp)
auth_bp.route("/verify-mfa", methods=["POST"])(verify_mfa)
auth_bp.route("/sso-login", methods=["POST"])(sso_login)
auth_bp.route("/oauth/authorize", methods=["POST"])(oauth_authorize)
auth_bp.route("/oauth/token", methods=["POST"])(oauth_token)
auth_bp.route("/recovery", methods=["POST"])(account_recovery)
auth_bp.route("/users", methods=["GET"])(token_required(admin_required(list_users)))
