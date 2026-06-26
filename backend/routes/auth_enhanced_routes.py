from flask import Blueprint
from controllers.auth_enhanced_controller import (
    double_auth_verify, initiate_password_reset, verify_reset_token,
    reset_password, oauth_initiate, oauth_callback,
    create_session, validate_session, revoke_session, list_sessions,
    argon2_status
)
from middleware.auth import token_required

auth_enhanced_bp = Blueprint("auth-enhanced", __name__)

auth_enhanced_bp.route("/double-auth", methods=["POST"])(double_auth_verify)
auth_enhanced_bp.route("/password-reset", methods=["POST"])(initiate_password_reset)
auth_enhanced_bp.route("/verify-reset-token", methods=["POST"])(verify_reset_token)
auth_enhanced_bp.route("/reset-password", methods=["POST"])(reset_password)
auth_enhanced_bp.route("/oauth-initiate", methods=["POST"])(oauth_initiate)
auth_enhanced_bp.route("/oauth-callback", methods=["POST"])(oauth_callback)
auth_enhanced_bp.route("/session-create", methods=["POST"])(token_required(create_session))
auth_enhanced_bp.route("/session-validate", methods=["POST"])(token_required(validate_session))
auth_enhanced_bp.route("/session-revoke", methods=["POST"])(token_required(revoke_session))
auth_enhanced_bp.route("/sessions-list", methods=["GET"])(token_required(list_sessions))
auth_enhanced_bp.route("/argon2-status", methods=["GET"])(token_required(argon2_status))
