from flask import Blueprint
from controllers.ueba_controller import (
    analyze_behavior, get_user_profile, login_anomaly_detection, risk_scoring
)
from middleware.auth import token_required

ueba_bp = Blueprint("ueba", __name__)

ueba_bp.route("/analyze-behavior", methods=["POST"])(token_required(analyze_behavior))
ueba_bp.route("/user-profile", methods=["POST"])(token_required(get_user_profile))
ueba_bp.route("/login-anomaly", methods=["POST"])(token_required(login_anomaly_detection))
ueba_bp.route("/risk-score", methods=["POST"])(token_required(risk_scoring))
