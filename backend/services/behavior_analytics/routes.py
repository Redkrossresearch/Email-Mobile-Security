from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.behavior_analytics.ueba_service import (
    analyze_behavior, get_user_profile, login_anomaly_detection, risk_scoring
)

ueba_bp = Blueprint("ueba_service", __name__)

@ueba_bp.route("/analyze-behavior", methods=["POST"])
@token_required
def behavior_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **analyze_behavior(data.get("email", ""), data.get("login_data", {}))})

@ueba_bp.route("/user-profile", methods=["POST"])
@token_required
def user_profile_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **get_user_profile(data.get("email", ""))})

@ueba_bp.route("/login-anomaly", methods=["POST"])
@token_required
def login_anomaly_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **login_anomaly_detection(data.get("email", ""), data.get("ip_address", ""), data.get("user_agent", ""), data.get("device_fingerprint", ""))})

@ueba_bp.route("/risk-score", methods=["POST"])
@token_required
def risk_score_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **risk_scoring(data.get("email", ""), data.get("context_data", {}))})
