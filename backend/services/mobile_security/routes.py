from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.mobile_security.mobile_service import (
    get_devices, get_device_detail, scan_apps, analyze_sms,
    malware_scan, get_sms_logs, get_call_logs,
    device_health, get_dashboard_stats,
    app_reputation, caller_scan, caller_feed, volte_status
)

mobile_bp = Blueprint("mobile_service", __name__)

@mobile_bp.route("/devices", methods=["GET"])
@token_required
def devices(current_user=None):
    return jsonify({"success": True, "devices": get_devices()})

@mobile_bp.route("/devices/<device_id>", methods=["GET"])
@token_required
def device_detail(current_user=None, device_id=None):
    return jsonify({"success": True, **get_device_detail(device_id)})

@mobile_bp.route("/scan-apps", methods=["GET"])
@token_required
def scan_apps_route(current_user=None):
    device_id = request.args.get("device_id")
    return jsonify({"success": True, "apps": scan_apps(device_id)})

@mobile_bp.route("/analyze-sms", methods=["POST"])
@token_required
def sms_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **analyze_sms(data.get("sms_text", ""), data.get("sender_number", ""))})

@mobile_bp.route("/malware-scan", methods=["GET"])
@token_required
def malware_route(current_user=None):
    file_hash = request.args.get("hash", "")
    return jsonify({"success": True, **malware_scan(file_hash)})

@mobile_bp.route("/sms-logs", methods=["GET"])
@token_required
def sms_logs_route(current_user=None):
    return jsonify({"success": True, "sms_logs": get_sms_logs()})

@mobile_bp.route("/call-logs", methods=["GET"])
@token_required
def call_logs_route(current_user=None):
    return jsonify({"success": True, "call_logs": get_call_logs()})

@mobile_bp.route("/device-health", methods=["GET"])
@token_required
def health_route(current_user=None):
    device_id = request.args.get("device_id", "default")
    return jsonify({"success": True, **device_health(device_id)})

@mobile_bp.route("/dashboard-stats", methods=["GET"])
@token_required
def dashboard_route(current_user=None):
    return jsonify({"success": True, **get_dashboard_stats()})

@mobile_bp.route("/app-reputation", methods=["POST"])
@token_required
def app_rep_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **app_reputation(data.get("package_name", ""))})

@mobile_bp.route("/caller-scan", methods=["POST"])
@token_required
def caller_scan_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **caller_scan(data.get("phone_number", ""))})

@mobile_bp.route("/caller-feed", methods=["GET"])
@token_required
def caller_feed_route(current_user=None):
    return jsonify({"success": True, "caller_feed": caller_feed()})

@mobile_bp.route("/volte-status", methods=["GET"])
@token_required
def volte_route(current_user=None):
    device_id = request.args.get("device_id", "default")
    return jsonify({"success": True, **volte_status(device_id)})
