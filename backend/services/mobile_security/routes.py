from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.mobile_security.mobile_service import (
    get_devices, get_device_detail, scan_apps, analyze_sms,
    malware_scan, get_sms_logs, get_call_logs, check_battery,
    device_health, get_dashboard_stats,
    app_reputation, caller_scan, caller_feed, report_caller, volte_status,
    register_device
)
from config.database import _query, _insert, _update_stat, _get_stat

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
    text = data.get("text") or data.get("sms_text") or ""
    return jsonify({"success": True, **analyze_sms(text, data.get("sender_number", ""))})

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

@mobile_bp.route("/check-battery", methods=["GET"])
@token_required
def battery_route(current_user=None):
    return jsonify(check_battery())

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
    return jsonify({"success": True, **app_reputation(data.get("package_name", ""), data.get("file_hash", ""))})

@mobile_bp.route("/caller-scan", methods=["POST"])
@token_required
def caller_scan_route(current_user=None):
    data = request.get_json() or {}
    phone = data.get("phone") or data.get("phone_number") or ""
    return jsonify({"success": True, **caller_scan(phone)})

@mobile_bp.route("/caller-feed", methods=["GET"])
@token_required
def caller_feed_route(current_user=None):
    return jsonify(caller_feed())

@mobile_bp.route("/report-caller", methods=["POST"])
@token_required
def report_caller_route(current_user=None):
    data = request.get_json() or {}
    phone = data.get("phone") or data.get("phone_number") or ""
    category = data.get("category") or "scam"
    caller_name = data.get("caller_name") or ""
    if not phone:
        return jsonify({"success": False, "error": "Phone number is required"}), 400
    return jsonify(report_caller(phone, category, caller_name))

@mobile_bp.route("/volte-status", methods=["GET"])
@token_required
def volte_route(current_user=None):
    device_id = request.args.get("device_id", "default")
    return jsonify({"success": True, **volte_status(device_id)})

@mobile_bp.route("/caller-history", methods=["GET"])
@token_required
def caller_history_route(current_user=None):
    limit = int(request.args.get("limit", 50))
    rows = _query("SELECT * FROM caller_history ORDER BY created_at DESC LIMIT ?", (limit,))
    return jsonify({"success": True, "history": rows, "total": len(rows)})

@mobile_bp.route("/call-log", methods=["POST"])
@token_required
def add_call_log_route(current_user=None):
    data = request.get_json() or {}
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "message": "Phone required"}), 400
    _insert("call_logs", {
        "phone": phone, "name": data.get("name", "Unknown"),
        "direction": data.get("direction", "incoming"),
        "duration": data.get("duration", 0),
        "blocked": 1 if data.get("blocked") else 0,
        "spam_type": data.get("spam_type", "legitimate"),
        "score": data.get("score", 0),
        "risk_level": data.get("risk_level", "safe")
    })
    _update_stat("total_call_logs")
    if data.get("blocked"):
        _update_stat("calls_blocked")
    return jsonify({"success": True, "message": "Call log saved"})

@mobile_bp.route("/sms-history", methods=["GET"])
@token_required
def sms_history_route(current_user=None):
    limit = int(request.args.get("limit", 50))
    rows = _query("SELECT * FROM sms_scan_history ORDER BY created_at DESC LIMIT ?", (limit,))
    return jsonify({"success": True, "history": rows, "total": len(rows)})

@mobile_bp.route("/scan-stats", methods=["GET"])
@token_required
def scan_stats_route(current_user=None):
    return jsonify({
        "success": True,
        "stats": {
            "total_scans": _get_stat("total_scans"),
            "threats_blocked": _get_stat("threats_blocked"),
            "total_sms_scans": _get_stat("total_sms_scans"),
            "phishing_blocked": _get_stat("phishing_blocked"),
            "total_call_logs": _get_stat("total_call_logs"),
            "calls_blocked": _get_stat("calls_blocked"),
        }
    })


@mobile_bp.route("/register-device", methods=["POST"])
@token_required
def register_device_route(current_user=None):
    data = request.get_json() or {}
    device_id = data.get("device_id", "").strip()
    name = data.get("name", "").strip()
    if not device_id or not name:
        return jsonify({"success": False, "error": "device_id and name are required"}), 400
    result = register_device(
        device_id, name,
        platform=data.get("platform", "Android"),
        os_version=data.get("os_version", "Unknown"),
        model=data.get("model", "Unknown"),
        imei=data.get("imei", ""),
        registered_by=current_user.get("email", "") if isinstance(current_user, dict) else str(current_user),
    )
    return jsonify(result)
