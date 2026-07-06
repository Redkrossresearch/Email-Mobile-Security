from flask import Blueprint
from controllers.mobile_controller import (
    get_devices, get_device_detail, scan_apps, analyze_sms,
    malware_scan, get_sms_logs, get_call_logs,
    device_health, get_dashboard_stats,
    app_reputation, caller_scan, caller_feed,
    volte_status
)
from middleware.auth import token_required

mobile_bp = Blueprint("mobile", __name__)

mobile_bp.route("/devices", methods=["GET"])(token_required(get_devices))
mobile_bp.route("/devices/<device_id>", methods=["GET"])(token_required(get_device_detail))
mobile_bp.route("/scan-apps", methods=["GET"])(token_required(scan_apps))
mobile_bp.route("/analyze-sms", methods=["POST"])(token_required(analyze_sms))
mobile_bp.route("/malware-scan", methods=["GET"])(token_required(malware_scan))
mobile_bp.route("/sms-logs", methods=["GET"])(token_required(get_sms_logs))
mobile_bp.route("/call-logs", methods=["GET"])(token_required(get_call_logs))
mobile_bp.route("/device-health", methods=["GET"])(token_required(device_health))
mobile_bp.route("/dashboard-stats", methods=["GET"])(token_required(get_dashboard_stats))
mobile_bp.route("/app-reputation", methods=["POST"])(token_required(app_reputation))
mobile_bp.route("/caller-scan", methods=["POST"])(token_required(caller_scan))
mobile_bp.route("/caller-feed", methods=["GET"])(token_required(caller_feed))
mobile_bp.route("/volte-status", methods=["GET"])(token_required(volte_status))
