from flask import Blueprint
from controllers.threat_intel_controller import (
    fetch_ioc_feeds, ioc_lookup, generate_alert, list_alerts, scan_hash,
    dns_sinkhole, trigger_soar
)
from middleware.auth import token_required

threat_intel_bp = Blueprint("threat_intel", __name__)

threat_intel_bp.route("/feeds", methods=["GET"])(token_required(fetch_ioc_feeds))
threat_intel_bp.route("/ioc-lookup", methods=["POST"])(token_required(ioc_lookup))
threat_intel_bp.route("/alerts", methods=["GET"])(token_required(list_alerts))
threat_intel_bp.route("/alerts/generate", methods=["POST"])(token_required(generate_alert))
threat_intel_bp.route("/scan-hash", methods=["POST"])(token_required(scan_hash))
threat_intel_bp.route("/dns-sinkhole", methods=["POST"])(token_required(dns_sinkhole))
threat_intel_bp.route("/soar/trigger", methods=["POST"])(token_required(trigger_soar))
