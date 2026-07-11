from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.threat_intel.threat_intel_service import (
    fetch_ioc_feeds, ioc_lookup, generate_alert, list_alerts, scan_hash,
    dns_sinkhole, trigger_soar
)

threat_intel_bp = Blueprint("threat_intel_service", __name__)

@threat_intel_bp.route("/feeds", methods=["GET"])
@token_required
def feeds(current_user=None):
    return jsonify({"success": True, **fetch_ioc_feeds()})

@threat_intel_bp.route("/ioc-lookup", methods=["POST"])
@token_required
def ioc_lookup_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **ioc_lookup(data.get("ioc_type", ""), data.get("ioc_value", ""))})

@threat_intel_bp.route("/alerts", methods=["GET"])
@token_required
def alerts_list(current_user=None):
    return jsonify({"success": True, "alerts": list_alerts()})

@threat_intel_bp.route("/alerts/generate", methods=["POST"])
@token_required
def alerts_generate(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, "alert": generate_alert(data.get("type", "general"), data.get("title", ""), data.get("severity", "medium"), data.get("description", ""), data.get("source", "manual"))})

@threat_intel_bp.route("/scan-hash", methods=["POST"])
@token_required
def hash_scan(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **scan_hash(data.get("hash", ""))})

@threat_intel_bp.route("/dns-sinkhole", methods=["POST"])
@token_required
def sinkhole(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **dns_sinkhole(data.get("domain", ""), data.get("action", "block"))})

@threat_intel_bp.route("/soar/trigger", methods=["POST"])
@token_required
def soar(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **trigger_soar(data.get("playbook", "generic_incident_response"), data.get("target", ""), data.get("params", {}))})
