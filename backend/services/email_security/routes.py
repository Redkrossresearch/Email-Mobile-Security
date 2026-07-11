from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.email_security.email_service import (
    check_spf, check_dkim, check_dmarc, analyze_phishing, sender_reputation,
    content_disarm, add_to_allow_list, add_to_block_list
)

email_bp = Blueprint("email", __name__)

@email_bp.route("/check-spf", methods=["POST"])
@token_required
def spf(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **check_spf(data.get("domain", "").strip().lower())})

@email_bp.route("/check-dkim", methods=["POST"])
@token_required
def dkim(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **check_dkim(data.get("domain", "").strip().lower(), data.get("selector"))})

@email_bp.route("/check-dmarc", methods=["POST"])
@token_required
def dmarc(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **check_dmarc(data.get("domain", "").strip().lower())})

@email_bp.route("/phishing-scan", methods=["POST"])
@token_required
def phishing(current_user=None):
    data = request.get_json() or {}
    return jsonify(analyze_phishing(data.get("body", ""), data.get("subject", ""), data.get("sender", ""), data.get("reply_to", "")))

@email_bp.route("/sender-scan", methods=["POST"])
@token_required
def sender(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **sender_reputation(data.get("email", "").strip().lower(), data.get("sender_ip", ""))})

@email_bp.route("/content-disarm", methods=["POST"])
@token_required
def disarm(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **content_disarm(data.get("content", ""))})

@email_bp.route("/allow-list", methods=["POST"])
@token_required
def allow_list(current_user=None):
    data = request.get_json() or {}
    add_to_allow_list(data.get("sender", ""))
    return jsonify({"success": True, "message": f"{data.get('sender')} added to allow list"})

@email_bp.route("/block-list", methods=["POST"])
@token_required
def block_list(current_user=None):
    data = request.get_json() or {}
    add_to_block_list(data.get("sender", ""))
    return jsonify({"success": True, "message": f"{data.get('sender')} added to block list"})
