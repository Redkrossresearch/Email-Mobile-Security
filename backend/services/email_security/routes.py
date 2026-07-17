from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.email_security.email_service import (
    check_spf as svc_spf, check_dkim as svc_dkim, check_dmarc as svc_dmarc,
    analyze_phishing, sender_reputation as svc_sender_rep,
    content_disarm as svc_disarm, add_to_allow_list, add_to_block_list
)

# Re-use old controller functions for endpoints not yet ported to the service layer
from controllers.email_controller import (
    sandbox_analysis as ctrl_sandbox, url_analysis as ctrl_url,
    lookalike_domain as ctrl_lookalike, bec_scan as ctrl_bec,
    heuristic_scan as ctrl_heuristic, attachment_block as ctrl_attachment,
    outbound_encrypt as ctrl_encrypt, analyze_header as ctrl_header,
    analyze_eml_file as ctrl_eml, generate_eml_pdf as ctrl_pdf,
    generate_eml_xlsx as ctrl_xlsx, auto_remediate as ctrl_remediate
)

email_bp = Blueprint("email", __name__)

@email_bp.route("/check-spf", methods=["POST"])
@token_required
def spf(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **svc_spf(data.get("domain", "").strip().lower())})

@email_bp.route("/check-dkim", methods=["POST"])
@token_required
def dkim(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **svc_dkim(data.get("domain", "").strip().lower(), data.get("selector"))})

@email_bp.route("/check-dmarc", methods=["POST"])
@token_required
def dmarc(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **svc_dmarc(data.get("domain", "").strip().lower())})

@email_bp.route("/phishing-scan", methods=["POST"])
@token_required
def phishing(current_user=None):
    data = request.get_json() or {}
    return jsonify(analyze_phishing(data.get("body", ""), data.get("subject", ""), data.get("sender", ""), data.get("reply_to", "")))

@email_bp.route("/sender-scan", methods=["POST"])
@token_required
def sender(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **svc_sender_rep(data.get("email", "").strip().lower(), data.get("sender_ip", ""))})

@email_bp.route("/content-disarm", methods=["POST"])
@token_required
def disarm(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **svc_disarm(data.get("content", ""))})

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

# ── Old controller endpoints re-wired ──

@email_bp.route("/sandbox-analysis", methods=["POST"])
@token_required
def sandbox(current_user=None):
    return ctrl_sandbox(current_user)

@email_bp.route("/url-analysis", methods=["POST"])
@token_required
def url_scan(current_user=None):
    return ctrl_url(current_user)

@email_bp.route("/lookalike-domain", methods=["POST"])
@token_required
def lookalike(current_user=None):
    return ctrl_lookalike(current_user)

@email_bp.route("/bec-scan", methods=["POST"])
@token_required
def bec(current_user=None):
    return ctrl_bec(current_user)

@email_bp.route("/heuristic-scan", methods=["POST"])
@token_required
def heuristic(current_user=None):
    return ctrl_heuristic(current_user)

@email_bp.route("/attachment-block", methods=["POST"])
@token_required
def attachment(current_user=None):
    return ctrl_attachment(current_user)

@email_bp.route("/outbound-encrypt", methods=["POST"])
@token_required
def outbound_encrypt(current_user=None):
    return ctrl_encrypt(current_user)

@email_bp.route("/analyze-header", methods=["POST"])
@token_required
def header(current_user=None):
    return ctrl_header(current_user)

@email_bp.route("/analyze-eml-file", methods=["POST"])
@token_required
def eml_file(current_user=None):
    return ctrl_eml(current_user)

@email_bp.route("/eml-report/pdf", methods=["GET"])
@token_required
def eml_pdf(current_user=None):
    return ctrl_pdf(current_user)

@email_bp.route("/eml-report/xlsx", methods=["GET"])
@token_required
def eml_xlsx(current_user=None):
    return ctrl_xlsx(current_user)

@email_bp.route("/auto-remediate", methods=["POST"])
@token_required
def auto_remediate(current_user=None):
    return ctrl_remediate(current_user)
