from flask import Blueprint
from controllers.email_controller import (
    check_spf, check_dkim, check_dmarc, sandbox_analysis, url_analysis,
    lookalike_domain, bec_scan, heuristic_scan, attachment_block,
    outbound_encrypt, analyze_header, sender_scan,
    analyze_eml_file, generate_eml_pdf, generate_eml_xlsx,
    content_disarm, auto_remediate
)
from middleware.auth import token_required

email_bp = Blueprint("email", __name__)

email_bp.route("/check-spf", methods=["POST"])(token_required(check_spf))
email_bp.route("/check-dkim", methods=["POST"])(token_required(check_dkim))
email_bp.route("/check-dmarc", methods=["POST"])(token_required(check_dmarc))
email_bp.route("/sandbox-analysis", methods=["POST"])(token_required(sandbox_analysis))
email_bp.route("/url-analysis", methods=["POST"])(token_required(url_analysis))
email_bp.route("/lookalike-domain", methods=["POST"])(token_required(lookalike_domain))
email_bp.route("/bec-scan", methods=["POST"])(token_required(bec_scan))
email_bp.route("/heuristic-scan", methods=["POST"])(token_required(heuristic_scan))
email_bp.route("/attachment-block", methods=["POST"])(token_required(attachment_block))
email_bp.route("/outbound-encrypt", methods=["POST"])(token_required(outbound_encrypt))
email_bp.route("/analyze-header", methods=["POST"])(token_required(analyze_header))
email_bp.route("/sender-scan", methods=["POST"])(token_required(sender_scan))
email_bp.route("/analyze-eml-file", methods=["POST"])(token_required(analyze_eml_file))
email_bp.route("/eml-report/pdf", methods=["GET"])(token_required(generate_eml_pdf))
email_bp.route("/eml-report/xlsx", methods=["GET"])(token_required(generate_eml_xlsx))
email_bp.route("/content-disarm", methods=["POST"])(token_required(content_disarm))
email_bp.route("/auto-remediate", methods=["POST"])(token_required(auto_remediate))
