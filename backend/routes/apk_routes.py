from flask import Blueprint
from controllers.apk_analyzer_controller import (
    decompile_apk, static_analysis, malware_scan_apk,
    list_apk_analyses, apk_tools_status
)
from middleware.auth import token_required

apk_bp = Blueprint("apk", __name__)

apk_bp.route("/decompile", methods=["POST"])(token_required(decompile_apk))
apk_bp.route("/static-analysis", methods=["POST"])(token_required(static_analysis))
apk_bp.route("/malware-scan", methods=["POST"])(token_required(malware_scan_apk))
apk_bp.route("/analyses", methods=["GET"])(token_required(list_apk_analyses))
apk_bp.route("/tools-status", methods=["GET"])(token_required(apk_tools_status))
