from flask import Blueprint
from controllers.yara_controller import (
    scan_ip_with_yara, list_yara_rules, create_yara_rule,
    toggle_yara_rule, delete_yara_rule, get_yara_scan_history
)
from middleware.auth import token_required

yara_bp = Blueprint("yara", __name__)

yara_bp.route("/scan-ip", methods=["POST"])(token_required(scan_ip_with_yara))
yara_bp.route("/rules", methods=["GET"])(token_required(list_yara_rules))
yara_bp.route("/rules", methods=["POST"])(token_required(create_yara_rule))
yara_bp.route("/rules/toggle", methods=["POST"])(token_required(toggle_yara_rule))
yara_bp.route("/rules/delete", methods=["POST"])(token_required(delete_yara_rule))
yara_bp.route("/history", methods=["GET"])(token_required(get_yara_scan_history))
