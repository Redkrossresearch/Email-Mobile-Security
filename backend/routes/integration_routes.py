from flask import Blueprint
from services.gmail_service import gmail_connect, gmail_scan_inbox, gmail_search, gmail_disconnect
from services.graph_service import graph_connect, graph_list_users, graph_scan_mail, graph_audit_logs, graph_disconnect
from middleware.auth import token_required

integration_bp = Blueprint("integration", __name__)

integration_bp.route("/gmail/connect", methods=["POST"])(token_required(gmail_connect))
integration_bp.route("/gmail/scan", methods=["POST"])(token_required(gmail_scan_inbox))
integration_bp.route("/gmail/search", methods=["POST"])(token_required(gmail_search))
integration_bp.route("/gmail/disconnect", methods=["POST"])(token_required(gmail_disconnect))
integration_bp.route("/graph/connect", methods=["POST"])(token_required(graph_connect))
integration_bp.route("/graph/users", methods=["POST"])(token_required(graph_list_users))
integration_bp.route("/graph/scan-mail", methods=["POST"])(token_required(graph_scan_mail))
integration_bp.route("/graph/audit-logs", methods=["POST"])(token_required(graph_audit_logs))
integration_bp.route("/graph/disconnect", methods=["POST"])(token_required(graph_disconnect))
