from flask import Blueprint
from controllers.reports_controller import (
    generate_pdf, generate_csv, generate_json,
    generate_comprehensive, generate_threat_report
)
from middleware.auth import token_required

report_bp = Blueprint("reports", __name__)

report_bp.route("/download-pdf", methods=["GET"])(token_required(generate_pdf))
report_bp.route("/download-csv", methods=["GET"])(token_required(generate_csv))
report_bp.route("/download-json", methods=["GET"])(token_required(generate_json))
report_bp.route("/comprehensive", methods=["GET"])(token_required(generate_comprehensive))
report_bp.route("/threat-report", methods=["GET"])(token_required(generate_threat_report))
