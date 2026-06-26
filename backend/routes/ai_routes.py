from flask import Blueprint
from controllers.ai_engine_controller import (
    analyze_ioc_with_ai, analyze_email_with_ai, ai_search_engine,
    list_ai_models, get_analysis_history, generate_ai_report
)
from middleware.auth import token_required

ai_bp = Blueprint("ai", __name__)

ai_bp.route("/analyze-ioc", methods=["POST"])(token_required(analyze_ioc_with_ai))
ai_bp.route("/analyze-email", methods=["POST"])(token_required(analyze_email_with_ai))
ai_bp.route("/search", methods=["POST"])(token_required(ai_search_engine))
ai_bp.route("/models", methods=["GET"])(token_required(list_ai_models))
ai_bp.route("/history", methods=["GET"])(token_required(get_analysis_history))
ai_bp.route("/generate-report", methods=["POST"])(token_required(generate_ai_report))
