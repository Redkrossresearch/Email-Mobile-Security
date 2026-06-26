from flask import Blueprint
from controllers.sandbox_controller import (
    create_sandbox, upload_to_sandbox, sandbox_status, destroy_sandbox
)
from middleware.auth import token_required

sandbox_bp = Blueprint("sandbox", __name__)

sandbox_bp.route("/create", methods=["POST"])(token_required(create_sandbox))
sandbox_bp.route("/upload", methods=["POST"])(token_required(upload_to_sandbox))
sandbox_bp.route("/status", methods=["GET"])(token_required(sandbox_status))
sandbox_bp.route("/destroy", methods=["POST"])(token_required(destroy_sandbox))
