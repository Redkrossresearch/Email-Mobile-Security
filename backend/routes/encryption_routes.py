from flask import Blueprint
from controllers.encryption_controller import (
    encrypt_data, decrypt_data, key_management, tls_status, pgp_encrypt
)
from middleware.auth import token_required

encryption_bp = Blueprint("encryption", __name__)

encryption_bp.route("/encrypt", methods=["POST"])(token_required(encrypt_data))
encryption_bp.route("/decrypt", methods=["POST"])(token_required(decrypt_data))
encryption_bp.route("/keys", methods=["GET"])(token_required(key_management))
encryption_bp.route("/tls-status", methods=["GET"])(token_required(tls_status))
encryption_bp.route("/pgp-encrypt", methods=["POST"])(token_required(pgp_encrypt))
