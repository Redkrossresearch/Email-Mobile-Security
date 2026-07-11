from flask import Blueprint, request, jsonify
from middleware.auth import token_required
from services.encryption.encryption_service import (
    encrypt_data, decrypt_data, key_management, tls_status, pgp_encrypt,
    pgp_decrypt, field_level_tokenization, detokenize, encrypt_field, decrypt_field
)

encryption_bp = Blueprint("encryption_service", __name__)

@encryption_bp.route("/encrypt", methods=["POST"])
@token_required
def encrypt_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **encrypt_data(data.get("plaintext", ""), data.get("algorithm", "aes-256-gcm"))})

@encryption_bp.route("/decrypt", methods=["POST"])
@token_required
def decrypt_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **decrypt_data(data.get("ciphertext", ""), data.get("algorithm", "aes-256-gcm"))})

@encryption_bp.route("/keys", methods=["GET"])
@token_required
def keys_route(current_user=None):
    action = request.args.get("action", "list")
    return jsonify({"success": True, **key_management(action)})

@encryption_bp.route("/tls-status", methods=["GET"])
@token_required
def tls_route(current_user=None):
    domain = request.args.get("domain", "example.com")
    return jsonify({"success": True, **tls_status(domain)})

@encryption_bp.route("/pgp-encrypt", methods=["POST"])
@token_required
def pgp_encrypt_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **pgp_encrypt(data.get("plaintext", ""), data.get("recipient_public_key"))})

@encryption_bp.route("/pgp-decrypt", methods=["POST"])
@token_required
def pgp_decrypt_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **pgp_decrypt(data.get("ciphertext", ""))})

@encryption_bp.route("/tokenize", methods=["POST"])
@token_required
def tokenize_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **field_level_tokenization(data.get("value", ""), data.get("token_type", "general"))})

@encryption_bp.route("/detokenize", methods=["POST"])
@token_required
def detokenize_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **detokenize(data.get("token", ""))})

@encryption_bp.route("/encrypt-field", methods=["POST"])
@token_required
def encrypt_field_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **encrypt_field(data.get("plaintext", ""), data.get("field_name", "unknown"))})

@encryption_bp.route("/decrypt-field", methods=["POST"])
@token_required
def decrypt_field_route(current_user=None):
    data = request.get_json() or {}
    return jsonify({"success": True, **decrypt_field(data.get("ciphertext", ""), data.get("field_name", "unknown"))})
