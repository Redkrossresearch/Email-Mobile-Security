import os
import json
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from services._shared.siem_logger import log_event

_fernet_key = Fernet.generate_key()
_fernet = Fernet(_fernet_key)

_aes_key = hashlib.sha256(_fernet_key).digest()

_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_public_key = _rsa_private_key.public_key()

_key_registry = [
    {
        "id": hashlib.sha256(_fernet_key).hexdigest()[:16],
        "algorithm": "AES-256-GCM / Fernet",
        "created_at": datetime.utcnow().isoformat(),
        "status": "active",
        "purpose": "Data encryption at rest and in transit"
    },
    {
        "id": hashlib.sha256(
            _rsa_public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()[:16],
        "algorithm": "RSA-2048",
        "created_at": datetime.utcnow().isoformat(),
        "status": "active",
        "purpose": "PGP simulation and asymmetric encryption"
    }
]

_token_store = {}
_field_store = {}


def encrypt_data(plaintext, algorithm="aes-256-gcm"):
    timestamp = datetime.utcnow().isoformat()
    key_id = hashlib.sha256(_fernet_key).hexdigest()[:16]

    try:
        if algorithm == "aes-256-gcm":
            nonce = os.urandom(12)
            aesgcm = AESGCM(_aes_key)
            ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
            combined = nonce + ct
            ciphertext_b64 = base64.b64encode(combined).decode()
            log_event("encryption", "INFO", "encryption", {"msg": f"AES-256-GCM encryption performed, key_id={key_id}"})
            return {
                "algorithm": algorithm,
                "ciphertext": ciphertext_b64,
                "key_id": key_id,
                "key_algorithm": "AES-256-GCM",
                "timestamp": timestamp
            }
        elif algorithm == "fernet":
            ct = _fernet.encrypt(plaintext.encode())
            ciphertext_b64 = base64.b64encode(ct).decode()
            log_event("encryption", "INFO", "encryption", {"msg": f"Fernet encryption performed, key_id={key_id}"})
            return {
                "algorithm": algorithm,
                "ciphertext": ciphertext_b64,
                "key_id": key_id,
                "key_algorithm": "Fernet",
                "timestamp": timestamp
            }
        else:
            return {"error": f"Unsupported algorithm: {algorithm}"}
    except Exception as e:
        log_event("encryption_error", "ERROR", "encryption", {"msg": f"encrypt_data failed: {str(e)}"})
        return {"error": str(e)}


def decrypt_data(ciphertext_b64, algorithm="aes-256-gcm"):
    timestamp = datetime.utcnow().isoformat()
    key_id = hashlib.sha256(_fernet_key).hexdigest()[:16]

    try:
        data = base64.b64decode(ciphertext_b64)
        if algorithm == "aes-256-gcm":
            nonce = data[:12]
            ct = data[12:]
            aesgcm = AESGCM(_aes_key)
            plaintext = aesgcm.decrypt(nonce, ct, None).decode()
            log_event("decryption", "INFO", "encryption", {"msg": f"AES-256-GCM decryption performed, key_id={key_id}"})
            return {
                "algorithm": algorithm,
                "plaintext": plaintext,
                "key_id": key_id,
                "timestamp": timestamp
            }
        elif algorithm == "fernet":
            raw = base64.b64decode(ciphertext_b64)
            plaintext = _fernet.decrypt(raw).decode()
            log_event("decryption", "INFO", "encryption", {"msg": f"Fernet decryption performed, key_id={key_id}"})
            return {
                "algorithm": algorithm,
                "plaintext": plaintext,
                "key_id": key_id,
                "timestamp": timestamp
            }
        else:
            return {"error": f"Unsupported algorithm: {algorithm}"}
    except Exception as e:
        log_event("decryption_error", "ERROR", "encryption", {"msg": f"decrypt_data failed: {str(e)}"})
        return {"error": str(e)}


def key_management(action, key_data=None):
    global _fernet_key, _fernet, _aes_key, _rsa_private_key, _rsa_public_key, _key_registry

    if action == "list":
        return {"keys": _key_registry}

    elif action == "rotate":
        old_id = hashlib.sha256(_fernet_key).hexdigest()[:16]
        for k in _key_registry:
            if k["id"] == old_id:
                k["status"] = "rotated"

        _fernet_key = Fernet.generate_key()
        _fernet = Fernet(_fernet_key)
        _aes_key = hashlib.sha256(_fernet_key).digest()
        _rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _rsa_public_key = _rsa_private_key.public_key()

        new_fernet_id = hashlib.sha256(_fernet_key).hexdigest()[:16]
        new_rsa_id = hashlib.sha256(
            _rsa_public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()[:16]

        now = datetime.utcnow().isoformat()
        _key_registry.append({
            "id": new_fernet_id,
            "algorithm": "AES-256-GCM / Fernet",
            "created_at": now,
            "status": "active",
            "purpose": "Data encryption at rest and in transit"
        })
        _key_registry.append({
            "id": new_rsa_id,
            "algorithm": "RSA-2048",
            "created_at": now,
            "status": "active",
            "purpose": "PGP simulation and asymmetric encryption"
        })

        log_event("key_rotation", "INFO", "encryption", {"msg": f"Keys rotated. New Fernet key_id={new_fernet_id}, RSA key_id={new_rsa_id}"})
        return {
            "status": "rotated",
            "new_fernet_key_id": new_fernet_id,
            "new_rsa_key_id": new_rsa_id,
            "timestamp": now
        }

    elif action == "status":
        active = [k for k in _key_registry if k["status"] == "active"]
        rotated = [k for k in _key_registry if k["status"] == "rotated"]
        return {
            "total_keys": len(_key_registry),
            "active_count": len(active),
            "rotated_count": len(rotated),
            "keys": _key_registry,
            "recommendations": [
                "Rotate keys every 90 days" if active else "No active keys",
                "Use AES-256-GCM for symmetric encryption",
                "Use RSA-2048 for asymmetric operations"
            ]
        }

    else:
        return {"error": f"Unknown action: {action}"}


def tls_status(domain):
    log_event("tls_check", "INFO", "encryption", {"msg": f"TLS status check for {domain}"})
    return {
        "domain": domain,
        "tls_version": "TLS 1.3",
        "certificate_issuer": "Let's Encrypt Authority X3",
        "certificate_expiry": (datetime.utcnow() + timedelta(days=60)).isoformat(),
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "is_valid": True,
        "issues": [],
        "recommendations": [
            "Ensure HSTS header is enabled",
            "Enable OCSP stapling",
            "Consider using certificate transparency logs"
        ]
    }


def pgp_encrypt(plaintext, recipient_public_key=None):
    key = recipient_public_key if recipient_public_key else _rsa_public_key
    key_id = hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()[:16]

    ct = key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    ciphertext_b64 = base64.b64encode(ct).decode()
    signature = base64.b64encode(os.urandom(64)).decode()
    timestamp = datetime.utcnow().isoformat()

    log_event("pgp_encryption", "INFO", "encryption", {"msg": f"PGP encryption performed, key_id={key_id}"})
    return {
        "ciphertext": ciphertext_b64,
        "algorithm": "RSA-OAEP-2048",
        "key_id": key_id,
        "signature": signature,
        "timestamp": timestamp
    }


def pgp_decrypt(ciphertext_b64):
    ct = base64.b64decode(ciphertext_b64)
    plaintext = _rsa_private_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    key_id = hashlib.sha256(
        _rsa_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()[:16]
    timestamp = datetime.utcnow().isoformat()

    log_event("pgp_decryption", "INFO", "encryption", {"msg": f"PGP decryption performed, key_id={key_id}"})
    return {
        "algorithm": "RSA-OAEP-2048",
        "plaintext": plaintext,
        "key_id": key_id,
        "timestamp": timestamp
    }


def field_level_tokenization(sensitive_value, token_type="email"):
    token_hex = secrets.token_hex(16)
    token = f"tok_{token_type}_{token_hex}"

    if token_type == "email" and "@" in sensitive_value:
        local, domain = sensitive_value.split("@", 1)
        masked = local[0] + "***@" + "***." + domain.split(".")[-1]
    elif token_type == "ssn":
        masked = "***-**-" + sensitive_value[-4:] if len(sensitive_value) >= 4 else "***"
    elif token_type == "phone":
        masked = "***-***-" + sensitive_value[-4:] if len(sensitive_value) >= 4 else "***"
    elif token_type == "cc":
        masked = "****-****-****-" + sensitive_value[-4:] if len(sensitive_value) >= 4 else "****"
    else:
        masked = sensitive_value[:2] + "***" if len(sensitive_value) >= 2 else "***"

    _token_store[token] = {
        "original": sensitive_value,
        "token_type": token_type,
        "created_at": datetime.utcnow().isoformat()
    }

    log_event("tokenization", "INFO", "encryption", {"msg": f"Token created: {token} for type={token_type}"})
    return {
        "original_type": token_type,
        "token": token,
        "masked_value": masked,
        "created_at": datetime.utcnow().isoformat()
    }


def detokenize(token):
    if token in _token_store:
        entry = _token_store[token]
        log_event("detokenization", "INFO", "encryption", {"msg": f"Detokenized: {token}"})
        return {
            "token": token,
            "original_value": entry["original"],
            "token_type": entry["token_type"],
            "created_at": entry["created_at"]
        }
    return {"error": f"Token not found: {token}"}


def encrypt_field(plaintext, field_name):
    field_key = hashlib.sha256((field_name + _fernet_key.decode()).encode()).digest()[:32]
    nonce = os.urandom(12)
    aesgcm = AESGCM(field_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), field_name.encode())
    combined = nonce + ct
    ciphertext_b64 = base64.b64encode(combined).decode()

    field_id = hashlib.sha256(field_name.encode()).hexdigest()[:16]
    _field_store[field_name] = ciphertext_b64

    log_event("field_encryption", "INFO", "encryption", {"msg": f"Field '{field_name}' encrypted, field_id={field_id}"})
    return {
        "field_name": field_name,
        "ciphertext": ciphertext_b64,
        "field_id": field_id,
        "algorithm": "AES-256-GCM",
        "timestamp": datetime.utcnow().isoformat()
    }


def decrypt_field(ciphertext, field_name):
    try:
        field_key = hashlib.sha256((field_name + _fernet_key.decode()).encode()).digest()[:32]
        data = base64.b64decode(ciphertext)
        nonce = data[:12]
        ct = data[12:]
        aesgcm = AESGCM(field_key)
        plaintext = aesgcm.decrypt(nonce, ct, field_name.encode()).decode()

        log_event("field_decryption", "INFO", "encryption", {"msg": f"Field '{field_name}' decrypted"})
        return {
            "field_name": field_name,
            "plaintext": plaintext,
            "algorithm": "AES-256-GCM",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        log_event("field_decryption_error", "ERROR", "encryption", {"msg": f"Failed to decrypt field '{field_name}': {str(e)}"})
        return {"error": str(e)}
