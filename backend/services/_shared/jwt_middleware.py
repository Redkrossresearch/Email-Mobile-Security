import jwt
import json
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
import os

PRIVATE_KEY = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "jwt_private.pem")).read()
PUBLIC_KEY = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "jwt_public.pem")).read()
JWT_ALGO = "RS256"
JWT_EXPIRY_MINUTES = 15
JWT_REFRESH_EXPIRY_DAYS = 7

SESSIONS = {}
REFRESH_TOKENS = {}

def create_token(user_id, name, roles, device_trust_score=100):
    now = datetime.utcnow()
    token_id = uuid.uuid4().hex
    payload = {
        "jti": token_id,
        "sub": user_id,
        "name": name,
        "roles": roles if isinstance(roles, list) else [roles],
        "device_trust_score": device_trust_score,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRY_MINUTES),
        "iss": "cybershield"
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGO)
    SESSIONS[token_id] = {"user_id": user_id, "created": now.isoformat(), "roles": roles}
    refresh = uuid.uuid4().hex
    REFRESH_TOKENS[refresh] = {"user_id": user_id, "token_id": token_id, "exp": now + timedelta(days=JWT_REFRESH_EXPIRY_DAYS)}
    return token, refresh

def verify_token(token):
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[JWT_ALGO], issuer="cybershield")
        if payload["jti"] not in SESSIONS:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def refresh_access_token(refresh_token):
    rt = REFRESH_TOKENS.get(refresh_token)
    if not rt or datetime.utcnow() > rt["exp"]:
        return None
    return create_token(rt["user_id"], "User", SESSIONS.get(rt["token_id"], {}).get("roles", ["analyst"]))

def revoke_session(token_id):
    SESSIONS.pop(token_id, None)
    for k, v in list(REFRESH_TOKENS.items()):
        if v["token_id"] == token_id:
            REFRESH_TOKENS.pop(k, None)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        if not token:
            return jsonify({"success": False, "message": "Token missing"}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        g.current_user = payload["sub"]
        g.user_roles = payload.get("roles", [])
        g.trust_score = payload.get("device_trust_score", 100)
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin" not in g.get("user_roles", []):
            return jsonify({"success": False, "message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def require_trust_score(min_score=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.get("trust_score", 100) < min_score:
                return jsonify({"success": False, "message": f"Device trust score too low ({g.get('trust_score', 0)}). Required: {min_score}", "step_up_auth": True}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
