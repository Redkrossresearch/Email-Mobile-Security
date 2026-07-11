import time
from functools import wraps
from flask import request, jsonify
from services._shared.jwt_middleware import verify_token, create_token as rs_create_token

RATE_LIMIT_MAP = {}

def rate_limit_middleware():
    ip = request.remote_addr or "127.0.0.1"
    now = time.time()
    window = 60
    max_requests = 100
    if ip not in RATE_LIMIT_MAP:
        RATE_LIMIT_MAP[ip] = []
    RATE_LIMIT_MAP[ip] = [t for t in RATE_LIMIT_MAP[ip] if now - t < window]
    if len(RATE_LIMIT_MAP[ip]) >= max_requests:
        return jsonify({"error": "Rate limit exceeded", "message": "Max 100 requests/min"}), 429
    RATE_LIMIT_MAP[ip].append(now)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            return jsonify({"error": "Token missing", "message": "Authorization required"}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        current_user = payload.get("sub")
        user_role = payload.get("roles", ["analyst"])[0] if payload.get("roles") else "analyst"
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid token"}), 401
        if "admin" not in payload.get("roles", []):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def create_token(email, name, role):
    token, _ = rs_create_token(email, name, [role])
    return token
