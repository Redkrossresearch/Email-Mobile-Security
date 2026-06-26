import jwt
import json
import time
from functools import wraps
from flask import request, jsonify
from config.settings import JWT_SECRET, JWT_ALGO, DATA_DIR

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
            token = auth.split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing", "message": "Authorization required"}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            current_user = data.get("email")
            user_role = data.get("role", "analyst")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token = auth.split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            if data.get("role") != "admin":
                return jsonify({"error": "Admin access required"}), 403
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def create_token(email, name, role):
    import datetime
    payload = {
        "email": email,
        "name": name,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
