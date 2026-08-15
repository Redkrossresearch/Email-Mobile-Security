import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from services.auth.routes import auth_bp
from services.email_security.routes import email_bp
from services.mobile_security.routes import mobile_bp
from routes.report_routes import report_bp
from middleware.auth import rate_limit_middleware
from services._shared.siem_logger import log_event, get_events
from config.database import init_db, seed_devices

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
REACT_DIR = os.path.join(PROJECT_DIR, "react_app")

app = Flask(__name__, static_folder=REACT_DIR, static_url_path="")
CORS(app, supports_credentials=True)

init_db()
seed_devices()

app.before_request(rate_limit_middleware)

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(mobile_bp, url_prefix="/api/mobile")
app.register_blueprint(email_bp, url_prefix="/api/email")
app.register_blueprint(report_bp, url_prefix="/api/reports")

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "online", "platform": "CyberShield Zero Trust Platform", "version": "6.0.0", "auth": "RS256+OAuth2+SAML+OIDC"})

@app.route("/api/siem/events", methods=["GET"])
def siem_events():
    severity = request.args.get("severity")
    event_type = request.args.get("event_type")
    limit = int(request.args.get("limit", 100))
    return jsonify({"success": True, "events": list(get_events(limit, severity, event_type))})

@app.route("/")
@app.route("/index")
def serve_index():
    return send_from_directory(REACT_DIR, "index.html")

@app.route("/login")
@app.route("/register")
@app.route("/dashboard")
@app.route("/email")
@app.route("/mobile")
@app.route("/reports")
def serve_spa(path=""):
    return send_from_directory(REACT_DIR, "index.html")

@app.route("/<path:filename>")
def serve_frontend(filename):
    if filename.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    file_path = os.path.join(REACT_DIR, filename)
    if os.path.isfile(file_path):
        return send_from_directory(REACT_DIR, filename)
    return send_from_directory(REACT_DIR, "index.html")

if __name__ == "__main__":
    print("\n" + "="*65)
    print("  CyberShield Zero Trust Platform v6.0")
    print("="*65)
    print("  React Frontend + Flask Backend")
    print("  Auth (RS256+Email OTP) | Email Security | Mobile Security")
    print("-"*65)
    print("  http://localhost:5000")
    print("="*65 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
