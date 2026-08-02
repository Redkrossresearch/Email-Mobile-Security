import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from routes.auth_routes import auth_bp
from routes.mobile_routes import mobile_bp
from routes.email_routes import email_bp
from routes.report_routes import report_bp
from routes.threat_intel_routes import threat_intel_bp
from routes.ueba_routes import ueba_bp
from routes.encryption_routes import encryption_bp
from routes.ai_routes import ai_bp
from routes.apk_routes import apk_bp
from routes.yara_routes import yara_bp
from routes.integration_routes import integration_bp

from middleware.auth import rate_limit_middleware

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path=""
)

CORS(app)

# app.before_request(rate_limit_middleware)

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(mobile_bp, url_prefix="/api/mobile")
app.register_blueprint(email_bp, url_prefix="/api/email")
app.register_blueprint(report_bp, url_prefix="/api/reports")
app.register_blueprint(threat_intel_bp, url_prefix="/api/threat-intel")
app.register_blueprint(ueba_bp, url_prefix="/api/ueba")
app.register_blueprint(encryption_bp, url_prefix="/api/encryption")
app.register_blueprint(ai_bp, url_prefix="/api/ai")
app.register_blueprint(apk_bp, url_prefix="/api/apk")
app.register_blueprint(yara_bp, url_prefix="/api/yara")
app.register_blueprint(integration_bp, url_prefix="/api/integration")


@app.route("/api/health")
def health_check():
    return jsonify({
        "status": "online",
        "platform": "CyberShield Email+Mobile Security",
        "version": "5.0.0",
        "features": 50
    })


@app.route("/api/features")
def list_features():
    return jsonify({
        "total_features": 116
    })


@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/email-security")
def email_security():
    return send_from_directory(FRONTEND_DIR, "email-security.html")


@app.route("/mobile-security")
def mobile_security():
    return send_from_directory(FRONTEND_DIR, "mobile-security.html")


@app.route("/threat-intel")
def threat_intel():
    return send_from_directory(FRONTEND_DIR, "threat-intel.html")


@app.route("/ai-engine")
def ai_engine():
    return send_from_directory(FRONTEND_DIR, "ai-engine.html")


@app.route("/apk-analyzer")
def apk_analyzer():
    return send_from_directory(FRONTEND_DIR, "apk-analyzer.html")


@app.route("/yara")
def yara():
    return send_from_directory(FRONTEND_DIR, "yara.html")


@app.route("/integrations")
def integrations():
    return send_from_directory(FRONTEND_DIR, "integrations.html")


@app.route("/encryption")
def encryption():
    return send_from_directory(FRONTEND_DIR, "encryption.html")


@app.route("/ueba")
def ueba():
    return send_from_directory(FRONTEND_DIR, "ueba.html")


@app.route("/reports")
def reports():
    return send_from_directory(FRONTEND_DIR, "reports.html")


@app.route("/<path:filename>")
def serve_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("CyberShield SOC v6.0 - Enterprise Security Platform")
    print("=" * 65)
    print("Running on: http://localhost:5000")
    print("=" * 65)

    app.run(host="0.0.0.0", port=5000, debug=True)
