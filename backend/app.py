import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from services.auth.routes import auth_bp
from services.email_security.routes import email_bp
from services.mobile_security.routes import mobile_bp
from services.threat_intel.routes import threat_intel_bp
from services.behavior_analytics.routes import ueba_bp
from services.encryption.routes import encryption_bp
from routes.report_routes import report_bp
from routes.ai_routes import ai_bp
from routes.apk_routes import apk_bp
from routes.yara_routes import yara_bp
from routes.integration_routes import integration_bp
from middleware.auth import rate_limit_middleware
from services._shared.siem_logger import log_event, get_events

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app, supports_credentials=True)

app.before_request(rate_limit_middleware)

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
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:filename>")
def serve_frontend(filename):
    return send_from_directory(FRONTEND_DIR, filename)

if __name__ == "__main__":
    print("\n" + "="*65)
    print("  CyberShield Zero Trust Platform v6.0")
    print("="*65)
    print("  Auth (RS256+OAuth2+SAML+OIDC+TOTP) | Email | Mobile")
    print("  Threat Intel | UEBA | Encryption | AI | APK | YARA")
    print("-"*65)
    print("  http://localhost:5000")
    print("="*65 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
