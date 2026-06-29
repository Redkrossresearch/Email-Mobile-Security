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

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

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
    return jsonify({"status": "online", "platform": "CyberShield Email+Mobile Security", "version": "5.0.0", "features": 50})

@app.route("/api/features", methods=["GET"])
def list_features():
    return jsonify({
        "total_features": 116,
        "email_security": [
            "DMARC Enforcement", "SPF Check", "DKIM Verification", "Zero-Day Sandbox",
            "Time-of-Click URL Analysis", "Content Disarm & Reconstruction (CDR)",
            "Lookalike Domain Detection", "BEC Protection", "Heuristic Analysis",
            "Attachment File-Type Blocking", "OCR Scanning", "Outbound Attachment Encryption",
            "Remote Browser Isolation (RBI)", "DNS Sinkholing", "SSL/TLS Decryption",
            "Drive-by Download Protection", "Credential Phishing Prevention",
            "Ad & Tracker Blocking", "Auto-Remediation (Clawback)",
            "SIEM/SOAR Integration", "In-Email Warning Banners", "ATO Protection",
            "MFA Enforcement", "Rate Limiting", "Email Header Deep Analyzer",
            "Sender Reputation Scanner", ".eml File Parser & Analyzer",
            "EML PDF Report Generator", "EML Excel Report Generator"
        ],
        "mobile_security": [
            "SS7 Vulnerability Protection", "A2P Monitoring", "IMSI Catcher Detection",
            "Baseband Firewall", "Deep Packet Inspection for SMSC",
            "Cryptographic Signature Validation", "Zero-Click Exploit Detection",
            "Spam Honey-Potting", "Keystroke Logging Prevention",
            "Rogue MDM Profile Blocking", "SMS App Sandboxing", "Corporate App Wrapping",
            "Biometric Triggering", "WebRTC Leak Protection", "Secure Enclave Integration",
            "Contact List Exfiltration Blocking", "Location Spoofing Detection",
            "STIR/SHAKEN Integration", "VoLTE/VoWiFi Traffic Encryption", "Remote Wipe & Lock",
            "Mobile App Reputation Service", "In-App Secure Keyboard",
            "Base Station Authentication Verification", "SMS Data Retention Policies",
            "Telecom Threat Intelligence", "Caller ID & Spam Scanner",
            "App Permission Scanner", "SMS Security Analyzer",
            "Malware Deep Scan", "Battery Abuse Detection",
            "Call Protection Center", "Device Health Diagnostics"
        ],
        "threat_intel": [
            "Multi-Source IOC Feeds (AlienVault, VirusTotal, AbuseIPDB, MISP, GreyNoise)",
            "IOC Lookup (IP/Domain/Email/Hash)", "Hash Scan vs 72 Engines",
            "Alert Generation & Management", "Severity-Based Alert Filtering"
        ],
        "ueba": [
            "User Behavior Anomaly Detection", "Behavioral User Profiling",
            "Login Anomaly Detection (Impossible Travel, Brute Force)",
            "Multi-Signal Risk Score Calculation"
        ],
        "encryption": [
            "AES-256-GCM Encryption/Decryption", "TLS 1.3 Configuration Status",
            "PGP Message Encryption (RSA-2048/AES-256)",
            "Encryption Key Management & Rotation", "Encryption Status Reporting"
        ],
        "reports": [
            "Professional PDF Security Report", "CSV Data Export",
            "JSON Data Export", "Comprehensive Module Status Report",
            "Threat Landscape Report", "Encryption Status Report",
            "UEBA Risk Assessment Report"
        ],
        "auth": [
            "Email/Password Authentication with Lockout", "Mobile Phone + PIN Login",
            "OTP Verification (6-digit)", "MFA TOTP Verification",
            "SSO Login (SAML/OIDC)", "OAuth 2.0 Authorization Code Flow",
            "Account Recovery Flow", "User Management (Admin)",
            "Rate Limited API Access"
        ],
        "auth_enhanced": [
            "Double Authentication Engine", "Password Reset with Token Verification",
            "OAuth 2.0 Integration (Google/Microsoft)", "Session Management with Session ID",
            "Argon2 Password Hashing", "Token-based Session Validation & Revocation"
        ],
        "ai_engine": [
            "AI-Powered IOC Analysis (Llama 3)", "AI Email Phishing Analysis (Phi 3)",
            "AI Search Engine for Security Research", "Automated AI Report Generation",
            "Multi-Model Support (Llama3, Phi3, Mistral)", "Analysis History Tracking"
        ],
        "apk_analyzer": [
            "APK Decompilation (JADX + APKTool)", "Static Code Analysis",
            "Malware Scanning Engine (5/72 detection)", "Permission & Network Analysis",
            "Hardcoded Secret Detection", "APK Analysis History"
        ],
        "yara_rules": [
            "YARA Rule Engine for IP Scanning", "Pre-built Rules (C2, Brute Force, Tor, VPN)",
            "Custom Rule Creation", "Rule Toggle Enable/Disable", "Scan History"
        ],
        "third_party_integrations": [
            "Gmail API Integration", "Microsoft Graph API Integration",
            "Inbox Scanning & Threat Detection", "User Risk Analysis (Graph)",
            "Audit Log Retrieval"
        ]
    })

@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:filename>")
def serve_frontend(filename):
    return send_from_directory(FRONTEND_DIR, filename)

if __name__ == "__main__":
    print("\n" + "="*65)
    print("  CyberShield SOC v6.0 - Enterprise Security Platform")
    print("="*65)
    print("  75+ Features Across 12 Modules")
    print("  Auth | Email | Mobile | Threat Intel | UEBA | Encryption")
    print("  AI Engine | APK Analyzer | YARA | Reports | Integrations | Auth Enhanced")
    print("-"*65)
    print("  OPEN BROWSER: http://localhost:5000")
    print("="*65 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
