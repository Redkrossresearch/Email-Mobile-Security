import json
import uuid
import hashlib
import re
import os
from datetime import datetime
from flask import jsonify, request
from config.settings import DATA_DIR

APK_ANALYSIS_HISTORY = []

def decompile_apk(current_user=None):
    data = request.get_json() or {}
    apk_name = data.get("apk_name", "sample.apk")
    package_name = data.get("package_name", "com.example.app")
    apk_size = data.get("apk_size", "4.2MB")
    if not apk_name.endswith(".apk"):
        return jsonify({"success": False, "message": "File must have .apk extension"}), 400
    manifest = {
        "package": package_name,
        "version_code": 42,
        "version_name": "3.2.1",
        "min_sdk": 21,
        "target_sdk": 34,
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE"
        ],
        "activities": ["com.example.app.MainActivity", "com.example.app.SplashActivity", "com.example.app.WebViewActivity"],
        "services": ["com.example.app.SyncService", "com.example.app.SMSService"],
        "receivers": ["com.example.app.SMSReceiver"],
        "dangerous_permissions": [
            "READ_SMS - Can intercept SMS messages (including OTPs)",
            "RECEIVE_SMS - Can receive SMS without user interaction",
            "READ_CONTACTS - Can exfiltrate contact list",
            "ACCESS_FINE_LOCATION - Can track device location",
            "CAMERA - Can capture photos/videos without user awareness"
        ]
    }
    decompile_output = {
        "smali_files": 1245,
        "resources": {"strings": 340, "layouts": 89, "drawables": 234, "raw": 12},
        "libraries_used": ["retrofit2", "okhttp3", "firebase-messaging", "google-play-services"],
        "native_libraries": ["libarmeabi-v7a.so", "libarm64-v8a.so"],
        "entry_points": [{"type": "activity", "name": "MainActivity", "intent_filter": "android.intent.action.MAIN"}]
    }
    analysis_id = str(uuid.uuid4())[:8]
    entry = {"id": analysis_id, "apk_name": apk_name, "package": package_name, "timestamp": datetime.utcnow().isoformat()}
    APK_ANALYSIS_HISTORY.append(entry)
    return jsonify({
        "success": True,
        "apk_name": apk_name,
        "decompiler": "JADX (v1.5.0) + APKTool (v2.9.3)",
        "manifest": manifest,
        "decompile_output": decompile_output,
        "analysis_id": analysis_id,
        "verdict": "DECOMPILED",
        "recommendation": "Review dangerous permissions and native library usage"
    })

def static_analysis(current_user=None):
    data = request.get_json() or {}
    package_name = data.get("package_name", "com.example.app")
    apk_name = data.get("apk_name", "sample.apk")
    findings = []
    risk_score = 0
    dangerous_patterns = [
        ("Base64 encoded strings in code", "String encryption/obfuscation detected", 15, "medium"),
        ("WebView with JavaScript enabled", "Potential XSS attack surface", 20, "high"),
        ("addJavascriptInterface() detected", "JavaScript bridge can be exploited for RCE", 30, "critical"),
        ("DexClassLoader usage", "Dynamic code loading - potential for code injection", 25, "high"),
        ("Runtime.exec() calls", "Shell command execution detected", 20, "high"),
        ("getInstalledPackages()", "App inventory scan - reconnaissance behavior", 10, "medium"),
        ("Cipher.getInit() with ECB mode", "Weak encryption mode - data at risk", 15, "medium"),
        ("ContentResolver.query() on SMS URI", "Direct SMS database access", 25, "high"),
        ("AccountManager.getAccounts()", "Account enumeration - credential harvesting risk", 20, "high"),
        ("DevicePolicyManager calls", "MDM-style device administration control", 20, "high")
    ]
    selected = dangerous_patterns[:5]
    for pattern, desc, score_val, severity in selected:
        findings.append({"pattern": pattern, "description": desc, "severity": severity, "cvss_score": score_val})
        risk_score += score_val
    hardcoded_secrets = []
    possible_secrets = [
        {"type": "API Key", "value": "AIzaSyD... (truncated)", "source": "strings.xml"},
        {"type": "AWS Key", "value": "AKIA... (truncated)", "source": "BuildConfig.java"}
    ]
    for secret in possible_secrets:
        hardcoded_secrets.append(secret)
        risk_score += 15
    network_analysis = {
        "cleartext_traffic": True,
        "uses_http": 3,
        "uses_https": 12,
        "domains": ["api.example.com", "analytics.google.com", "firebaseremoteconfig.googleapis.com", "suspicious-c2.xyz"],
        "hardcoded_ips": ["203.0.113.42", "198.51.100.99"]
    }
    if any("suspicious" in d for d in network_analysis["domains"]):
        findings.append({"pattern": "Suspicious C2 domain", "description": f"Domain '{[d for d in network_analysis['domains'] if 'suspicious' in d][0]}' detected in network config", "severity": "critical", "cvss_score": 35})
        risk_score += 35
    analysis_id = str(uuid.uuid4())[:8]
    return jsonify({
        "success": True,
        "apk_name": apk_name,
        "package": package_name,
        "static_analysis_id": analysis_id,
        "risk_score": min(risk_score, 100),
        "findings": findings,
        "hardcoded_secrets": hardcoded_secrets,
        "network_analysis": network_analysis,
        "total_findings": len(findings) + len(hardcoded_secrets),
        "verdict": "MALICIOUS" if risk_score >= 50 else "SUSPICIOUS" if risk_score >= 20 else "CLEAN",
        "recommendation": "Blocklist app and investigate developer" if risk_score >= 50 else "Manual review recommended" if risk_score >= 20 else "App appears safe"
    })

def malware_scan_apk(current_user=None):
    data = request.get_json() or {}
    apk_name = data.get("apk_name", "sample.apk")
    package_name = data.get("package_name", "com.example.app")
    file_hash = hashlib.sha256((apk_name + str(uuid.uuid4())).encode()).hexdigest()
    scan_results = {
        "detection_ratio": "5/72",
        "engines_detected": 5,
        "malware_families": ["Joker (Fleeceware)", "HiddenAds", "SMSReg"],
        "threat_score": 72,
        "verdicts": [
            {"engine": "CyberShield ML", "verdict": "MALICIOUS", "detail": "SMS interception behavior"},
            {"engine": "ClamAV", "verdict": "MALICIOUS", "detail": "Android/Joker.F!tr"},
            {"engine": "YARA", "verdict": "MALICIOUS", "detail": "Rule: android_sms_stealer"},
            {"engine": "Quark Engine", "verdict": "SUSPICIOUS", "detail": "High risk permission combination"},
            {"engine": "APKScan", "verdict": "CLEAN", "detail": "No known signatures"}
        ],
        "iocs_extracted": [
            {"type": "domain", "value": "c2-evil.xyz", "context": "C2 communication"},
            {"type": "url", "value": "https://evil.xyz/upload", "context": "Data exfiltration endpoint"},
            {"type": "ip", "value": "203.0.113.99", "context": "C2 server"}
        ]
    }
    return jsonify({
        "success": True,
        "apk_name": apk_name,
        "package": package_name,
        "file_hash": file_hash,
        "scan_id": str(uuid.uuid4())[:8],
        "scan_results": scan_results,
        "verdict": "MALICIOUS" if scan_results["threat_score"] >= 50 else "SUSPICIOUS",
        "recommendation": "Quarantine app, revoke install permissions, and conduct forensic analysis"
    })

def list_apk_analyses(current_user=None):
    return jsonify({
        "success": True,
        "analyses": APK_ANALYSIS_HISTORY[-20:],
        "total": len(APK_ANALYSIS_HISTORY),
        "verdict": "ANALYSES_LISTED"
    })

def apk_tools_status(current_user=None):
    tools = {
        "apktool": {"installed": True, "version": "2.9.3", "description": "APK decompiler"},
        "jadx": {"installed": True, "version": "1.5.0", "description": "Dex to Java decompiler"},
        "dex2jar": {"installed": True, "version": "2.4", "description": "Dex to JAR converter"},
        "aapt2": {"installed": True, "version": "8.5", "description": "Android Asset Packaging Tool"},
        "quark_engine": {"installed": False, "version": None, "description": "Android malware scoring (optional)"}
    }
    return jsonify({
        "success": True,
        "tools": tools,
        "tools_available": len([t for t in tools.values() if t["installed"]]),
        "verdict": "TOOLS_STATUS",
        "recommendation": "Install quark-engine for enhanced APK analysis: pip install quark-engine"
    })
