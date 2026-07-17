import json
import re
import random
import uuid
import hashlib
from datetime import datetime
from flask import jsonify, request
from config.settings import DATA_DIR

def get_devices(current_user=None):
    with open(f"{DATA_DIR}/devices.json") as f:
        devices = json.load(f)
    return jsonify({"success": True, "devices": devices, "total": len(devices)})

def get_device_detail(current_user=None, device_id=None):
    with open(f"{DATA_DIR}/devices.json") as f:
        devices = json.load(f)
    device = next((d for d in devices if d["id"] == device_id), None)
    if not device:
        return jsonify({"success": False, "message": "Device not found"}), 404
    return jsonify({"success": True, "device": device})

def scan_apps(current_user=None):
    with open(f"{DATA_DIR}/apps.json") as f:
        apps_db = json.load(f)
    installed = apps_db["installed"]
    high_risk = [a for a in installed if a["risk"] == "high"]
    medium_risk = [a for a in installed if a["risk"] == "medium"]
    return jsonify({
        "success": True,
        "apps": installed,
        "summary": {"total": len(installed), "high_risk": len(high_risk), "medium_risk": len(medium_risk), "low_risk": len(installed) - len(high_risk) - len(medium_risk)},
        "high_risk_apps": high_risk
    })

def analyze_sms(current_user=None):
    data = request.get_json()
    text = data.get("text", "") if data else ""
    score = 0
    findings = []
    phishing_keywords = ["click here", "claim now", "free prize", "won", "lottery", "congratulations",
                         "update kyc", "account blocked", "verify now", "urgent", "suspended", "loan offer"]
    suspicious_urls = re.findall(r'https?://[^\s]+', text)
    for url in suspicious_urls:
        suspicious_domains = ["bit.ly", "tinyurl", ".tk", ".cc", ".top", "secure-verify", "netflix-verify"]
        for dom in suspicious_domains:
            if dom in url.lower():
                score += 30
                findings.append(f"Suspicious URL domain: {url}")
    for kw in phishing_keywords:
        if kw.lower() in text.lower():
            score += 10
            findings.append(f"Phishing keyword found: '{kw}'")
    has_phone = bool(re.search(r'[\+0-9\-\(\)\s]{10,}', text))
    if has_phone:
        score += 5
        findings.append("Phone number detected in message")
    is_phishing = score >= 30
    is_suspicious = score >= 15 and not is_phishing
    return jsonify({
        "success": True,
        "score": min(score, 100),
        "verdict": "PHISHING" if is_phishing else ("SUSPICIOUS" if is_suspicious else "SAFE"),
        "findings": findings,
        "urls_found": suspicious_urls
    })

def malware_scan(current_user=None):
    with open(f"{DATA_DIR}/apps.json") as f:
        apps_db = json.load(f)
    sigs = apps_db["malware_signatures"]
    installed = apps_db["installed"]
    matches = []
    for app in installed:
        for sig in sigs:
            if sig["package"] in app.get("package", ""):
                matches.append({"app": app["name"], "threat": sig["name"], "type": sig["type"], "severity": sig["severity"]})
    return jsonify({
        "success": True,
        "scan_status": "completed",
        "threats_found": len(matches),
        "threats": matches,
        "apps_scanned": len(installed),
        "clean": len(installed) - len(matches)
    })

def get_sms_logs(current_user=None):
    with open(f"{DATA_DIR}/sms_messages.json") as f:
        sms_list = json.load(f)
    phishing = [s for s in sms_list if s["type"] == "phishing"]
    spam = [s for s in sms_list if s["type"] == "spam"]
    safe = [s for s in sms_list if s["type"] == "safe"]
    return jsonify({
        "success": True,
        "messages": sms_list,
        "summary": {"total": len(sms_list), "phishing": len(phishing), "spam": len(spam), "safe": len(safe)}
    })

def get_call_logs(current_user=None):
    with open(f"{DATA_DIR}/call_logs.json") as f:
        calls = json.load(f)
    blocked = [c for c in calls if c["blocked"]]
    return jsonify({
        "success": True,
        "calls": calls,
        "total_blocked": len(blocked),
        "total": len(calls)
    })

def device_health(current_user=None):
    checks = [
        {"name": "OS Patches", "status": "passed", "score": 100, "detail": "Latest patch 2026-06 applied"},
        {"name": "Root/Jailbreak", "status": "passed", "score": 100, "detail": "No root/jailbreak detected"},
        {"name": "Encryption", "status": "passed", "score": 100, "detail": "Device encryption enabled (AES-256)"},
        {"name": "VPN Status", "status": "warning", "score": 60, "detail": "VPN not connected on BYOD devices"},
        {"name": "Screen Lock", "status": "passed", "score": 100, "detail": "PIN/biometric lock active"},
        {"name": "App Sideloading", "status": "warning", "score": 70, "detail": "Unknown sources partially restricted"},
        {"name": "Developer Mode", "status": "passed", "score": 100, "detail": "Developer options disabled"}
    ]
    overall = sum(c["score"] for c in checks) // len(checks)
    return jsonify({
        "success": True,
        "overall_score": overall,
        "checks": checks,
        "passed": len([c for c in checks if c["status"] == "passed"]),
        "warnings": len([c for c in checks if c["status"] == "warning"]),
        "failed": len([c for c in checks if c["status"] == "failed"])
    })

def get_dashboard_stats(current_user=None):
    with open(f"{DATA_DIR}/devices.json") as f:
        devices = json.load(f)
    with open(f"{DATA_DIR}/sms_messages.json") as f:
        sms_list = json.load(f)
    with open(f"{DATA_DIR}/call_logs.json") as f:
        calls = json.load(f)
    with open(f"{DATA_DIR}/apps.json") as f:
        apps_db = json.load(f)
    healthy_devices = len([d for d in devices if d["status"] == "healthy"])
    threats = len([s for s in sms_list if s["type"] == "phishing"]) + len([c for c in calls if c["blocked"]])
    high_risk_apps = len([a for a in apps_db["installed"] if a["risk"] == "high"])
    overall_score = sum(d.get("health_score", 0) for d in devices) // len(devices) if devices else 0
    return jsonify({
        "success": True,
        "stats": {
            "devices_monitored": len(devices),
            "healthy_devices": healthy_devices,
            "threats_blocked": threats,
            "high_risk_apps": high_risk_apps,
            "overall_health_score": overall_score,
            "sms_phishing": len([s for s in sms_list if s["type"] == "phishing"]),
            "calls_blocked": len([c for c in calls if c["blocked"]]),
            "total_apps": len(apps_db["installed"])
        }
    })

def app_reputation(current_user=None):
    data = request.get_json() or {}
    package_name = data.get("package_name", "com.unknown.app")
    app_name = data.get("app_name", package_name.split(".")[-1])
    reputations = {
        "com.cleanmaster.pro": {"risk": "high", "score": 82, "category": "System Cleaner", "issues": ["Data collection", "SMS permissions", "Background activity"]},
        "com.battery.boost": {"risk": "medium", "score": 55, "category": "Battery Optimizer", "issues": ["Excessive permissions", "Adware behavior"]},
        "com.freevpn.pro": {"risk": "high", "score": 78, "category": "VPN Service", "issues": ["Data exfiltration", "DNS hijacking"]},
        "com.file.manager": {"risk": "medium", "score": 45, "category": "File Manager", "issues": ["Unnecessary permissions"]},
    }
    rep = reputations.get(package_name, {"risk": "unknown", "score": 50, "category": "General", "issues": []})
    return jsonify({
        "success": True,
        "app_name": app_name,
        "package_name": package_name,
        "reputation_score": rep["score"],
        "risk_level": rep["risk"],
        "category": rep["category"],
        "issues_found": rep["issues"],
        "verdict": "UNSAFE" if rep["risk"] == "high" else "CAUTION" if rep["risk"] == "medium" else "SAFE",
        "recommendation": "Uninstall immediately" if rep["risk"] == "high" else "Review permissions" if rep["risk"] == "medium" else "App is reputable"
    })

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    PHONES_AVAILABLE = True
except ImportError:
    PHONES_AVAILABLE = False

def caller_scan(current_user=None):
    data = request.get_json() or {}
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "message": "Phone number required"}), 400
    phone_clean = re.sub(r'[\s\-\(\)]', '', phone)
    valid = False
    national_format = ""
    international_format = ""
    carrier_name = "Unknown"
    region = "Unknown"
    country_code_val = ""
    if PHONES_AVAILABLE:
        try:
            parsed = phonenumbers.parse(phone, None)
            valid = phonenumbers.is_valid_number(parsed)
            national_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            international_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
            region = geocoder.description_for_number(parsed, "en") or "Unknown"
            country_code_val = str(parsed.country_code)
        except Exception:
            pass
    if not valid:
        phone_clean = re.sub(r'[\s\-\(\)\+]', '', phone)
    spam_db = {
        "+919876543210": {"spam": True, "type": "telemarketer", "reports": 342, "name": "SPAM LIKELY"},
        "+919999999999": {"spam": True, "type": "scam", "reports": 1256, "name": "SCAM CALLER"},
        "+911234567890": {"spam": False, "type": "legitimate", "reports": 2, "name": "Ramesh Kumar"},
        "+14155551234": {"spam": True, "type": "robocall", "reports": 567, "name": "SPAM RISK"},
        "+440123456789": {"spam": False, "type": "legitimate", "reports": 0, "name": "James Wilson"},
        "+12025551234": {"spam": True, "type": "irs_scam", "reports": 2341, "name": "SCAM DETECTED"},
    }
    spam_info = {"spam": False, "type": "unknown", "reports": 0, "name": "Unknown Caller"}
    for key, val in spam_db.items():
        if key.replace("+", "") in phone_clean or phone_clean in key:
            spam_info = val
            break
    score = min(spam_info["reports"] // 10, 100) if spam_info["spam"] else random.randint(0, 15)
    return jsonify({
        "success": True,
        "phone": phone,
        "valid_number": valid,
        "national_format": national_format,
        "international_format": international_format,
        "carrier": carrier_name,
        "region": region,
        "country_code": country_code_val,
        "caller_name": spam_info["name"],
        "spam": spam_info["spam"],
        "spam_type": spam_info["type"],
        "spam_score": score,
        "total_reports": spam_info["reports"],
        "tags": ["telemarketer"] if spam_info["type"] == "telemarketer" else ["scam"] if spam_info["spam"] else ["safe"],
        "verdict": "SPAM" if spam_info["spam"] else "SAFE",
        "recommendation": "Block this number and report to DND registry" if spam_info["spam"] else "Caller appears legitimate"
    })

CALL_FEED = [
    {"number": "+919999999999", "name": "SCAM CALLER", "time": "just now", "status": "blocked", "type": "scam"},
    {"number": "+911234567890", "name": "Ramesh Kumar", "time": "2 min ago", "status": "allowed", "type": "contact"},
    {"number": "+14155551234", "name": "SPAM RISK", "time": "5 min ago", "status": "blocked", "type": "robocall"},
    {"number": "+12025551234", "name": "SCAM DETECTED", "time": "8 min ago", "status": "blocked", "type": "irs_scam"},
    {"number": "+919876543210", "name": "SPAM LIKELY", "time": "12 min ago", "status": "blocked", "type": "telemarketer"},
]

def caller_feed(current_user=None):
    import random as rnd
    names = ["SPAM CALLER", "Ramesh Kumar", "SCAM DETECTED", "SPAM RISK", "Priya Sharma", "UNKNOWN CALLER", "Telemarketer"]
    types = ["scam", "legitimate", "irs_scam", "robocall", "legitimate", "unknown", "telemarketer"]
    statuses = ["blocked", "allowed", "blocked", "blocked", "allowed", "blocked", "blocked"]
    prefixes = ["+91", "+1", "+44", "+91", "+91", "+1", "+44"]
    new_call = {
        "number": prefixes[rnd.randint(0, len(prefixes)-1)] + str(rnd.randint(1000000000, 9999999999))[:10],
        "name": names[rnd.randint(0, len(names)-1)],
        "time": "just now",
        "status": "blocked" if rnd.random() > 0.3 else "allowed",
        "type": types[rnd.randint(0, len(types)-1)]
    }
    CALL_FEED.insert(0, new_call)
    if len(CALL_FEED) > 20:
        CALL_FEED.pop()
    return jsonify({
        "success": True,
        "feed": CALL_FEED,
        "total_blocked": len([c for c in CALL_FEED if c["status"] == "blocked"]),
        "verdict": "CALL_FEED_UPDATED"
    })

def volte_status(current_user=None):
    return jsonify({
        "success": True,
        "volte_enabled": True,
        "vowifi_enabled": True,
        "encryption_protocol": "SRTP + ZRTP",
        "cipher_suite": "AES-256-GCM",
        "key_exchange": "ECDH-P256",
        "integrity_protection": "HMAC-SHA256",
        "active_calls_encrypted": 3,
        "encryption_score": 94,
        "status": "SECURE",
        "verdict": "VOLTE_ENCRYPTION_ACTIVE",
        "recommendation": "All voice traffic is encrypted end-to-end"
    })
