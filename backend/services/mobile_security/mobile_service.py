import hashlib
import re
from datetime import datetime, timedelta
from services._shared.siem_logger import log_event

KNWON_BAD_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"threat_type": "Ransomware", "malware_name": "WannaCry", "severity": "critical", "recommendation": "Immediately quarantine and wipe device"},
    "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35": {"threat_type": "Trojan", "malware_name": "BankBot", "severity": "high", "recommendation": "Remove malicious app and change passwords"},
    "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce": {"threat_type": "Spyware", "malware_name": "Pegasus", "severity": "critical", "recommendation": "Factory reset device immediately"},
    "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a": {"threat_type": "Adware", "malware_name": "DroidPlugin", "severity": "medium", "recommendation": "Uninstall suspicious applications"},
}

SAMPLE_DEVICES = [
    {"id": "d-001", "name": "Mike's Pixel 7", "platform": "Android", "os_version": "14.0", "trust_score": 88, "last_seen": "2026-07-11T14:30:00Z", "is_compromised": False, "risk_level": "low"},
    {"id": "d-002", "name": "Sarah's iPhone 15", "platform": "iOS", "os_version": "18.5", "trust_score": 95, "last_seen": "2026-07-12T08:15:00Z", "is_compromised": False, "risk_level": "low"},
    {"id": "d-003", "name": "Alex's Galaxy S24", "platform": "Android", "os_version": "13.0", "trust_score": 62, "last_seen": "2026-07-10T22:45:00Z", "is_compromised": True, "risk_level": "high"},
    {"id": "d-004", "name": "Office Tablet", "platform": "Android", "os_version": "12.0", "trust_score": 45, "last_seen": "2026-07-09T16:00:00Z", "is_compromised": True, "risk_level": "critical"},
    {"id": "d-005", "name": "Jane's iPad Air", "platform": "iOS", "os_version": "17.4", "trust_score": 78, "last_seen": "2026-07-11T19:20:00Z", "is_compromised": False, "risk_level": "medium"},
]

SMS_PHISHING_WEIGHTS = {
    "win prize": 0.20, "you won": 0.18, "congratulations you": 0.15,
    "click link": 0.14, "free gift": 0.15, "claim reward": 0.17,
    "bank alert": 0.12, "otp": 0.10, "verify": 0.10, "urgent": 0.12,
    "account suspended": 0.14, "login attempt": 0.10, "reset password": 0.12,
    "payment failed": 0.13, "refund": 0.10, "limited time": 0.10,
    "exclusive offer": 0.12, "call now": 0.08, "text stop": 0.06,
    "cash prize": 0.20, "inheritance": 0.22, "lottery": 0.18,
    "gift card": 0.12, "amazon": 0.06, "paypal": 0.08,
    "netflix": 0.08, "iphone": 0.10, "samsung": 0.06,
}

SAMPLE_APPS = [
    {"package_name": "com.example.banking", "app_name": "SecureBank", "version": "4.2.1", "permissions": ["CAMERA", "SMS", "CONTACTS", "LOCATION"], "risk_score": 65, "is_malicious": False, "signature_hash": "a1b2c3d4e5f6...", "install_source": "Play Store"},
    {"package_name": "com.example.game", "app_name": "Candy Crush Clone", "version": "1.0.3", "permissions": ["STORAGE", "INTERNET", "VIBRATE"], "risk_score": 20, "is_malicious": False, "signature_hash": "f6e5d4c3b2a1...", "install_source": "Play Store"},
    {"package_name": "com.example.tracker", "app_name": "DeviceTracker", "version": "2.0.0", "permissions": ["LOCATION", "CAMERA", "MICROPHONE", "SMS", "CONTACTS", "CALL_LOG", "PHONE"], "risk_score": 85, "is_malicious": True, "signature_hash": "deadbeef1234...", "install_source": "Sideloaded"},
    {"package_name": "com.example.utility", "app_name": "Flashlight Pro", "version": "3.1.2", "permissions": ["CAMERA", "STORAGE", "INTERNET", "LOCATION"], "risk_score": 55, "is_malicious": False, "signature_hash": "ab12cd34ef56...", "install_source": "Play Store"},
    {"package_name": "com.example.social", "app_name": "FriendConnect", "version": "5.0.1", "permissions": ["CONTACTS", "STORAGE", "CAMERA", "MICROPHONE", "INTERNET"], "risk_score": 45, "is_malicious": False, "signature_hash": "9876543210fe...", "install_source": "App Store"},
]

SAMPLE_SMS_LOGS = [
    {"id": "sms-001", "from_number": "+12025551234", "to_number": "+12025559876", "message_preview": "You won a $1000 gift card! Click here to claim...", "timestamp": "2026-07-12T10:30:00Z", "is_spam": True, "classification": "phishing"},
    {"id": "sms-002", "from_number": "+14035551234", "to_number": "+14035559876", "message_preview": "Your package is on hold. Please update delivery preferences...", "timestamp": "2026-07-12T09:15:00Z", "is_spam": True, "classification": "spam"},
    {"id": "sms-003", "from_number": "+16505551234", "to_number": "+16505559876", "message_preview": "Hey, are we still meeting for lunch tomorrow?", "timestamp": "2026-07-12T08:45:00Z", "is_spam": False, "classification": "legitimate"},
    {"id": "sms-004", "from_number": "+18185551234", "to_number": "+18185559876", "message_preview": "Your OTP for login is 847291. Do not share this code.", "timestamp": "2026-07-12T08:30:00Z", "is_spam": False, "classification": "legitimate"},
    {"id": "sms-005", "from_number": "+12135551234", "to_number": "+12135559876", "message_preview": "Congratulations! You've been selected for an exclusive free vacation...", "timestamp": "2026-07-11T22:00:00Z", "is_spam": True, "classification": "scam"},
]

SAMPLE_CALL_LOGS = [
    {"call_id": "call-001", "from_number": "+12025551234", "to_number": "+12025559876", "duration_seconds": 0, "call_type": "missed", "timestamp": "2026-07-12T10:30:00Z", "is_spam": True},
    {"call_id": "call-002", "from_number": "+14035551234", "to_number": "+14035559876", "duration_seconds": 45, "call_type": "incoming", "timestamp": "2026-07-12T09:15:00Z", "is_spam": True},
    {"call_id": "call-003", "from_number": "+16505551234", "to_number": "+16505559876", "duration_seconds": 320, "call_type": "outgoing", "timestamp": "2026-07-12T08:45:00Z", "is_spam": False},
    {"call_id": "call-004", "from_number": "+18185551234", "to_number": "+18185559876", "duration_seconds": 12, "call_type": "incoming", "timestamp": "2026-07-12T08:30:00Z", "is_spam": False},
    {"call_id": "call-005", "from_number": "+12135551234", "to_number": "+12135559876", "duration_seconds": 0, "call_type": "missed", "timestamp": "2026-07-11T22:00:00Z", "is_spam": True},
]


def get_devices():
    return {"success": True, "devices": SAMPLE_DEVICES, "total": len(SAMPLE_DEVICES), "timestamp": datetime.utcnow().isoformat() + "Z"}


def get_device_detail(device_id):
    device = next((d for d in SAMPLE_DEVICES if d["id"] == device_id), None)
    if not device:
        return {"success": False, "error": "Device not found"}
    detail = {
        **device,
        "model": "Pixel 7" if "Pixel" in device["name"] else "iPhone 15" if "iPhone" in device["name"] else "Galaxy S24" if "Galaxy" in device["name"] else "Unknown",
        "build_number": "UP1A.230505.001" if "Android" in device["platform"] else "22A5358a",
        "imei": "358901234567890",
        "wifi_mac": "AA:BB:CC:DD:EE:01",
        "bluetooth_mac": "AA:BB:CC:DD:EE:02",
        "trust_score_breakdown": {
            "device_integrity": 85, "network_security": 70, "app_risk": 65,
            "behavioral_anomaly": 90, "location_trust": 80, "patch_level": 60,
        },
        "first_seen": "2026-01-15T09:00:00Z",
        "apps": SAMPLE_APPS,
        "recent_activities": [
            {"type": "app_install", "app": "Flashlight Pro", "timestamp": "2026-07-10T14:00:00Z", "risk": "medium"},
            {"type": "sms_sent", "to": "+12025559876", "timestamp": "2026-07-10T12:30:00Z", "risk": "low"},
            {"type": "location_change", "location": "New York, NY", "timestamp": "2026-07-10T10:15:00Z", "risk": "low"},
        ],
    }
    log_event("DEVICE_DETAIL_ACCESSED", "INFO", "mobile", {"device_id": device_id}, None)
    return {"success": True, "device": detail}


def scan_apps(device_id):
    log_event("APPS_SCANNED", "INFO", "mobile", {"device_id": device_id}, None)
    return {"success": True, "device_id": device_id, "apps": SAMPLE_APPS, "total_apps": len(SAMPLE_APPS), "malicious_count": sum(1 for a in SAMPLE_APPS if a["is_malicious"]), "scan_timestamp": datetime.utcnow().isoformat() + "Z"}


def analyze_sms(sms_text, sender_number):
    text = sms_text.lower()
    score = 0.0
    matched_patterns = []
    for pattern, weight in SMS_PHISHING_WEIGHTS.items():
        if pattern in text:
            score += weight
            matched_patterns.append(pattern)
    link_count = len(re.findall(r'https?://\S+', text))
    score += min(link_count * 0.05, 0.15)
    score = min(score, 1.0)
    is_spam = score > 0.50
    if is_spam:
        classification = "phishing" if any(p in ["win prize", "claim reward", "cash prize", "inheritance", "lottery"] for p in matched_patterns) else "spam"
        log_event("SMS_SPAM_DETECTED", "HIGH", "mobile", {"sender": sender_number, "probability": score, "classification": classification}, sender_number)
    else:
        classification = "legitimate"
    return {
        "success": True,
        "probability": round(score, 4),
        "is_spam": is_spam,
        "matched_patterns": matched_patterns,
        "classification": classification,
        "recommendation": "Block and report" if is_spam else "No threat detected",
    }


def malware_scan(file_hash):
    lower_hash = file_hash.lower()
    result = KNWON_BAD_HASHES.get(lower_hash)
    if result:
        log_event("MALWARE_DETECTED", result["severity"].upper(), "mobile", {"hash": file_hash, "threat": result["malware_name"]}, None)
        return {"success": True, "hash": file_hash, "threat_found": True, **result}
    return {"success": True, "hash": file_hash, "threat_found": False, "threat_type": None, "malware_name": None, "severity": None, "recommendation": "No known threats detected"}


def get_sms_logs():
    return {"success": True, "logs": SAMPLE_SMS_LOGS, "total": len(SAMPLE_SMS_LOGS)}


def get_call_logs():
    return {"success": True, "logs": SAMPLE_CALL_LOGS, "total": len(SAMPLE_CALL_LOGS)}


def device_health(device_id):
    device = next((d for d in SAMPLE_DEVICES if d["id"] == device_id), None)
    if not device:
        return {"success": False, "error": "Device not found"}
    score = 100
    issues = []
    recommendations = []
    outdated_versions_android = {"10.0", "11.0", "12.0", "13.0"}
    outdated_versions_ios = {"15.0", "16.0", "17.0"}
    os_ver = device["os_version"]
    if device["platform"] == "Android":
        major = os_ver.split(".")[0]
        if major in ("12", "13") or os_ver in outdated_versions_android:
            score -= 20
            issues.append("OS version is outdated")
            recommendations.append("Update to latest Android version")
    elif device["platform"] == "iOS":
        major = os_ver.split(".")[0]
        if major in ("15", "16", "17") or os_ver in outdated_versions_ios:
            score -= 20
            issues.append("OS version is outdated")
            recommendations.append("Update to latest iOS version")
    if device["is_compromised"]:
        score -= 30
        issues.append("Device is compromised (root/jailbreak detected)")
        recommendations.append("Factory reset device immediately")
    if not device.get("encryption_enabled", False if device["id"] in ("d-003", "d-004") else True):
        score -= 15
        issues.append("Device encryption is not enabled")
        recommendations.append("Enable device encryption")
    if device["id"] == "d-004":
        score -= 15
        issues.append("No screen lock configured")
        recommendations.append("Set up PIN or biometric screen lock")
    prompt_patch = os_ver
    patch_outdated = device.get("id") == "d-004"
    if patch_outdated:
        score -= 10
        issues.append("Security patch level is out of date")
        recommendations.append("Install latest security patch")
    score = max(score, 0)
    log_event("DEVICE_HEALTH_CHECKED", "INFO", "mobile", {"device_id": device_id, "health_score": score}, None)
    return {"success": True, "device_id": device_id, "health_score": score, "issues": issues, "recommendations": recommendations, "status": "healthy" if score >= 70 else "at_risk" if score >= 40 else "critical"}


def get_dashboard_stats():
    total = len(SAMPLE_DEVICES)
    compromised = sum(1 for d in SAMPLE_DEVICES if d["is_compromised"])
    at_risk = sum(1 for d in SAMPLE_DEVICES if d["risk_level"] in ("medium", "high"))
    secure = total - compromised - at_risk
    return {
        "success": True,
        "stats": {
            "total_devices": total,
            "compromised": compromised,
            "at_risk": at_risk,
            "secure": secure,
            "total_threats_blocked": 127,
            "sms_analyzed": 5432,
            "calls_scanned": 2189,
            "apps_scanned": 876,
            "avg_trust_score": round(sum(d["trust_score"] for d in SAMPLE_DEVICES) / total, 1),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def app_reputation(package_name):
    app = next((a for a in SAMPLE_APPS if a["package_name"] == package_name), None)
    if not app:
        return {"success": False, "error": "App not found"}
    permissions = [
        {"permission": "CAMERA", "risk_level": "high"},
        {"permission": "SMS", "risk_level": "critical"},
        {"permission": "CONTACTS", "risk_level": "high"},
        {"permission": "LOCATION", "risk_level": "high"},
        {"permission": "STORAGE", "risk_level": "medium"},
        {"permission": "INTERNET", "risk_level": "low"},
        {"permission": "MICROPHONE", "risk_level": "critical"},
        {"permission": "CALL_LOG", "risk_level": "high"},
        {"permission": "PHONE", "risk_level": "high"},
        {"permission": "VIBRATE", "risk_level": "low"},
    ]
    relevant_perms = []
    for p_app in app["permissions"]:
        for p_def in permissions:
            if p_def["permission"] == p_app:
                relevant_perms.append(p_def)
                break
    score = max(0, 100 - app["risk_score"])
    return {
        "success": True,
        "package_name": package_name,
        "app_name": app["app_name"],
        "reputation_score": score,
        "category": "Banking" if "bank" in app["package_name"] else "Utility" if "utility" in app["package_name"] else "Game" if "game" in app["package_name"] else "Tool" if "tracker" in app["package_name"] else "Social",
        "permissions": relevant_perms,
        "known_issues": ["Excessive permissions requested", "Data collection without clear disclosure"] if app["risk_score"] > 50 else [],
        "recommendation": "Remove app immediately" if app["is_malicious"] else "Review permissions" if app["risk_score"] > 50 else "App appears safe",
    }


def caller_scan(phone_number):
    spam_callers = {
        "+12025551234": {"reports": 234, "category": "scam", "name": "IRS Scam"},
        "+14035551234": {"reports": 567, "category": "telemarketer", "name": "Unknown Telemarketer"},
        "+12135551234": {"reports": 89, "category": "robocaller", "name": "Auto Warranty Scam"},
    }
    entry = spam_callers.get(phone_number)
    if entry:
        score = min(entry["reports"] / 10, 100)
        likelihood = "high" if entry["reports"] > 100 else "medium" if entry["reports"] > 50 else "low"
        log_event("SPAM_CALLER_DETECTED", "MEDIUM", "mobile", {"phone": phone_number, "category": entry["category"]}, phone_number)
        return {
            "success": True,
            "phone_number": phone_number,
            "spam_score": score,
            "spam_likelihood": likelihood,
            "category": entry["category"],
            "known_reports": entry["reports"],
            "caller_name": entry["name"],
            "recommendation": "Block number" if entry["reports"] > 50 else "Flag for review",
        }
    return {
        "success": True,
        "phone_number": phone_number,
        "spam_score": 0,
        "spam_likelihood": "low",
        "category": "legitimate",
        "known_reports": 0,
        "caller_name": "Unknown",
        "recommendation": "No spam reports found",
    }


def caller_feed():
    feed = [
        {"report_id": "r-001", "phone_number": "+12025551234", "category": "scam", "reported_by": "user_001", "timestamp": "2026-07-12T10:00:00Z", "description": "Caller claimed to be from IRS demanding payment"},
        {"report_id": "r-002", "phone_number": "+14035551234", "category": "telemarketer", "reported_by": "user_042", "timestamp": "2026-07-12T08:30:00Z", "description": "Repeated calls about extended car warranty"},
        {"report_id": "r-003", "phone_number": "+12135551234", "category": "robocaller", "reported_by": "user_017", "timestamp": "2026-07-11T19:45:00Z", "description": "Automated message about free cruise"},
        {"report_id": "r-004", "phone_number": "+17025559876", "category": "scam", "reported_by": "user_089", "timestamp": "2026-07-11T15:20:00Z", "description": "Fake tech support claiming virus on phone"},
        {"report_id": "r-005", "phone_number": "+13035554321", "category": "telemarketer", "reported_by": "user_033", "timestamp": "2026-07-10T12:00:00Z", "description": "Solar panel installation offer"},
    ]
    return {"success": True, "reports": feed, "total": len(feed)}


def volte_status(device_id):
    device = next((d for d in SAMPLE_DEVICES if d["id"] == device_id), None)
    if not device:
        return {"success": False, "error": "Device not found"}
    secure = device["risk_level"] not in ("high", "critical")
    return {
        "success": True,
        "device_id": device_id,
        "enabled": True,
        "encryption": "SRTP-AES-256" if secure else "None",
        "call_type": "VoLTE" if device["platform"] == "Android" else "VoWiFi",
        "secure": secure,
        "recommendation": "Enable VoLTE encryption" if not secure else "VoLTE/VoWiFi is secure",
        "vulnerabilities": ["No encryption negotiated"] if not secure else [],
    }
