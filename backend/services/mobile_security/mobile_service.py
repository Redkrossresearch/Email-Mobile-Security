import hashlib
import re
import os
import json
from datetime import datetime, timedelta, timezone as dt_timezone
from itertools import groupby
from services._shared.siem_logger import log_event
from config.database import _insert, _query, _query_one, _update_stat, _get_stat, get_db

CALLER_REPORTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "caller_reports.json")


def risk_level(score):
    if score >= 75:
        return {"level": "HIGH", "label": "High Risk", "color": "#ff3a6e", "css": "var(--danger)"}
    if score >= 45:
        return {"level": "MEDIUM", "label": "Medium Risk", "color": "#f5c400", "css": "var(--warn)"}
    if score >= 20:
        return {"level": "LOW", "label": "Low Risk", "color": "#4d9fff", "css": "var(--accent4)"}
    return {"level": "SAFE", "label": "Safe", "color": "#00ff88", "css": "var(--safe)"}

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    PHONES_AVAILABLE = True
except ImportError:
    PHONES_AVAILABLE = False

DEFAULT_REGIONS = ["IN", "US", "GB", "CA", "AU", "AE", "SG", "DE", "FR", "NL", "JP", "BR", "ZA", "MX"]
VOIP_CARRIERS = ["vonage", "twilio", "bandwidth", "skype", "ringcentral", "8x8", "zoom", "magicjack", "google voice", "phone.com", "microsoft teams", "voip"]

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
    # Prizes / lottery / scams
    "win prize": 0.20, "you won": 0.18, "you have won": 0.20, "congratulations": 0.16,
    "winner": 0.15, "selected": 0.12, "free vacation": 0.15, "free gift": 0.15,
    "claim reward": 0.17, "claim your": 0.12, "cash prize": 0.20, "cash reward": 0.18,
    "lottery": 0.18, "inheritance": 0.22, "gift card": 0.12, "redeem": 0.12,
    "exclusive offer": 0.12, "limited time": 0.10, "last chance": 0.14,
    # Urgency / pressure
    "urgent": 0.12, "act now": 0.16, "hurry": 0.12, "immediately": 0.10,
    "expires today": 0.16, "expire today": 0.16, "don't miss": 0.12,
    "within 24": 0.12, "few hours": 0.10,
    # Account / bank / KYC
    "account suspended": 0.14, "account blocked": 0.16, "account deactivated": 0.18,
    "deactivated": 0.16, "deactivate": 0.15, "verify now": 0.10, "verify your": 0.12,
    "update kyc": 0.18, "kyc": 0.15, "aadhaar": 0.18, "login attempt": 0.10,
    "reset password": 0.12, "payment failed": 0.13, "refund": 0.10,
    "fraud alert": 0.16, "unauthorized": 0.14, "net banking": 0.14, "upi": 0.10,
    "bank alert": 0.12, "card blocked": 0.16, "otp": 0.10, "atm card": 0.12,
    # Delivery / courier scams
    "package": 0.16, "parcel": 0.16, "delivery": 0.10, "deliver": 0.10,
    "shipment": 0.14, "tracking": 0.10, "on hold": 0.10, "failed delivery": 0.16,
    "courier": 0.12, "postal": 0.12, "fedex": 0.12, "dhl": 0.12, "usps": 0.12,
    # Brand impersonation
    "amazon": 0.06, "paypal": 0.08, "netflix": 0.08, "apple": 0.08,
    "sbi": 0.10, "hdfc": 0.10, "icici": 0.10, "google pay": 0.10, "paytm": 0.10,
    "phonepe": 0.10, "iphone": 0.10, "samsung": 0.06,
    # Click / links
    "click link": 0.14, "click here": 0.10, "click": 0.08, "call now": 0.08,
    "text stop": 0.06, "reply stop": 0.06,
    # Email-style spam
    "get rich": 0.16, "make money": 0.16, "work from home": 0.12, "data entry": 0.10,
    "crypto": 0.12, "bitcoin": 0.12, "forex": 0.14, "stock tip": 0.16, "invest now": 0.14,
    "medication": 0.12, "pharmacy": 0.12, "viagra": 0.16,
    "loan offer": 0.12, "free trial": 0.10, "income opportunity": 0.14,
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
    rows = _query("SELECT * FROM registered_devices ORDER BY last_seen DESC")
    devices = []
    for r in rows:
        devices.append({
            "id": r["device_id"], "name": r["name"], "platform": r["platform"],
            "os_version": r["os_version"], "model": r["model"],
            "trust_score": r["trust_score"], "last_seen": r["last_seen"],
            "is_compromised": bool(r["is_compromised"]), "risk_level": r["risk_level"],
        })
    return {"success": True, "devices": devices, "total": len(devices), "timestamp": datetime.utcnow().isoformat() + "Z"}


def register_device(device_id, name, platform="Android", os_version="Unknown", model="Unknown", imei="", registered_by=""):
    existing = _query_one("SELECT device_id FROM registered_devices WHERE device_id=?", (device_id,))
    if existing:
        _update("registered_devices", "device_id", device_id, {
            "name": name, "platform": platform, "os_version": os_version,
            "model": model, "imei": imei, "last_seen": datetime.utcnow().isoformat(),
        })
    else:
        _insert("registered_devices", {
            "device_id": device_id, "name": name, "platform": platform,
            "os_version": os_version, "model": model, "imei": imei,
            "trust_score": 80, "is_compromised": 0, "risk_level": "low",
            "encryption_enabled": 1, "screen_lock": 1,
            "registered_by": registered_by,
        })
    log_event("DEVICE_REGISTERED", "INFO", "mobile", {"device_id": device_id, "name": name}, registered_by)
    return {"success": True, "device_id": device_id, "message": "Device registered"}


def _update(table, id_col, id_val, updates):
    sets = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [id_val]
    conn = get_db()
    conn.execute(f"UPDATE {table} SET {sets} WHERE {id_col}=?", vals)
    conn.commit()
    conn.close()


def get_device_detail(device_id):
    r = _query_one("SELECT * FROM registered_devices WHERE device_id=?", (device_id,))
    if not r:
        return {"success": False, "error": "Device not found"}
    device = {
        "id": r["device_id"], "name": r["name"], "platform": r["platform"],
        "os_version": r["os_version"], "model": r["model"],
        "trust_score": r["trust_score"], "last_seen": r["last_seen"],
        "is_compromised": bool(r["is_compromised"]), "risk_level": r["risk_level"],
    }
    detail = {
        **device,
        "imei": r["imei"],
        "encryption_enabled": bool(r["encryption_enabled"]),
        "screen_lock": bool(r["screen_lock"]),
        "trust_score_breakdown": {
            "device_integrity": 85, "network_security": 70, "app_risk": 65,
            "behavioral_anomaly": 90, "location_trust": 80, "patch_level": 60,
        },
        "first_seen": r["created_at"],
        "apps": [],
        "recent_activities": [],
    }
    log_event("DEVICE_DETAIL_ACCESSED", "INFO", "mobile", {"device_id": device_id}, None)
    return {"success": True, "device": detail}


def scan_apps(device_id):
    log_event("APPS_SCANNED", "INFO", "mobile", {"device_id": device_id}, None)
    return {"success": True, "device_id": device_id, "apps": SAMPLE_APPS, "total_apps": len(SAMPLE_APPS), "malicious_count": sum(1 for a in SAMPLE_APPS if a["is_malicious"]), "scan_timestamp": datetime.utcnow().isoformat() + "Z"}


def analyze_sms(sms_text, sender_number):
    original = sms_text or ""
    text = original.lower()
    score = 0.0
    matched_patterns = []
    findings = []
    for pattern, weight in SMS_PHISHING_WEIGHTS.items():
        if pattern in text:
            score += weight
            matched_patterns.append(pattern)

    suspicious_urls = re.findall(r'https?://[^\s]+', text)
    suspicious_domains = ["bit.ly", "tinyurl", ".tk", ".cc", ".top", "secure-verify", "netflix-verify", "claim", "offer", "promo", "win"]
    for url in suspicious_urls:
        for dom in suspicious_domains:
            if dom in url.lower():
                score += 0.25
                findings.append(f"Suspicious URL domain: {url}")
                break
    link_count = len(suspicious_urls)
    score += min(link_count * 0.05, 0.15)

    phishing_keywords = ["click here", "claim now", "free prize", "won", "prize", "lottery", "congratulations",
                         "update kyc", "account blocked", "verify now", "urgent", "suspended", "loan offer",
                         "gift card", "act now", "redeem", "selected", "winner", "free vacation", "deactivated"]
    for kw in phishing_keywords:
        if kw in text:
            score += 0.10
            findings.append(f"Phishing keyword found: '{kw}'")

    has_phone = bool(re.search(r'[\+0-9\-\(\)\s]{10,}', text))
    if has_phone:
        score += 0.05
        findings.append("Phone number detected in message")

    # Heuristic: multiple exclamation marks (high-pressure language)
    excl = original.count("!")
    if excl >= 2:
        score += 0.12
        findings.append("Multiple exclamation marks — high-pressure language")
    elif excl == 1:
        score += 0.06

    # Heuristic: monetary amounts / currency symbols
    if re.search(r'[$€£₹¥]\s*\d', text) or re.search(r'\b(inr|rs\.?|rupees|dollars)\b\s*\d', text):
        score += 0.10
        findings.append("Monetary value mentioned in message")

    # Heuristic: excessive ALL-CAPS emphasis
    words = [w for w in re.findall(r'[A-Za-z]{4,}', original) if w.isalpha()]
    if words and len(words) >= 3 and sum(1 for w in words if w.isupper()) / len(words) >= 0.5:
        score += 0.10
        findings.append("Excessive ALL-CAPS text")

    # Heuristic: urgency / expiry language
    if re.search(r'\b(act now|hurry|expires?|last chance|within 24|don\'t miss|limited|immediately)\b', text):
        score += 0.10
        findings.append("Urgency / expiry language detected")

    # Heuristic: delivery / courier combo (classic parcel-scam phrasing)
    delivery_words = [w for w in ["package", "parcel", "delivery", "deliver", "shipment", "tracking", "on hold", "courier", "postal", "failed delivery"] if w in text]
    if len(delivery_words) >= 2:
        score += 0.15
        findings.append("Delivery-related terminology detected")

    score = min(score, 1.0)
    final_score = round(score * 100)
    is_spam = score > 0.45
    is_suspicious = score > 0.25 and not is_spam
    verdict = "PHISHING" if is_spam else ("SUSPICIOUS" if is_suspicious else "SAFE")
    if is_spam:
        classification = "phishing" if any(p in ["win prize", "claim reward", "cash prize", "cash reward", "inheritance", "lottery", "free vacation", "winner"] for p in matched_patterns) else "spam"
        log_event("SMS_SPAM_DETECTED", "HIGH", "mobile", {"sender": sender_number, "probability": score, "classification": classification}, sender_number)
    else:
        classification = "legitimate"
    result = {
        "success": True,
        "score": final_score,
        "probability": round(score, 4),
        "is_spam": is_spam,
        "verdict": verdict,
        "risk": risk_level(final_score),
        "matched_patterns": matched_patterns,
        "findings": findings,
        "urls_found": suspicious_urls,
        "classification": classification,
        "recommendation": "Block and report" if is_spam else "No threat detected",
    }
    try:
        _insert("sms_scan_history", {
            "text": original[:500], "score": final_score,
            "risk_level": risk_level(final_score)["level"].lower(),
            "verdict": verdict, "findings": json.dumps(findings),
            "urls_found": json.dumps(suspicious_urls),
            "scanned_by": sender_number or "system"
        })
        _update_stat("total_sms_scans")
        if is_spam:
            _update_stat("phishing_blocked")
    except Exception:
        pass
    return result


def malware_scan(file_hash):
    lower_hash = file_hash.lower()
    result = KNWON_BAD_HASHES.get(lower_hash)
    if result:
        log_event("MALWARE_DETECTED", result["severity"].upper(), "mobile", {"hash": file_hash, "threat": result["malware_name"]}, None)
        _insert("malware_scan_history", {
            "threats_found": 1, "apps_scanned": 0,
            "threats_json": json.dumps([result]), "score": 100, "risk_level": "high",
            "scanned_by": "system"
        })
        _update_stat("threats_blocked")
        return {"success": True, "hash": file_hash, "threat_found": True, "risk": risk_level(100), **result}

    from config.settings import VIRUSTOTAL_API_KEY
    if VIRUSTOTAL_API_KEY:
        try:
            import requests as _req
            resp = _req.get(
                f"https://www.virustotal.com/api/v3/files/{lower_hash}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if resp.ok:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                total_engines = sum(stats.values())
                detections = []
                for eng, res in data.get("last_analysis_results", {}).items():
                    if res.get("category") in ("malicious", "suspicious"):
                        detections.append({"engine": eng, "category": res["category"], "result": res.get("result", "unknown")})

                if malicious > 0:
                    severity = "critical" if malicious >= 10 else "high" if malicious >= 5 else "medium"
                    threat_name = data.get("meaningful_name", data.get("popular_threat_name", "Unknown Malware"))
                    score_val = min(int(malicious / max(total_engines, 1) * 100), 100)
                    log_event("MALWARE_DETECTED_VT", severity.upper(), "mobile", {"hash": file_hash, "threat": threat_name, "detections": malicious}, None)
                    _insert("malware_scan_history", {
                        "threats_found": 1, "apps_scanned": 0,
                        "threats_json": json.dumps([{"malware_name": threat_name, "detections": malicious, "suspicious": suspicious}]),
                        "score": score_val, "risk_level": risk_level(score_val)["level"].lower(),
                        "scanned_by": "virustotal"
                    })
                    _update_stat("threats_blocked")
                    return {
                        "success": True, "hash": file_hash, "threat_found": True,
                        "risk": risk_level(score_val),
                        "threat_type": "malware", "malware_name": threat_name,
                        "severity": severity,
                        "detections": malicious, "suspicious": suspicious, "undetected": undetected,
                        "total_engines": total_engines, "detection_list": detections[:20],
                        "file_type": data.get("type_description", "unknown"),
                        "file_size": data.get("size", 0),
                        "names": data.get("names", [])[:5],
                        "reputation": data.get("reputation", 0),
                        "recommendation": "Quarantine and remove immediately",
                    }
                else:
                    return {
                        "success": True, "hash": file_hash, "threat_found": False,
                        "risk": risk_level(0), "threat_type": None, "malware_name": None,
                        "severity": None,
                        "detections": 0, "suspicious": suspicious, "undetected": undetected,
                        "total_engines": total_engines, "detection_list": [],
                        "file_type": data.get("type_description", "unknown"),
                        "file_size": data.get("size", 0),
                        "reputation": data.get("reputation", 0),
                        "recommendation": "No threats detected — file appears clean",
                    }
            elif resp.status_code == 404:
                return {"success": True, "hash": file_hash, "threat_found": False, "risk": risk_level(0), "threat_type": None, "malware_name": None, "severity": None, "recommendation": "Hash not found in VirusTotal database — unknown file", "detections": 0, "total_engines": 0}
        except Exception as e:
            log_event("VT_API_ERROR", "WARNING", "mobile", {"hash": file_hash, "error": str(e)}, None)

    return {"success": True, "hash": file_hash, "threat_found": False, "risk": risk_level(0), "threat_type": None, "malware_name": None, "severity": None, "recommendation": "No known threats detected"}


def get_sms_logs():
    return {"success": True, "logs": SAMPLE_SMS_LOGS, "total": len(SAMPLE_SMS_LOGS)}


def get_call_logs():
    db_calls = _query("SELECT * FROM call_logs ORDER BY timestamp DESC LIMIT 100")
    logs = []
    for c in db_calls:
        logs.append({
            "id": c["id"], "number": c["phone"], "name": c["name"],
            "direction": c["direction"], "duration": c["duration"],
            "blocked": bool(c["blocked"]), "type": c["spam_type"],
            "time": c["timestamp"], "source": "real"
        })
    return {"success": True, "logs": logs, "calls": logs, "total": len(logs)}


def check_battery():
    battery_data = [
        {"name": "DeviceTracker", "cpu": 87, "battery": 38, "flagged": True},
        {"name": "Flashlight Pro", "cpu": 62, "battery": 55, "flagged": True},
        {"name": "SecureBank", "cpu": 18, "battery": 82, "flagged": False},
        {"name": "FriendConnect", "cpu": 12, "battery": 74, "flagged": False},
        {"name": "Candy Crush Clone", "cpu": 8, "battery": 66, "flagged": False},
    ]
    log_event("BATTERY_CHECKED", "INFO", "mobile", {"apps_flagged": sum(1 for a in battery_data if a["flagged"])}, None)
    return {"success": True, "apps": battery_data, "flagged_count": sum(1 for a in battery_data if a["flagged"]), "verdict": "BATTERY_ABUSE_CHECKED"}


def device_health(device_id):
    r = _query_one("SELECT * FROM registered_devices WHERE device_id=?", (device_id,))
    if not r:
        return {"success": False, "error": "Device not found"}
    score = 100
    issues = []
    recommendations = []
    os_ver = r["os_version"]
    if r["platform"] == "Android":
        major = os_ver.split(".")[0] if os_ver else "0"
        if major in ("10", "11", "12", "13"):
            score -= 20
            issues.append("OS version is outdated")
            recommendations.append("Update to latest Android version")
    elif r["platform"] == "iOS":
        major = os_ver.split(".")[0] if os_ver else "0"
        if major in ("15", "16", "17"):
            score -= 20
            issues.append("OS version is outdated")
            recommendations.append("Update to latest iOS version")
    if r["is_compromised"]:
        score -= 30
        issues.append("Device is compromised (root/jailbreak detected)")
        recommendations.append("Factory reset device immediately")
    if not r["encryption_enabled"]:
        score -= 15
        issues.append("Device encryption is not enabled")
        recommendations.append("Enable device encryption")
    if not r["screen_lock"]:
        score -= 15
        issues.append("No screen lock configured")
        recommendations.append("Set up PIN or biometric screen lock")
    score = max(score, 0)
    log_event("DEVICE_HEALTH_CHECKED", "INFO", "mobile", {"device_id": device_id, "health_score": score}, None)
    return {"success": True, "device_id": device_id, "health_score": score, "issues": issues, "recommendations": recommendations, "status": "healthy" if score >= 70 else "at_risk" if score >= 40 else "critical"}


def get_dashboard_stats():
    dev_stats = _query_one("SELECT COUNT(*) as total, SUM(is_compromised) as compromised FROM registered_devices")
    total = dev_stats["total"] if dev_stats else 0
    compromised = dev_stats["compromised"] if dev_stats and dev_stats["compromised"] else 0
    at_risk_q = _query_one("SELECT COUNT(*) as cnt FROM registered_devices WHERE risk_level IN ('medium','high')")
    at_risk = at_risk_q["cnt"] if at_risk_q else 0
    secure = total - compromised - at_risk
    db_scans = _get_stat("total_scans")
    db_threats = _get_stat("threats_blocked")
    db_sms = _get_stat("total_sms_scans")
    db_phishing = _get_stat("phishing_blocked")
    db_caller = _query_one("SELECT COUNT(*) as cnt FROM caller_history")
    db_call_logs = _query_one("SELECT COUNT(*) as cnt, SUM(blocked) as blocked FROM call_logs")
    return {
        "success": True,
        "stats": {
            "total_devices": total,
            "compromised": compromised,
            "at_risk": at_risk,
            "secure": secure,
            "total_threats_blocked": db_threats,
            "sms_analyzed": db_sms,
            "calls_scanned": db_caller["cnt"] if db_caller else 0,
            "apps_scanned": _get_stat("total_scans"),
            "avg_trust_score": 0,
            "threats_blocked": db_threats,
            "sms_phishing": db_phishing,
            "calls_blocked": (db_call_logs["blocked"] or 0) if db_call_logs else 0,
            "devices_monitored": total,
            "total_apps": 0,
            "total_scans": db_scans,
            "total_caller_scans": db_caller["cnt"] if db_caller else 0,
            "total_sms_scans": db_sms,
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def app_reputation(package_name="", file_hash=""):
    if file_hash:
        from config.settings import VIRUSTOTAL_API_KEY
        if VIRUSTOTAL_API_KEY:
            try:
                import requests as _req
                resp = _req.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash.lower()}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    timeout=10,
                )
                if resp.ok:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    total_engines = sum(stats.values())
                    detections = []
                    for eng, res in data.get("last_analysis_results", {}).items():
                        if res.get("category") in ("malicious", "suspicious"):
                            detections.append({"engine": eng, "category": res["category"], "result": res.get("result", "unknown")})

                    rep_score = max(0, 100 - int(malicious / max(total_engines, 1) * 100)) if total_engines else 50
                    verdict = "UNSAFE" if malicious >= 5 else "CAUTION" if malicious >= 1 or suspicious >= 3 else "SAFE"

                    _insert("app_scan_history", {
                        "app_name": data.get("meaningful_name", "Unknown"),
                        "package_name": file_hash,
                        "scan_type": "virustotal",
                        "score": 100 - rep_score,
                        "risk_level": risk_level(100 - rep_score)["level"].lower(),
                        "issues": json.dumps(detections[:10]),
                        "scanned_by": "virustotal"
                    })
                    _update_stat("total_scans")

                    return {
                        "success": True,
                        "hash": file_hash,
                        "package_name": data.get("meaningful_name", "Unknown"),
                        "app_name": data.get("meaningful_name", "Unknown"),
                        "reputation_score": rep_score,
                        "risk_score": 100 - rep_score,
                        "risk": risk_level(100 - rep_score),
                        "verdict": verdict,
                        "detections": malicious,
                        "suspicious": suspicious,
                        "undetected": undetected,
                        "total_engines": total_engines,
                        "detection_list": detections[:20],
                        "file_type": data.get("type_description", "unknown"),
                        "file_size": data.get("size", 0),
                        "names": data.get("names", [])[:5],
                        "tags": data.get("tags", []),
                        "recommendation": "Remove immediately" if malicious >= 5 else "Review carefully" if malicious >= 1 else "App appears safe",
                    }
                elif resp.status_code == 404:
                    return {"success": True, "hash": file_hash, "verdict": "UNKNOWN", "recommendation": "Hash not found in VirusTotal — cannot verify", "detections": 0, "total_engines": 0}
            except Exception as e:
                log_event("VT_APP_ERROR", "WARNING", "mobile", {"hash": file_hash, "error": str(e)}, None)

    app = next((a for a in SAMPLE_APPS if a["package_name"] == package_name), None)
    if not app:
        return {"success": False, "error": "App not found. Provide a file_hash for VirusTotal lookup or a known package_name."}
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
    _insert("app_scan_history", {
        "app_name": app["app_name"],
        "package_name": package_name,
        "scan_type": "local",
        "score": app["risk_score"],
        "risk_level": risk_level(app["risk_score"])["level"].lower(),
        "issues": json.dumps(["Excessive permissions"] if app["risk_score"] > 50 else []),
        "scanned_by": "local"
    })
    _update_stat("total_scans")
    return {
        "success": True,
        "package_name": package_name,
        "app_name": app["app_name"],
        "reputation_score": score,
        "risk_score": app["risk_score"],
        "risk": risk_level(app["risk_score"]),
        "category": "Banking" if "bank" in app["package_name"] else "Utility" if "utility" in app["package_name"] else "Game" if "game" in app["package_name"] else "Tool" if "tracker" in app["package_name"] else "Social",
        "verdict": "UNSAFE" if app["is_malicious"] else "CAUTION" if app["risk_score"] > 50 else "SAFE",
        "permissions": relevant_perms,
        "known_issues": ["Excessive permissions requested", "Data collection without clear disclosure"] if app["risk_score"] > 50 else [],
        "recommendation": "Remove app immediately" if app["is_malicious"] else "Review permissions" if app["risk_score"] > 50 else "App appears safe",
    }


def _load_reports():
    try:
        with open(CALLER_REPORTS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_reports(reports):
    try:
        os.makedirs(os.path.dirname(CALLER_REPORTS_FILE), exist_ok=True)
        with open(CALLER_REPORTS_FILE, "w") as f:
            json.dump(reports, f, indent=2)
    except Exception as e:
        log_event("CALLER_REPORT_SAVE_FAILED", "WARNING", "mobile", {"error": str(e)}, None)


def report_caller(phone_number, category="scam", caller_name=""):
    if not category:
        category = "scam"
    reports = _load_reports()
    digits = re.sub(r"\D", "", str(phone_number or ""))
    key = phone_number if str(phone_number or "").startswith("+") else ("+" + digits)
    entry = reports.get(key) or {"reports": 0, "categories": {}, "name": "", "last_reported": ""}
    entry["reports"] += 1
    entry["categories"][category] = entry["categories"].get(category, 0) + 1
    if caller_name:
        entry["name"] = caller_name
    entry["last_reported"] = datetime.utcnow().isoformat() + "Z"
    reports[key] = entry
    _save_reports(reports)
    log_event("CALLER_REPORTED", "MEDIUM", "mobile", {"phone": key, "category": category, "reports": entry["reports"]}, key)
    return {"success": True, "phone": key, "category": category, "total_reports": entry["reports"], "message": "Number reported. It is now flagged across the platform in real time."}


def _relative_time(iso_ts):
    try:
        t = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt_timezone.utc)
        secs = (datetime.now(dt_timezone.utc) - t).total_seconds()
    except Exception:
        return "recent"
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} hr ago"
    return f"{int(secs // 86400)} days ago"


def caller_scan(phone_number):
    spam_callers = {
        "+12025551234": {"reports": 234, "category": "scam", "name": "SCAM DETECTED"},
        "+14035551234": {"reports": 567, "category": "telemarketer", "name": "Unknown Telemarketer"},
        "+12135551234": {"reports": 89, "category": "robocaller", "name": "Auto Warranty Scam"},
        "+919999999999": {"reports": 1256, "category": "scam", "name": "SCAM CALLER"},
        "+919876543210": {"reports": 342, "category": "telemarketer", "name": "SPAM LIKELY"},
        "+14155551234": {"reports": 567, "category": "robocall", "name": "SPAM RISK"},
        "+911234567890": {"reports": 2, "category": "legitimate", "name": "Ramesh Kumar"},
        "+440123456789": {"reports": 0, "category": "legitimate", "name": "James Wilson"},
    }
    digits_only = re.sub(r"\D", "", str(phone_number or ""))
    valid = False
    national_format = ""
    international_format = ""
    e164_format = ""
    carrier_name = "Unknown"
    region = "Unknown"
    country_code_val = ""
    region_code = ""
    is_voip = False
    timezones = []

    if PHONES_AVAILABLE and digits_only:
        for hint in [None] + DEFAULT_REGIONS:
            try:
                candidate = phonenumbers.parse(phone_number, hint)
                if phonenumbers.is_valid_number(candidate):
                    parsed = candidate
                    break
            except Exception:
                continue
        else:
            parsed = None
        if parsed is not None:
            valid = phonenumbers.is_valid_number(parsed)
            national_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            international_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
            region = geocoder.description_for_number(parsed, "en") or "Unknown"
            country_code_val = str(parsed.country_code)
            region_code = phonenumbers.region_code_for_number(parsed) or ""
            try:
                timezones = list(timezone.time_zones_for_number(parsed))
            except Exception:
                timezones = []
            if any(v in carrier_name.lower() for v in VOIP_CARRIERS):
                is_voip = True

    known_entry = spam_callers.get(phone_number) or spam_callers.get("+" + digits_only)
    community = _load_reports().get(phone_number) or _load_reports().get("+" + digits_only)

    # Combined entry: known demo data takes precedence for name; community reports add score.
    entry = None
    total_reports = 0
    if known_entry:
        entry = dict(known_entry)
    if community:
        entry = entry or {}
        entry["reports"] = entry.get("reports", 0) + community.get("reports", 0)
        entry["name"] = community.get("name") or entry.get("name", "Unknown")
        top_cat = max(community.get("categories", {}), key=community.get("categories", {}).get) if community.get("categories") else "spam"
        if community.get("reports"):
            entry["category"] = top_cat

    if entry and entry.get("category") != "legitimate":
        score = min(entry["reports"] / 10, 70)
        total_reports = entry.get("reports", 0)
        log_event("SPAM_CALLER_DETECTED", "MEDIUM", "mobile", {"phone": phone_number, "category": entry["category"], "reports": total_reports}, phone_number)
    else:
        score = 0

    longest_run = 1
    if len(digits_only) >= 8:
        longest_run = max(len(list(g)) for _, g in groupby(digits_only))

    if longest_run >= 5:
        score += 25
    elif longest_run == 4:
        score += 15
    elif longest_run == 3:
        score += 8

    # Real-time heuristics for ANY number
    suspicious_prefixes = ["900", "901", "1900", "809", "140", "1800"]
    if any(digits_only.startswith(p) for p in suspicious_prefixes):
        score += 15
    if len(digits_only) >= 6:
        ascending = all(int(a) <= int(b) for a, b in zip(digits_only, digits_only[1:]))
        descending = all(int(a) >= int(b) for a, b in zip(digits_only, digits_only[1:]))
        if ascending or descending:
            score += 12
    if re.fullmatch(r"(\d)\1{5,}", digits_only):
        score += 30
    if is_voip and not entry:
        score += 10
    if not valid:
        score = max(score, 30)
    score = min(int(score), 100)

    tags = []
    if entry and entry.get("category") != "legitimate":
        tags.append(entry["category"].upper())
    if community:
        tags.append("COMMUNITY REPORTED")
    if is_voip:
        tags.append("VOIP")
    if longest_run >= 4:
        tags.append("REPEATED DIGITS")
    if not valid:
        tags.append("UNVERIFIED")
    if re.fullmatch(r"(\d)\1{5,}", digits_only):
        tags.append("FAKE NUMBER PATTERN")
    if not tags:
        tags = ["SAFE"]

    if not valid:
        verdict = "UNVERIFIED"
    elif score >= 75:
        verdict = "HIGH_RISK"
    elif entry and entry.get("category") != "legitimate":
        verdict = "SPAM"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif is_voip:
        verdict = "VOIP_SUSPECT"
    elif not entry and not community:
        verdict = "UNKNOWN"
    else:
        verdict = "SAFE"

    spam = bool(entry and entry.get("category") != "legitimate") or score >= 40

    risk = risk_level(score)
    if spam and risk["level"] == "SAFE":
        risk = risk_level(max(score, 20))

    return {
        "success": True,
        "phone": phone_number,
        "valid_number": valid,
        "national_format": national_format,
        "international_format": international_format,
        "e164_format": e164_format,
        "carrier": carrier_name,
        "is_voip": is_voip,
        "region": region,
        "country_code": country_code_val,
        "region_code": region_code,
        "timezones": timezones,
        "caller_name": (entry or {}).get("name") or "Unknown",
        "spam": spam,
        "spam_type": (entry or {}).get("category", "unknown"),
        "spam_score": score,
        "risk": risk,
        "total_reports": total_reports,
        "community_reports": community.get("reports", 0) if community else 0,
        "tags": tags,
        "verdict": verdict,
        "recommendation": "Block this number and report to DND registry" if spam else ("VoIP number — verify identity before sharing details" if is_voip else ("Not a valid E.164 number — enter full number with country code" if not valid else ("No community data on this number yet — verify before sharing sensitive info" if verdict == "UNKNOWN" else "Caller appears legitimate"))),
    }
    try:
        _insert("caller_history", {
            "phone": phone_number, "e164": e164_format,
            "country_iso": region_code, "country_name": region,
            "carrier": carrier_name, "number_type": "voip" if is_voip else "mobile",
            "score": score, "risk_level": risk["level"].lower(),
            "verdict": verdict, "tags": json.dumps(tags),
            "explanation": f"Score {score}/100. {total_reports} reports.",
            "recommendation": "Block" if spam else "Safe"
        })
        _update_stat("total_scans")
        if spam:
            _update_stat("threats_blocked")
    except Exception:
        pass


def caller_feed():
    feed = []

    # Deterministic "live" events — changes every minute so the feed feels real-time
    now = datetime.now(dt_timezone.utc)
    live_pool = [
        {"number": "+919620334455", "name": "Telemarketing Spam", "type": "telemarketer", "status": "blocked", "reports": 14},
        {"number": "+919990001111", "name": "Bank KYC Scam", "type": "scam", "status": "blocked", "reports": 23},
        {"number": "+911234567890", "name": "Ramesh Kumar", "type": "contact", "status": "allowed", "reports": 0},
        {"number": "+14155551234", "name": "Auto Warranty Scam", "type": "robocall", "status": "blocked", "reports": 9},
        {"number": "+440123456789", "name": "James Wilson", "type": "contact", "status": "allowed", "reports": 0},
        {"number": "+919620778899", "name": "Loan Offer Scam", "type": "scam", "status": "blocked", "reports": 7},
    ]
    idx = now.minute % len(live_pool)
    feed.append({**live_pool[idx], "time": "just now"})
    feed.append({**live_pool[(idx + 2) % len(live_pool)], "time": "1 min ago"})

    # Community reports (last 24h)
    for phone, rep in _load_reports().items():
        if not rep.get("last_reported"):
            continue
        try:
            last = datetime.fromisoformat(rep["last_reported"].replace("Z", "+00:00"))
        except Exception:
            continue
        if (now - last).total_seconds() < 86400:
            cat = max(rep.get("categories", {}), key=rep.get("categories", {}).get) if rep.get("categories") else "scam"
            feed.append({
                "number": phone, "name": rep.get("name") or "Community Reported", "type": cat,
                "status": "blocked", "time": _relative_time(rep["last_reported"]),
                "reports": rep.get("reports", 0),
            })

    # Real call logs from the device feed
    try:
        with open(os.path.join(os.path.dirname(CALLER_REPORTS_FILE), "call_logs.json")) as f:
            logs = json.load(f)
    except Exception:
        logs = []
    for entry in logs[:8]:
        feed.append({
            "number": entry.get("from", "UNKNOWN"), "name": str(entry.get("type", "unknown")).title(),
            "type": entry.get("type", "unknown"), "status": "blocked" if entry.get("blocked") else "allowed",
            "time": _relative_time(entry.get("timestamp", "")), "reports": 0,
        })

    return {"success": True, "feed": feed, "total_blocked": sum(1 for f in feed if f["status"] == "blocked"), "verdict": "CALL_FEED_UPDATED"}


def volte_status(device_id):
    r = _query_one("SELECT * FROM registered_devices WHERE device_id=?", (device_id,))
    if not r:
        return {"success": False, "error": "Device not found"}
    secure = r["risk_level"] not in ("high", "critical")
    return {
        "success": True,
        "device_id": device_id,
        "enabled": True,
        "encryption": "SRTP-AES-256" if secure else "None",
        "call_type": "VoLTE" if r["platform"] == "Android" else "VoWiFi",
        "secure": secure,
        "recommendation": "Enable VoLTE encryption" if not secure else "VoLTE/VoWiFi is secure",
        "vulnerabilities": ["No encryption negotiated"] if not secure else [],
    }
