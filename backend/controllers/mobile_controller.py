import json
import re
import random
import uuid
import hashlib
from datetime import datetime
from flask import jsonify, request
from config.settings import DATA_DIR

# ─────────────────────────────────────────────────────────────
# Shared risk-scoring helper
# Every scanner (SMS, malware, app reputation, caller ID) funnels
# its 0-100 score through this so the whole product uses one
# consistent 4-tier scale and color language.
# ─────────────────────────────────────────────────────────────
def risk_level(score):
    """Map a 0-100 risk score to a level/color/label used across the UI."""
    score = max(0, min(100, int(score)))
    if score < 20:
        return {"score": score, "level": "safe", "color": "green", "label": "Safe"}
    elif score < 40:
        return {"score": score, "level": "low", "color": "yellow", "label": "Low Risk"}
    elif score < 70:
        return {"score": score, "level": "medium", "color": "orange", "label": "Medium Risk"}
    else:
        return {"score": score, "level": "high", "color": "red", "label": "Dangerous"}

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
    risk_to_score = {"high": 80, "medium": 50, "low": 10}
    for a in installed:
        rl = risk_level(risk_to_score.get(a.get("risk", "low"), 10))
        a["score"] = rl["score"]
        a["risk_level"] = rl["level"]
        a["color"] = rl["color"]
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
    explanations = []
    phishing_keywords = ["click here", "claim now", "free prize", "won", "lottery", "congratulations",
                         "update kyc", "account blocked", "verify now", "urgent", "suspended", "loan offer"]
    suspicious_urls = re.findall(r'https?://[^\s]+', text)
    for url in suspicious_urls:
        suspicious_domains = ["bit.ly", "tinyurl", ".tk", ".cc", ".top", "secure-verify", "netflix-verify"]
        for dom in suspicious_domains:
            if dom in url.lower():
                score += 30
                findings.append(f"Suspicious URL domain: {url}")
                explanations.append(
                    f"The link uses '{dom}', a domain pattern commonly abused by phishing "
                    f"campaigns to disguise the real destination or mimic a trusted brand."
                )
    for kw in phishing_keywords:
        if kw.lower() in text.lower():
            score += 10
            findings.append(f"Phishing keyword found: '{kw}'")
            explanations.append(
                f"The phrase '{kw}' is a classic urgency/reward trigger scammers use to "
                f"pressure victims into acting before they think it through."
            )
    has_phone = bool(re.search(r'[\+0-9\-\(\)\s]{10,}', text))
    if has_phone:
        score += 5
        findings.append("Phone number detected in message")
        explanations.append(
            "A phone number is embedded in the message — legitimate banks and services rarely "
            "ask you to call an unlisted number instead of using their official app or website."
        )
    is_phishing = score >= 30
    is_suspicious = score >= 15 and not is_phishing
    verdict = "PHISHING" if is_phishing else ("SUSPICIOUS" if is_suspicious else "SAFE")
    rl = risk_level(score)
    if not explanations:
        summary = "No phishing indicators were detected in this message. It appears safe."
    else:
        summary = (
            f"This message was flagged {verdict} with a risk score of {rl['score']}/100 because of "
            f"{len(explanations)} indicator(s): " + " ".join(explanations)
        )
    return jsonify({
        "success": True,
        "score": rl["score"],
        "risk_level": rl["level"],
        "color": rl["color"],
        "risk_label": rl["label"],
        "verdict": verdict,
        "findings": findings,
        "explanations": explanations,
        "explanation": summary,
        "urls_found": suspicious_urls
    })

def malware_scan(current_user=None):
    with open(f"{DATA_DIR}/apps.json") as f:
        apps_db = json.load(f)
    sigs = apps_db["malware_signatures"]
    installed = apps_db["installed"]
    severity_score = {"critical": 95, "high": 80, "medium": 55, "low": 25}
    matches = []
    for app in installed:
        for sig in sigs:
            if sig["package"] in app.get("package", ""):
                sev = sig.get("severity", "medium").lower()
                s = severity_score.get(sev, 50)
                rl = risk_level(s)
                matches.append({
                    "app": app["name"],
                    "threat": sig["name"],
                    "type": sig["type"],
                    "severity": sig["severity"],
                    "score": rl["score"],
                    "risk_level": rl["level"],
                    "color": rl["color"],
                    "explanation": (
                        f"'{app['name']}' matches the known signature '{sig['name']}' "
                        f"({sig['type']}), classified as {sig['severity']} severity. "
                        f"Apps matching this signature have been observed performing malicious "
                        f"behavior consistent with this threat category."
                    )
                })
    overall_score = max([m["score"] for m in matches], default=0)
    overall_rl = risk_level(overall_score)
    return jsonify({
        "success": True,
        "scan_status": "completed",
        "threats_found": len(matches),
        "threats": matches,
        "apps_scanned": len(installed),
        "clean": len(installed) - len(matches),
        "score": overall_rl["score"],
        "risk_level": overall_rl["level"],
        "color": overall_rl["color"],
        "risk_label": overall_rl["label"],
        "explanation": (
            f"{len(matches)} app(s) matched known malware signatures out of {len(installed)} scanned."
            if matches else
            f"No malware signatures matched any of the {len(installed)} apps scanned. Device looks clean."
        )
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
    rl = risk_level(rep["score"])
    if rep["issues"]:
        explanation = (
            f"'{app_name}' ({rep['category']}) scored {rl['score']}/100 due to: "
            + "; ".join(rep["issues"]) + "."
        )
    else:
        explanation = f"'{app_name}' ({rep['category']}) has no known reputation issues on record."
    return jsonify({
        "success": True,
        "app_name": app_name,
        "package_name": package_name,
        "reputation_score": rl["score"],
        "score": rl["score"],
        "risk_level": rl["level"],
        "color": rl["color"],
        "risk_label": rl["label"],
        "category": rep["category"],
        "issues_found": rep["issues"],
        "explanation": explanation,
        "verdict": "UNSAFE" if rep["risk"] == "high" else "CAUTION" if rep["risk"] == "medium" else "SAFE",
        "recommendation": "Uninstall immediately" if rep["risk"] == "high" else "Review permissions" if rep["risk"] == "medium" else "App is reputable"
    })

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder
    PHONES_AVAILABLE = True
except ImportError:
    PHONES_AVAILABLE = False

# Standardized ISO-3166 alpha-2 -> country name labels (covers the regions
# we try during parsing plus the countries represented in the spam/community DB).
COUNTRY_NAMES = {
    "IN": "India", "US": "United States", "CA": "Canada", "GB": "United Kingdom",
    "AU": "Australia", "NG": "Nigeria", "PK": "Pakistan", "PH": "Philippines",
    "DE": "Germany", "FR": "France", "SG": "Singapore", "AE": "United Arab Emirates",
    "ZA": "South Africa", "BR": "Brazil", "ES": "Spain", "IT": "Italy",
    "RU": "Russia", "JP": "Japan", "KR": "South Korea", "CN": "China",
    "TW": "Taiwan", "HK": "Hong Kong", "MY": "Malaysia", "ID": "Indonesia",
    "TH": "Thailand", "VN": "Vietnam", "TR": "Turkey", "SA": "Saudi Arabia",
    "IL": "Israel", "EG": "Egypt", "KE": "Kenya", "GH": "Ghana",
    "TZ": "Tanzania", "AR": "Argentina", "MX": "Mexico", "CO": "Colombia",
    "CL": "Chile", "PE": "Peru", "NL": "Netherlands", "BE": "Belgium",
    "CH": "Switzerland", "SE": "Sweden", "NO": "Norway", "DK": "Denmark",
    "FI": "Finland", "PL": "Poland", "CZ": "Czech Republic", "AT": "Austria",
    "IE": "Ireland", "PT": "Portugal", "GR": "Greece", "HU": "Hungary",
    "RO": "Romania", "UA": "Ukraine", "NZ": "New Zealand", "LK": "Sri Lanka",
    "BD": "Bangladesh", "NP": "Nepal",
}

# Regions attempted, in order, when a number is given without a leading "+".
# India first since this product's primary user base dials without the "+91".
DEFAULT_REGIONS = ["IN", "US", "GB", "AU", "CA", "DE", "FR", "SG", "AE", "MY", "TH", "JP", "KR", "BR", "ZA", "NG"]

# ── Heuristic scoring helpers ────────────────────────────────
def _repeated_digits_penalty(national: str) -> int:
    """Penalize suspicious digit patterns (repeated/sequential digits)."""
    digits = re.sub(r'\D', '', national)
    penalty = 0
    if re.search(r'(\d)\1{2,}', digits[-6:]):
        penalty += 20
    if re.search(r'(\d)\1{3,}', digits):
        penalty += 15
    seqs = ['1234', '2345', '3456', '4567', '5678', '6789', '7890',
            '9876', '8765', '7654', '6543', '5432', '4321', '3210']
    if any(s in digits for s in seqs):
        penalty += 10
    return penalty


# Known VoIP / virtual-carrier substrings (carrier names containing these
# indicate a virtual number, which fraudsters often abuse).
VOIP_CARRIERS = ["vonage", "skype", "ringcentral", "google voice", "twilio",
                 "bandwidth", "textnow", "textfree", "nextplus", "talkatone",
                 "dingtone", "viber", "voip", "virtual", "burner"]


def _carrier_risk(carrier_name: str) -> int:
    """Return additional risk points if the carrier is a known VoIP provider."""
    cl = carrier_name.lower()
    return 30 if any(v in cl for v in VOIP_CARRIERS) else 0


def caller_scan(current_user=None):
    data = request.get_json() or {}
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "message": "Phone number required"}), 400

    valid = False
    parsed = None
    tried_region = None
    national_format = ""
    international_format = ""
    e164_format = ""
    carrier_name = "Unknown"
    region_desc = "Unknown"
    country_iso = ""
    country_name = "Unknown"
    country_dial_code = ""
    number_type_str = "unknown"

    if PHONES_AVAILABLE:
        regions_to_try = [None] if phone.strip().startswith("+") else DEFAULT_REGIONS
        for region_hint in regions_to_try:
            try:
                candidate = phonenumbers.parse(phone, region_hint)
                if phonenumbers.is_valid_number(candidate):
                    parsed = candidate
                    tried_region = region_hint
                    valid = True
                    break
                elif parsed is None:
                    parsed = candidate
            except Exception:
                continue

        if parsed is not None:
            try:
                national_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
                international_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
                region_desc = geocoder.description_for_number(parsed, "en") or "Unknown"
                country_iso = phonenumbers.region_code_for_number(parsed) or ""
                country_name = COUNTRY_NAMES.get(country_iso, country_iso or "Unknown")
                country_dial_code = f"+{parsed.country_code}"
                ntype = phonenumbers.number_type(parsed)
                type_map = {
                    phonenumbers.PhoneNumberType.MOBILE: "mobile",
                    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
                    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
                    phonenumbers.PhoneNumberType.VOIP: "voip",
                    phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
                    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
                    phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
                    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
                    phonenumbers.PhoneNumberType.PAGER: "pager",
                    phonenumbers.PhoneNumberType.UAN: "uan",
                    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
                }
                number_type_str = type_map.get(ntype, "unknown")
            except Exception:
                pass

    if not valid:
        return jsonify({
            "success": True,
            "phone": phone,
            "valid_number": False,
            "score": 0,
            "risk_level": "unknown",
            "color": "gray",
            "risk_label": "Invalid Number",
            "caller_name": "Unknown",
            "verdict": "INVALID",
            "explanation": (
                "This doesn't parse as a valid phone number for any recognized country. "
                "Try including the country code, e.g. +91XXXXXXXXXX for India or "
                "+1XXXXXXXXXX for the US/Canada."
            ),
            "recommendation": "Re-enter the number with its country code (E.164 format)."
        })

    # ── Heuristic risk scoring ──────────────────────────────
    score = 10

    # 1. Number-type risk
    type_risk = {
        "voip": 50, "premium_rate": 80, "shared_cost": 40,
        "voicemail": 35, "pager": 25, "uan": 15,
        "mobile": 15, "fixed_line_or_mobile": 15,
        "fixed_line": 5, "toll_free": 15, "personal": 10, "unknown": 20,
    }
    score += type_risk.get(number_type_str, 20)

    # 2. Repeated / sequential digit patterns
    score += _repeated_digits_penalty(national_format)

    # 3. Carrier (VoIP / virtual carrier detection)
    score += _carrier_risk(carrier_name)

    score = max(0, min(100, score))
    rl = risk_level(score)

    # ── Verdict & explanation ───────────────────────────────
    is_voip = _carrier_risk(carrier_name) > 0
    is_repeated = _repeated_digits_penalty(national_format) > 0

    if score >= 70:
        verdict = "SPAM"
        tags = ["voip"] if is_voip else ["scam"]
        reason = "is a VoIP/virtual number (commonly used by fraudsters)" if is_voip else "shows strong scam indicators"
        explanation = (
            f"Risk score {score}/100 — this {country_name} {number_type_str} number {reason}. "
            f"{'Suspicious digit pattern detected. ' if is_repeated else ''}"
            f"Carrier: {carrier_name}."
        )
        recommendation = "Block this number and report it to your telecom regulator. Do not answer or call back."
    elif score >= 40:
        verdict = "CAUTION"
        tags = ["suspicious"]
        explanation = (
            f"Risk score {score}/100 — this {country_name} {number_type_str} number shows "
            f"{'suspicious digit patterns' if is_repeated else 'moderate risk indicators'}. "
            f"Carrier: {carrier_name}."
        )
        recommendation = "Let unknown calls go to voicemail. Do not share personal information."
    else:
        verdict = "VERIFIED"
        tags = ["safe"]
        explanation = (
            f"Risk score {score}/100 — this {country_name} {number_type_str} number "
            f"appears to be a standard line with no strong scam indicators. "
            f"Carrier: {carrier_name}."
        )
        recommendation = "This number looks safe to answer, but always stay cautious with unknown callers."

    return jsonify({
        "success": True,
        "phone": phone,
        "valid_number": True,
        "e164": e164_format,
        "national_format": national_format,
        "international_format": international_format,
        "carrier": carrier_name,
        "region": region_desc,
        "country_iso": country_iso,
        "country_name": country_name,
        "country_dial_code": country_dial_code,
        "number_type": number_type_str,
        "caller_name": carrier_name if carrier_name != "Unknown" else "Unknown Caller",
        "identity_verified": score < 40,
        "spam": verdict == "SPAM",
        "spam_type": "voip" if is_voip else "suspicious" if verdict == "SPAM" else "legitimate",
        "score": rl["score"],
        "risk_level": rl["level"],
        "color": rl["color"],
        "risk_label": rl["label"],
        "total_reports": 0,
        "tags": tags,
        "verdict": verdict,
        "explanation": explanation,
        "recommendation": recommendation
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
        "volte_encryption": "AES-256",
        "volte_status": "active",
        "sip_tls": "TLS 1.3",
        "srtp_enabled": True,
        "cipher": "AES_CM_128_HMAC_SHA1_32",
        "calls_encrypted": 1472,
        "calls_total": 1520,
        "encryption_rate": "96.8%",
        "recommendation": "VoLTE encryption is active and compliant"
    })
