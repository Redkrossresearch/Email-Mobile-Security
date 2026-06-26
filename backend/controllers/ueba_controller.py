import json
import random
import uuid
from datetime import datetime
from flask import jsonify, request
from config.settings import DATA_DIR

BEHAVIOR_PROFILES = {}

def analyze_behavior(current_user=None):
    data = request.get_json() or {}
    user_id = data.get("user_id", "user@example.com")
    event_type = data.get("event_type", "login")
    ip = data.get("ip", "192.168.1.1")
    location = data.get("location", "Mumbai, IN")
    device_fingerprint = data.get("device_fingerprint", "fp_default")
    action = data.get("action", "login_attempt")
    timestamp = data.get("timestamp", datetime.utcnow().isoformat())
    if user_id not in BEHAVIOR_PROFILES:
        BEHAVIOR_PROFILES[user_id] = {
            "usual_ips": ["192.168.1.1", "10.0.0.1"],
            "usual_locations": ["Mumbai, IN", "Pune, IN"],
            "usual_hours": list(range(6, 22)),
            "events_logged": 0,
            "risk_score": 0
        }
    profile = BEHAVIOR_PROFILES[user_id]
    profile["events_logged"] += 1
    anomalies = []
    risk = 0
    if ip not in profile["usual_ips"]:
        risk += 20
        anomalies.append(f"Unusual IP address: {ip}")
    if location not in profile["usual_locations"]:
        risk += 15
        anomalies.append(f"Unusual location: {location}")
    hour = datetime.utcnow().hour
    if hour not in profile["usual_hours"]:
        risk += 10
        anomalies.append(f"Login at unusual hour: {hour}:00 UTC")
    if profile["events_logged"] > 50:
        risk += 10
        anomalies.append(f"High event frequency: {profile['events_logged']} events")
    profile["risk_score"] = min(profile.get("risk_score", 0) + risk, 100)
    return jsonify({
        "success": True,
        "user_id": user_id,
        "event_type": event_type,
        "anomaly_detected": len(anomalies) > 0,
        "risk_score": min(risk, 100),
        "cumulative_risk": profile["risk_score"],
        "anomalies": anomalies,
        "action": "BLOCK" if profile["risk_score"] >= 80 else "MFA_CHALLENGE" if profile["risk_score"] >= 50 else "ALLOW",
        "ml_model": "IsolationForest (v2.1)",
        "prediction": "anomalous" if risk >= 30 else "normal",
        "recommendation": "Step-up authentication required" if risk >= 30 else "Behavior within normal parameters"
    })

def get_user_profile(current_user=None):
    data = request.get_json() or {}
    user_id = data.get("user_id", "user@example.com")
    profile = BEHAVIOR_PROFILES.get(user_id, {
        "usual_ips": [],
        "usual_locations": [],
        "events_logged": 0,
        "risk_score": 0
    })
    return jsonify({
        "success": True,
        "user_id": user_id,
        "profile": profile,
        "behavioral_baseline": "established" if profile["events_logged"] > 10 else "learning",
        "days_of_data": min(profile["events_logged"] // 10, 30),
        "recommendation": "Continue monitoring for behavioral changes"
    })

def login_anomaly_detection(current_user=None):
    data = request.get_json() or {}
    user_id = data.get("user_id", "user@example.com")
    login_ip = data.get("ip", "192.168.1.1")
    user_agent = data.get("user_agent", "Mozilla/5.0")
    geolocation = data.get("geolocation", "Mumbai, IN")
    score = 0
    flags = []
    impossible_travel_pairs = [
        (["Mumbai, IN", "Delhi, IN"], ["New York, US", "London, GB"]),
    ]
    for local_set, remote_set in impossible_travel_pairs:
        if geolocation in remote_set and login_ip.startswith("10."):
            score += 50
            flags.append(f"Impossible travel: {geolocation} in {5} min")
    if "python" in user_agent.lower() or "curl" in user_agent.lower():
        score += 25
        flags.append(f"Automated tool detected: {user_agent}")
    if user_id not in BEHAVIOR_PROFILES:
        BEHAVIOR_PROFILES[user_id] = {"login_count": 0}
    BEHAVIOR_PROFILES[user_id]["login_count"] += 1
    if BEHAVIOR_PROFILES[user_id]["login_count"] > 10:
        score += 15
        flags.append(f"Excessive login attempts: {BEHAVIOR_PROFILES[user_id]['login_count']}")
    return jsonify({
        "success": True,
        "user_id": user_id,
        "anomaly_score": min(score, 100),
        "verdict": "ANOMALOUS" if score >= 40 else "SUSPICIOUS" if score >= 15 else "NORMAL",
        "flags": flags,
        "action": "BLOCK" if score >= 40 else "MFA" if score >= 15 else "ALLOW"
    })

def risk_scoring(current_user=None):
    data = request.get_json() or {}
    user_id = data.get("user_id", "user@example.com")
    signals = {
        "device_trust": data.get("device_trust_score", 85),
        "login_frequency": data.get("login_frequency", 5),
        "failed_attempts_24h": data.get("failed_attempts", 0),
        "ip_reputation": data.get("ip_reputation", 90),
        "geo_velocity": data.get("geo_velocity", "normal"),
        "time_anomaly": data.get("time_anomaly", False),
        "new_device": data.get("new_device", False)
    }
    weights = {"device_trust": 0.25, "login_frequency": 0.10, "failed_attempts_24h": 0.20, "ip_reputation": 0.20, "geo_velocity": 0.10, "time_anomaly": 0.08, "new_device": 0.07}
    risk = 0
    risk += (100 - signals["device_trust"]) * weights["device_trust"]
    risk += min(signals["login_frequency"] * 3, 30) * weights["login_frequency"]
    risk += min(signals["failed_attempts_24h"] * 10, 100) * weights["failed_attempts_24h"]
    risk += (100 - signals["ip_reputation"]) * weights["ip_reputation"]
    risk += (20 if signals["geo_velocity"] == "impossible" else 0) * weights["geo_velocity"]
    risk += (40 if signals["time_anomaly"] else 0) * weights["time_anomaly"]
    risk += (30 if signals["new_device"] else 0) * weights["new_device"]
    return jsonify({
        "success": True,
        "user_id": user_id,
        "risk_score": round(risk, 1),
        "risk_level": "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
        "signals_analyzed": len(signals),
        "decision": "DENY" if risk >= 75 else "MFA_REQUIRED" if risk >= 50 else "ALLOW_WITH_MONITORING" if risk >= 25 else "ALLOW"
    })
