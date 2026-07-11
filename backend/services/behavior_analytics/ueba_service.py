import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from services._shared.siem_logger import log_event

LOGIN_HISTORY = defaultdict(list)
BEHAVIOR_PROFILES = {}

KNOWN_IPS = {
    "192.168.1.0/24": "internal",
    "10.0.0.0/8": "internal",
    "172.16.0.0/12": "internal",
}


def _ip_to_int(ip):
    parts = ip.strip().split(".")
    result = 0
    for part in parts:
        result = result * 256 + int(part)
    return result


def _ip_in_subnet(ip, subnet):
    try:
        ip_int = _ip_to_int(ip)
        network, prefix_len = subnet.split("/")
        prefix_len = int(prefix_len)
        network_int = _ip_to_int(network)
        if prefix_len == 0:
            return True
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        return (ip_int & mask) == (network_int & mask)
    except Exception:
        return False


def _get_ip_location(ip):
    try:
        ip_int = _ip_to_int(ip)
    except Exception:
        return {
            "city": "Unknown",
            "country": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Unknown",
        }

    for subnet, label in KNOWN_IPS.items():
        if _ip_in_subnet(ip, subnet):
            return {
                "city": "Local Network",
                "country": "Internal",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Internal Network",
            }

    bucket = ip_int % 10
    geo_map = {
        0: {"city": "New York", "country": "US", "latitude": 40.7128, "longitude": -74.0060, "isp": "Comcast"},
        1: {"city": "London", "country": "GB", "latitude": 51.5074, "longitude": -0.1278, "isp": "BT Group"},
        2: {"city": "Tokyo", "country": "JP", "latitude": 35.6762, "longitude": 139.6503, "isp": "NTT"},
        3: {"city": "Berlin", "country": "DE", "latitude": 52.52, "longitude": 13.405, "isp": "Deutsche Telekom"},
        4: {"city": "Sydney", "country": "AU", "latitude": -33.8688, "longitude": 151.2093, "isp": "Telstra"},
        5: {"city": "Mumbai", "country": "IN", "latitude": 19.076, "longitude": 72.8777, "isp": "Jio"},
        6: {"city": "Toronto", "country": "CA", "latitude": 43.6532, "longitude": -79.3832, "isp": "Rogers"},
        7: {"city": "Singapore", "country": "SG", "latitude": 1.3521, "longitude": 103.8198, "isp": "Singtel"},
        8: {"city": "São Paulo", "country": "BR", "latitude": -23.5505, "longitude": -46.6333, "isp": "Vivo"},
        9: {"city": "Dubai", "country": "AE", "latitude": 25.2048, "longitude": 55.2708, "isp": "Etisalat"},
    }
    return geo_map[bucket]


def _calculate_anomaly_score(email, login_data):
    factors = []
    score = 0
    profile = BEHAVIOR_PROFILES.get(email, {})

    loc = _get_ip_location(login_data.get("ip_address", "0.0.0.0"))
    current_country = loc.get("country", "Unknown")

    if profile:
        common_countries = profile.get("common_countries", {})
        if common_countries and current_country not in common_countries and current_country != "Unknown":
            factors.append(f"Login from unusual country: {current_country}")
            score += 30

        timestamp_str = login_data.get("timestamp", "")
        if timestamp_str:
            try:
                if isinstance(timestamp_str, str):
                    ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                else:
                    ts = timestamp_str
                hour = ts.hour if hasattr(ts, "hour") else 12
                if hour < 8 or hour > 20:
                    factors.append(f"Login outside normal working hours ({hour}:00)")
                    score += 15
            except Exception:
                pass

        recent_logins = [e for e in profile.get("events", []) if
                         (datetime.utcnow() - e.get("timestamp_obj", datetime.utcnow())) < timedelta(hours=1)]
        if len(recent_logins) > 10:
            factors.append(f"High login frequency: {len(recent_logins)} in last hour")
            score += 20

    current_fp = login_data.get("device_fingerprint", "")
    if profile and current_fp:
        known_fps = profile.get("known_device_fingerprints", set())
        if known_fps and current_fp not in known_fps:
            factors.append("Device fingerprint changed")
            score += 15

    recent_events = profile.get("events", []) if profile else []
    recent_hour = [e for e in recent_events if
                   (datetime.utcnow() - e.get("timestamp_obj", datetime.utcnow())) < timedelta(hours=1)]
    recent_failures = [e for e in recent_hour if not e.get("success", True)]
    if len(recent_failures) > 3:
        factors.append(f"Multiple recent failed attempts: {len(recent_failures)}")
        score += 25

    if not factors:
        score = 0

    score = min(score, 100)
    is_anomalous = score >= 40

    return {
        "score": score,
        "factors": factors,
        "is_anomalous": is_anomalous,
    }


def _update_profile(email, login_data):
    now = datetime.utcnow()
    ts_raw = login_data.get("timestamp", "")
    if ts_raw:
        try:
            if isinstance(ts_raw, str):
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
            else:
                ts = ts_raw
        except Exception:
            ts = now
    else:
        ts = now

    entry = {
        "ip_address": login_data.get("ip_address", ""),
        "user_agent": login_data.get("user_agent", ""),
        "device_fingerprint": login_data.get("device_fingerprint", ""),
        "success": login_data.get("success", True),
        "failure_reason": login_data.get("failure_reason", ""),
        "timestamp_obj": ts,
    }

    loc = _get_ip_location(login_data.get("ip_address", "0.0.0.0"))
    entry["country"] = loc.get("country", "Unknown")
    entry["city"] = loc.get("city", "Unknown")

    if email not in BEHAVIOR_PROFILES:
        BEHAVIOR_PROFILES[email] = {
            "email": email,
            "first_seen": now,
            "last_login": now,
            "total_logins": 0,
            "failed_logins": 0,
            "events": [],
            "known_ips": set(),
            "known_device_fingerprints": set(),
            "common_countries": defaultdict(int),
            "common_ips": defaultdict(int),
            "common_hours": defaultdict(int),
        }

    profile = BEHAVIOR_PROFILES[email]
    profile["events"].append(entry)
    profile["events"] = profile["events"][-100:]
    profile["last_login"] = ts
    profile["total_logins"] += 1

    if not login_data.get("success", True):
        profile["failed_logins"] += 1

    profile["known_ips"].add(login_data.get("ip_address", ""))
    fp = login_data.get("device_fingerprint", "")
    if fp:
        profile["known_device_fingerprints"].add(fp)
    profile["common_countries"][entry["country"]] += 1
    profile["common_ips"][entry["ip_address"]] += 1
    profile["common_hours"][ts.hour] += 1


def analyze_behavior(email, login_data):
    anomaly = _calculate_anomaly_score(email, login_data)
    _update_profile(email, login_data)

    profile = BEHAVIOR_PROFILES.get(email, {})
    first_seen = profile.get("first_seen", datetime.utcnow())
    profile_age_days = (datetime.utcnow() - first_seen).days
    total_logins = profile.get("total_logins", 0)

    if anomaly["score"] >= 80:
        recommendation = "Block access and alert security team immediately"
    elif anomaly["score"] >= 60:
        recommendation = "Require step-up authentication and notify user"
    elif anomaly["score"] >= 40:
        recommendation = "Flag for review and monitor closely"
    else:
        recommendation = "No action required"

    log_event("ueba_analysis", "INFO", "ueba", {"email": email, "score": anomaly["score"], "is_anomalous": anomaly["is_anomalous"], "factors": anomaly["factors"], "ip": login_data.get("ip_address", "")})

    return {
        "email": email,
        "score": anomaly["score"],
        "is_anomalous": anomaly["is_anomalous"],
        "anomaly_factors": anomaly["factors"],
        "profile_age_days": profile_age_days,
        "total_logins": total_logins,
        "recommendation": recommendation,
    }


def get_user_profile(email):
    profile = BEHAVIOR_PROFILES.get(email)
    if not profile:
        return {
            "email": email,
            "first_seen": None,
            "last_login": None,
            "total_logins": 0,
            "failed_logins": 0,
            "success_rate": 0.0,
            "common_ips": [],
            "common_countries": [],
            "common_hours": [],
            "avg_session_duration": 0.0,
            "risk_level": "unknown",
        }

    total = profile.get("total_logins", 0)
    failed = profile.get("failed_logins", 0)
    success_rate = ((total - failed) / total) if total > 0 else 0.0

    common_ips_sorted = sorted(profile.get("common_ips", {}).items(), key=lambda x: x[1], reverse=True)
    common_countries_sorted = sorted(profile.get("common_countries", {}).items(), key=lambda x: x[1], reverse=True)
    common_hours_sorted = sorted(profile.get("common_hours", {}).items(), key=lambda x: x[1], reverse=True)

    events = profile.get("events", [])
    avg_duration = 0.0
    if len(events) >= 2:
        timestamps = [e.get("timestamp_obj", datetime.utcnow()) for e in events]
        timestamps.sort()
        total_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
        avg_duration = total_seconds / (len(timestamps) - 1) if len(timestamps) > 1 else 0.0

    if total < 5:
        risk_level = "unknown"
    elif failed / total > 0.5 if total > 0 else False:
        risk_level = "high"
    elif len(common_countries_sorted) > 3:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "email": email,
        "first_seen": profile.get("first_seen", datetime.utcnow()).isoformat(),
        "last_login": profile.get("last_login", datetime.utcnow()).isoformat(),
        "total_logins": total,
        "failed_logins": failed,
        "success_rate": round(success_rate, 4),
        "common_ips": [ip for ip, _ in common_ips_sorted[:5]],
        "common_countries": [c for c, _ in common_countries_sorted[:5]],
        "common_hours": [h for h, _ in common_hours_sorted[:5]],
        "avg_session_duration": round(avg_duration, 2),
        "risk_level": risk_level,
    }


def login_anomaly_detection(email, ip_address, user_agent, device_fingerprint):
    now = datetime.utcnow()
    login_event = {
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": now.isoformat(),
        "device_fingerprint": device_fingerprint,
        "success": True,
        "failure_reason": "",
    }
    LOGIN_HISTORY[email].append(login_event)
    LOGIN_HISTORY[email] = LOGIN_HISTORY[email][-100:]

    login_data = {
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": now.isoformat(),
        "device_fingerprint": device_fingerprint,
        "success": True,
        "failure_reason": "",
    }

    result = analyze_behavior(email, login_data)

    score = result["score"]
    if score >= 80:
        risk_level = "critical"
    elif score >= 60:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    requires_step_up = score > 60

    log_event("login_anomaly_detection", "INFO", "ueba", {"email": email, "ip": ip_address, "score": score, "risk_level": risk_level, "requires_step_up_auth": requires_step_up})

    return {
        "is_anomalous": result["is_anomalous"],
        "anomaly_score": score,
        "risk_level": risk_level,
        "factors": result["anomaly_factors"],
        "recommendation": result["recommendation"],
        "requires_step_up_auth": requires_step_up,
    }


def risk_scoring(email, context_data):
    failed_attempts = context_data.get("failed_attempts_last_hour", 0)
    ip_reputation = context_data.get("ip_reputation", 1.0)
    device_trust = context_data.get("device_trust", 1.0)
    geo_velocity = context_data.get("geo_velocity", 0.0)
    hours_since = context_data.get("hours_since_last_login", 0.0)
    is_known_device = context_data.get("is_known_device", True)
    is_known_location = context_data.get("is_known_location", True)

    failed_score = min(failed_attempts / 10.0, 1.0) * 100
    ip_score = (1.0 - ip_reputation) * 100
    device_score = (1.0 - device_trust) * 100
    geo_score = min(geo_velocity / 1000.0, 1.0) * 100
    recency_score = min(hours_since / 24.0, 1.0) * 100
    known_device_score = 0.0 if is_known_device else 100.0
    known_location_score = 0.0 if is_known_location else 100.0

    weighted_score = (
        failed_score * 0.25
        + ip_score * 0.20
        + device_score * 0.20
        + geo_score * 0.10
        + recency_score * 0.10
        + known_device_score * 0.075
        + known_location_score * 0.075
    )

    weighted_score = round(min(weighted_score, 100.0), 2)

    if weighted_score >= 80:
        risk_level = "critical"
    elif weighted_score >= 60:
        risk_level = "high"
    elif weighted_score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    auth_required = weighted_score > 60

    if weighted_score >= 80:
        recommendation = "Block access and trigger incident response"
    elif weighted_score >= 60:
        recommendation = "Require MFA and manual review"
    elif weighted_score >= 40:
        recommendation = "Step-up authentication recommended"
    else:
        recommendation = "Allow access with standard controls"

    breakdown = {
        "failed_attempts": round(failed_score, 2),
        "ip_reputation": round(ip_score, 2),
        "device_trust": round(device_score, 2),
        "geo_velocity": round(geo_score, 2),
        "recency": round(recency_score, 2),
        "known_device": round(known_device_score, 2),
        "known_location": round(known_location_score, 2),
    }

    log_event("risk_scoring", "INFO", "ueba", {"email": email, "score": weighted_score, "risk_level": risk_level, "auth_required": auth_required})

    return {
        "score": weighted_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "authentication_required": auth_required,
        "recommendation": recommendation,
    }
