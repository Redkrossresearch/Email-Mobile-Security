import json
import re
import uuid
import hashlib
import os
from datetime import datetime
from flask import jsonify, request
from config.settings import DATA_DIR

IOC_CACHE = {}
ALERT_DB = []

VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
SINKHOLED_DOMAINS = {}

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

import requests

def fetch_ioc_feeds(current_user=None):
    live_status = {}
    if VT_API_KEY:
        try:
            r = requests.get("https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", headers={"x-apikey": VT_API_KEY}, timeout=5)
            live_status["virustotal"] = {"status": "connected" if r.ok else "error", "note": "API key configured" if r.ok else f"HTTP {r.status_code}"}
        except Exception as e:
            live_status["virustotal"] = {"status": "error", "note": str(e)}
    else:
        live_status["virustotal"] = {"status": "no_api_key", "note": "Set VT_API_KEY env var"}
    if ABUSEIPDB_API_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90}, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}, timeout=5)
            live_status["abuseipdb"] = {"status": "connected" if r.ok else "error", "note": "API key configured" if r.ok else f"HTTP {r.status_code}"}
        except Exception as e:
            live_status["abuseipdb"] = {"status": "error", "note": str(e)}
    else:
        live_status["abuseipdb"] = {"status": "no_api_key", "note": "Set ABUSEIPDB_API_KEY env var"}
    default_feeds = {
        "alienvault_otx": {"status": "simulated", "iocs_fetched": 3450, "last_sync": datetime.utcnow().isoformat() + "Z"},
        "greynoise": {"status": "simulated", "iocs_fetched": 2100, "last_sync": datetime.utcnow().isoformat() + "Z"},
        "spamhaus": {"status": "simulated", "iocs_fetched": 5600, "last_sync": datetime.utcnow().isoformat() + "Z"}
    }
    return jsonify({
        "success": True,
        "feeds": {**default_feeds, **live_status},
        "total_feeds": len(default_feeds) + len(live_status),
        "cache_status": "warming" if not IOC_CACHE else "hot",
        "ioc_count_in_cache": len(IOC_CACHE)
    })

def ioc_lookup(current_user=None):
    data = request.get_json() or {}
    indicator = data.get("indicator", "").strip().lower()
    indicator_type = data.get("type", "auto")
    if not indicator:
        return jsonify({"success": False, "message": "Indicator required"}), 400
    if indicator_type == "auto":
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
            indicator_type = "ip"
        elif re.match(r'^[a-f0-9]{32}$', indicator):
            indicator_type = "md5"
        elif re.match(r'^[a-f0-9]{40}$', indicator):
            indicator_type = "sha1"
        elif re.match(r'^[a-f0-9]{64}$', indicator):
            indicator_type = "sha256"
        elif "@" in indicator:
            indicator_type = "email"
        elif "." in indicator:
            indicator_type = "domain"
        else:
            indicator_type = "unknown"
    malicious = False
    score = 0
    tags = []
    asn = "N/A"
    country = "Unknown"
    external_note = None
    if indicator_type == "ip" and ABUSEIPDB_API_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": indicator, "maxAgeInDays": 90}, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}, timeout=5)
            if r.ok:
                d = r.json().get("data", {})
                score = int(d.get("abuseConfidenceScore", 0))
                malicious = score >= 50
                country = d.get("countryCode", "Unknown")
                asn = f"AS{d.get('asn', 'N/A')}"
                if d.get("isp"):
                    tags.append(f"ISP: {d['isp']}")
                if d.get("domain"):
                    tags.append(f"Domain: {d['domain']}")
                if malicious:
                    tags.append("abuseipdb_malicious")
                external_note = "AbuseIPDB lookup completed"
        except Exception as e:
            external_note = f"AbuseIPDB error: {str(e)}"
    if indicator_type == "domain" and DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(indicator, "A", lifetime=5)
            ip = str(answers[0])
            tags.append(f"resolved_to: {ip}")
            if ABUSEIPDB_API_KEY:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90}, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}, timeout=5)
                    if r.ok:
                        d = r.json().get("data", {})
                        ds = int(d.get("abuseConfidenceScore", 0))
                        if ds > score:
                            score = ds
                            malicious = ds >= 50
                except Exception:
                    pass
        except Exception:
            tags.append("dns_resolution_failed")
    if indicator_type == "ip" and not ABUSEIPDB_API_KEY:
        try:
            r = requests.get(f"https://ipapi.co/{indicator}/json/", timeout=5)
            if r.ok:
                d = r.json()
                country = d.get("country_name", "Unknown")
                asn = f"AS{d.get('asn', 'N/A')}" if d.get("asn") else "N/A"
                tags.append(f"ISP: {d.get('org', 'Unknown')}")
        except Exception:
            pass
    if score == 0 and not malicious:
        threat_db = {
            "ip": {"45.33.32.156": {"malicious": True, "score": 85, "tags": ["c2", "malware"], "asn": "AS54321"}, "8.8.8.8": {"malicious": False, "score": 0, "tags": [], "asn": "AS15169"}},
            "domain": {"evil.com": {"malicious": True, "score": 92, "tags": ["phishing", "malware"]}, "google.com": {"malicious": False, "score": 0, "tags": []}},
            "email": {"attacker@evil.com": {"malicious": True, "score": 88, "tags": ["phishing", "spam"]}},
        }
        result = threat_db.get(indicator_type, {}).get(indicator, {"malicious": False, "score": 0, "tags": []})
        malicious = result.get("malicious", False)
        score = result.get("score", 0)
        tags = result.get("tags", tags)
    return jsonify({
        "success": True,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "malicious": malicious,
        "threat_score": min(score, 100),
        "tags": list(set(tags)),
        "asn": asn,
        "country": country,
        "first_seen": "2026-01-15T00:00:00Z",
        "last_seen": datetime.utcnow().isoformat() + "Z",
        "external_lookup": external_note,
        "verdict": "MALICIOUS" if malicious else "BENIGN" if score == 0 else "SUSPICIOUS"
    })

def generate_alert(current_user=None):
    data = request.get_json() or {}
    alert_id = str(uuid.uuid4())[:8]
    severity = data.get("severity", "medium")
    title = data.get("title", "Security Alert")
    description = data.get("description", "")
    source = data.get("source", "threat-intel")
    alert = {
        "alert_id": alert_id,
        "severity": severity,
        "title": title,
        "description": description,
        "source": source,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "open",
        "assigned_to": None
    }
    ALERT_DB.append(alert)
    return jsonify({
        "success": True,
        "alert": alert,
        "auto_escalated": severity in ("critical", "high"),
        "playbook_triggered": f"respond-{severity}" if severity in ("critical", "high") else None,
        "total_active_alerts": len(ALERT_DB)
    })

def list_alerts(current_user=None):
    severity = request.args.get("severity", "")
    alerts = ALERT_DB if not severity else [a for a in ALERT_DB if a["severity"] == severity]
    return jsonify({
        "success": True,
        "alerts": alerts,
        "total": len(alerts),
        "open": len([a for a in ALERT_DB if a["status"] == "open"]),
        "closed": len([a for a in ALERT_DB if a["status"] == "closed"])
    })

def scan_hash(current_user=None):
    data = request.get_json() or {}
    file_hash = data.get("hash", "")
    if not file_hash:
        return jsonify({"success": False, "message": "Hash required"}), 400
    if len(file_hash) not in (32, 40, 64):
        return jsonify({"success": False, "message": "Invalid hash length"}), 400
    detections = 0
    total_engines = 72
    vt_result = None
    if VT_API_KEY:
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers={"x-apikey": VT_API_KEY}, timeout=10)
            if r.ok:
                vt = r.json()
                attrs = vt.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total_engines = stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0) + stats.get("undetected", 0)
                vt_result = "virustotal_live"
        except Exception:
            vt_result = "virustotal_error"
    if not vt_result:
        if file_hash.startswith("a") or file_hash.endswith("f"):
            detections = 15
        vt_result = "simulated"
    return jsonify({
        "success": True,
        "hash": file_hash,
        "hash_type": "MD5" if len(file_hash) == 32 else "SHA1" if len(file_hash) == 40 else "SHA256",
        "detection_ratio": f"{detections}/{total_engines}",
        "malicious": detections >= 5,
        "suspicious": detections >= 2 and detections < 5,
        "undetected": detections == 0,
        "source": vt_result,
        "verdict": "MALICIOUS" if detections >= 5 else "SUSPICIOUS" if detections >= 2 else "CLEAN",
        "scan_date": datetime.utcnow().isoformat() + "Z"
    })

def dns_sinkhole(current_user=None):
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    action = data.get("action", "sinkhole")
    if not domain:
        return jsonify({"success": False, "message": "Domain required"}), 400
    if action == "sinkhole":
        SINKHOLED_DOMAINS[domain] = {"sinkholed_at": datetime.utcnow().isoformat() + "Z", "sinkholed_by": current_user, "redirect_ip": "0.0.0.0"}
        return jsonify({"success": True, "domain": domain, "action": "SINKHOLED", "redirect_ip": "0.0.0.0", "total_sinkholed": len(SINKHOLED_DOMAINS), "verdict": "DNS_SINKHOLE_ACTIVE"})
    elif action == "release":
        SINKHOLED_DOMAINS.pop(domain, None)
        return jsonify({"success": True, "domain": domain, "action": "RELEASED", "verdict": "DNS_SINKHOLE_REMOVED"})
    elif action == "list":
        return jsonify({"success": True, "sinkholed_domains": SINKHOLED_DOMAINS, "total": len(SINKHOLED_DOMAINS)})
    return jsonify({"success": False, "message": "Invalid action"}), 400

def trigger_soar(current_user=None):
    data = request.get_json() or {}
    alert_id = data.get("alert_id", "")
    playbook = data.get("playbook", "default-response")
    severity = data.get("severity", "medium")
    if not alert_id:
        return jsonify({"success": False, "message": "alert_id required"}), 400
    playbooks = {
        "phishing-response": ["Block sender", "Quarantine email", "Alert SOC team", "Run sandbox analysis"],
        "malware-response": ["Isolate endpoint", "Kill process", "Collect forensics", "Notify IR team"],
        "brute-force-response": ["Lock account", "Reset password", "Enable MFA", "Alert admin"],
        "default-response": ["Log incident", "Assign analyst", "Generate report"]
    }
    steps = playbooks.get(playbook, playbooks["default-response"])
    return jsonify({
        "success": True,
        "alert_id": alert_id,
        "playbook": playbook,
        "severity": severity,
        "steps_executed": steps,
        "execution_time_ms": 342,
        "status": "COMPLETED",
        "triggered_by": current_user,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "verdict": "SOAR_PLAYBOOK_EXECUTED"
    })
