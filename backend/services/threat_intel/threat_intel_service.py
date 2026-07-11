from datetime import datetime, timezone
import hashlib
import uuid

from services._shared.siem_logger import log_event

IOC_STORE = [
    {"id": 1, "type": "ip", "value": "185.220.101.0", "source": "AlienVault OTX", "confidence": "high", "severity": "critical", "tags": ["c2", "malspam"], "first_seen": "2026-01-15T10:30:00Z", "last_seen": "2026-06-20T14:22:00Z", "description": "Known C2 server for Emotet"},
    {"id": 2, "type": "domain", "value": "evil-malware.xyz", "source": "VirusTotal", "confidence": "high", "severity": "high", "tags": ["phishing", "malware"], "first_seen": "2026-03-10T08:15:00Z", "last_seen": "2026-06-19T22:10:00Z", "description": "Phishing domain targeting banking customers"},
    {"id": 3, "type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "source": "VirusTotal", "confidence": "medium", "severity": "medium", "tags": ["ransomware"], "first_seen": "2026-04-05T06:00:00Z", "last_seen": "2026-06-18T11:30:00Z", "description": "SHA-256 of known ransomware sample"},
    {"id": 4, "type": "url", "value": "https://phishing-bank.com/login", "source": "GSB", "confidence": "high", "severity": "critical", "tags": ["phishing", "social_engineering"], "first_seen": "2026-05-20T12:00:00Z", "last_seen": "2026-06-20T09:00:00Z", "description": "Phishing page mimicking major bank"},
    {"id": 5, "type": "email", "value": "attacker@evil.com", "source": "Community", "confidence": "medium", "severity": "medium", "tags": ["phishing", "spam"], "first_seen": "2026-02-14T16:45:00Z", "last_seen": "2026-06-17T20:30:00Z", "description": "Known phishing sender"},
]

_IN_MEMORY_ALERTS = []


def fetch_ioc_feeds():
    now = datetime.now(timezone.utc).isoformat()
    source_summary = {}
    type_summary = {}

    for ioc in IOC_STORE:
        src = ioc["source"]
        source_summary[src] = source_summary.get(src, 0) + 1
        typ = ioc["type"]
        type_summary[typ] = type_summary.get(typ, 0) + 1

    log_event("ioc_feeds_fetched", "INFO", "threat_intel", {"total": len(IOC_STORE)})

    return {
        "total": len(IOC_STORE),
        "iocs": IOC_STORE,
        "source_summary": source_summary,
        "type_summary": type_summary,
        "last_updated": now,
    }


def ioc_lookup(ioc_type, ioc_value):
    matches = [
        ioc for ioc in IOC_STORE
        if ioc["type"] == ioc_type and ioc_value.lower() in ioc["value"].lower()
    ]

    log_event("ioc_lookup", "INFO", "threat_intel", {"type": ioc_type, "value": ioc_value, "total_found": len(matches)})

    return {
        "matches": matches,
        "total_found": len(matches),
    }


def list_alerts():
    default_alerts = [
        {
            "id": 1,
            "type": "c2_communication",
            "title": "Outbound C2 Communication Detected",
            "severity": "critical",
            "source": "Network IDS",
            "timestamp": "2026-06-20T14:22:00Z",
            "status": "open",
            "description": "Host 10.0.1.55 initiated outbound connection to known C2 server 185.220.101.0",
            "recommended_action": "Isolate the host immediately and block the IP at the firewall",
        },
        {
            "id": 2,
            "type": "phishing",
            "title": "Phishing Email Detected",
            "severity": "high",
            "source": "Email Gateway",
            "timestamp": "2026-06-19T22:10:00Z",
            "status": "open",
            "description": "Phishing email from attacker@evil.com targeting finance department",
            "recommended_action": "Block sender domain and notify affected users",
        },
        {
            "id": 3,
            "type": "malware",
            "title": "Ransomware Hash Match",
            "severity": "medium",
            "source": "Endpoint Protection",
            "timestamp": "2026-06-18T11:30:00Z",
            "status": "investigating",
            "description": "File hash match with known ransomware sample detected on endpoint",
            "recommended_action": "Quarantine the file and scan the host for lateral movement",
        },
        {
            "id": 4,
            "type": "phishing",
            "title": "Phishing URL Accessed",
            "severity": "critical",
            "source": "Web Proxy",
            "timestamp": "2026-06-20T09:00:00Z",
            "status": "open",
            "description": "User navigated to known phishing site https://phishing-bank.com/login",
            "recommended_action": "Block URL, reset user credentials, and enforce MFA re-enrollment",
        },
    ]

    all_alerts = default_alerts + _IN_MEMORY_ALERTS

    log_event("alerts_listed", "INFO", "threat_intel", {"total": len(all_alerts)})

    return all_alerts


def generate_alert(alert_type, title, severity, description, source):
    now = datetime.now(timezone.utc).isoformat()
    alert = {
        "id": len(_IN_MEMORY_ALERTS) + 100,
        "type": alert_type,
        "title": title,
        "severity": severity,
        "source": source,
        "timestamp": now,
        "status": "open",
        "description": description,
        "recommended_action": _recommendation_for_severity(severity),
    }

    _IN_MEMORY_ALERTS.append(alert)

    log_event("alert_generated", "INFO", "threat_intel", {"alert_id": alert["id"], "type": alert_type, "severity": severity})

    return alert


def _recommendation_for_severity(severity):
    recommendations = {
        "critical": "Immediate response required: isolate affected systems and escalate to incident response team",
        "high": "Prompt investigation recommended: review logs and contain potential threat",
        "medium": "Scheduled investigation: monitor and gather additional intelligence",
        "low": "Monitor for changes: add to watchlist for further observation",
    }
    return recommendations.get(severity, "Review and assess the alert")


def scan_hash(file_hash):
    known_bad = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "verdict": "malicious",
            "threat_type": "ransomware",
            "malware_name": "GenericRansomware",
            "severity": "high",
            "recommendation": "Immediately isolate the host, quarantine the file, and initiate incident response procedure",
        },
    }

    log_event("hash_scan", "INFO", "threat_intel", {"hash": file_hash})

    if file_hash in known_bad:
        matched = known_bad[file_hash]
        ioc_match = next((ioc for ioc in IOC_STORE if ioc["type"] == "hash" and ioc["value"] == file_hash), None)
        return {
            "verdict": matched["verdict"],
            "matched_ioc": ioc_match,
            "threat_type": matched["threat_type"],
            "malware_name": matched["malware_name"],
            "severity": matched["severity"],
            "recommendation": matched["recommendation"],
        }

    return {
        "verdict": "clean",
        "matched_ioc": None,
        "threat_type": None,
        "malware_name": None,
        "severity": None,
        "recommendation": "No known threat association found. File appears safe.",
    }


def dns_sinkhole(domain, action):
    log_event("dns_sinkhole", "INFO", "threat_intel", {"domain": domain, "action": action})

    return {
        "success": True,
        "domain": domain,
        "action": action,
        "message": f"Domain '{domain}' has been {action}ed via DNS sinkhole",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def trigger_soar(playbook, target, params=None):
    playbook_id = f"SOAR-{uuid.uuid4().hex[:8].upper()}"
    steps = [
        {"step": 1, "name": "Enrichment", "status": "completed", "result": f"Enriched data for target {target}"},
        {"step": 2, "name": "Analysis", "status": "completed", "result": "Threat analysis completed, indicators correlated"},
        {"step": 3, "name": "Containment", "status": "completed", "result": f"Containment actions executed against {target}"},
        {"step": 4, "name": "Notification", "status": "completed", "result": "SOC team notified of playbook execution"},
    ]

    log_event("soar_playbook_triggered", "INFO", "threat_intel", {
        "playbook": playbook,
        "playbook_id": playbook_id,
        "target": target,
        "status": "completed",
    })

    return {
        "playbook_id": playbook_id,
        "playbook": playbook,
        "target": target,
        "status": "completed",
        "steps": steps,
        "params": params or {},
    }
