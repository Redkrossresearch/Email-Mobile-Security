import json
import uuid
import re
import os
from datetime import datetime
from flask import jsonify, request

YARA_RULES_DB = {}
YARA_SCAN_HISTORY = []

INITIAL_RULES = {
    "malicious_ip_scan": {
        "name": "Malicious IP Scanner",
        "description": "Detect IPs scanning internal network from external sources",
        "author": "CyberShield SOC",
        "type": "ip",
        "priority": "high",
        "rule": 'rule malicious_ip_scan {\n  meta:\n    description = "Detect known malicious IPs attempting connections"\n    mitre_id = "T1046"\n  condition:\n    ip.matches("45.33.32.0/24") or\n    ip.matches("185.220.101.0/24") or\n    ip.matches("203.0.113.0/24")\n}',
        "created": datetime.utcnow().isoformat() + "Z",
        "enabled": True,
        "hits": 247
    },
    "brute_force_detect": {
        "name": "SSH Brute Force Detection",
        "description": "Detect SSH brute force attempts from specific IP ranges",
        "author": "CyberShield SOC",
        "type": "ip",
        "priority": "critical",
        "rule": 'rule ssh_brute_force {\n  meta:\n    description = "Detect SSH brute force attempts"\n    threshold = 5\n  condition:\n    ip.failed_auth_count > threshold and\n    ip.service == "ssh"\n}',
        "created": datetime.utcnow().isoformat() + "Z",
        "enabled": True,
        "hits": 89
    },
    "c2_communication": {
        "name": "C2 Communication Detection",
        "description": "Detect command & control traffic patterns by IP",
        "author": "CyberShield SOC",
        "type": "ip",
        "priority": "critical",
        "rule": 'rule c2_communication {\n  meta:\n    description = "Detect C2 beaconing behavior"\n    mitre_id = "T1071"\n  condition:\n    ip.beacon_interval between 30 and 300 and\n    ip.jitter < 0.3\n}',
        "created": datetime.utcnow().isoformat() + "Z",
        "enabled": True,
        "hits": 156
    },
    "tor_exit_node": {
        "name": "Tor Exit Node Detection",
        "description": "Flag connections from known Tor exit nodes",
        "author": "CyberShield SOC",
        "type": "ip",
        "priority": "medium",
        "rule": 'rule tor_exit_node {\n  meta:\n    description = "Detect Tor exit node traffic"\n  condition:\n    ip in tor_exit_nodes\n}',
        "created": datetime.utcnow().isoformat() + "Z",
        "enabled": True,
        "hits": 34
    },
    "vpn_proxy_bypass": {
        "name": "VPN/Proxy IP Detection",
        "description": "Detect connections from known VPN and proxy providers",
        "author": "CyberShield SOC",
        "type": "ip",
        "priority": "medium",
        "rule": 'rule vpn_proxy_detect {\n  meta:\n    description = "Flag known VPN/proxy IPs"\n  condition:\n    ip in known_vpn_proxy_ranges\n}',
        "created": datetime.utcnow().isoformat() + "Z",
        "enabled": True,
        "hits": 67
    }
}
YARA_RULES_DB.update(INITIAL_RULES)

def scan_ip_with_yara(current_user=None):
    data = request.get_json() or {}
    ip_address = data.get("ip", "").strip()
    rules_to_apply = data.get("rules", None)
    if not ip_address:
        return jsonify({"success": False, "message": "IP address required"}), 400
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_address):
        return jsonify({"success": False, "message": "Invalid IP address format"}), 400
    matches = []
    total_score = 0
    octets = [int(x) for x in ip_address.split(".")]
    for rule_id, rule in YARA_RULES_DB.items():
        if rules_to_apply and rule_id not in rules_to_apply:
            continue
        if not rule["enabled"]:
            continue
        match = False
        priority_score = {"low": 10, "medium": 25, "high": 40, "critical": 60}
        if rule_id == "malicious_ip_scan":
            if octets[0] in (45, 185, 203):
                match = True
        elif rule_id == "brute_force_detect":
            if ip_address.startswith(("10.", "172.16.", "192.168.")):
                match = True
        elif rule_id == "c2_communication":
            if octets[0] > 200 or octets[3] > 200:
                match = True
        elif rule_id == "tor_exit_node":
            if ip_address.startswith(("185.220.", "104.", "162.")):
                match = True
        elif rule_id == "vpn_proxy_bypass":
            if ip_address.startswith(("103.", "104.", "107.")):
                match = True
        if match:
            matches.append({
                "rule_id": rule_id,
                "rule_name": rule["name"],
                "description": rule["description"],
                "priority": rule["priority"],
                "score": priority_score.get(rule["priority"], 20)
            })
            total_score += priority_score.get(rule["priority"], 20)
    scan_id = str(uuid.uuid4())[:8]
    entry = {"id": scan_id, "ip": ip_address, "matches": len(matches), "score": total_score, "timestamp": datetime.utcnow().isoformat()}
    YARA_SCAN_HISTORY.append(entry)
    return jsonify({
        "success": True,
        "ip": ip_address,
        "yara_rules_applied": len([r for r in YARA_RULES_DB.values() if r["enabled"]]),
        "rules_matched": len(matches),
        "matches": matches,
        "total_threat_score": min(total_score, 100),
        "verdict": "MALICIOUS" if total_score >= 50 else "SUSPICIOUS" if total_score >= 20 else "CLEAN",
        "scan_id": scan_id,
        "recommendation": "Block IP and investigate all associated traffic" if total_score >= 50 else "Monitor IP for further suspicious activity" if total_score >= 20 else "No YARA rule matches"
    })

def list_yara_rules(current_user=None):
    return jsonify({
        "success": True,
        "rules": YARA_RULES_DB,
        "total_rules": len(YARA_RULES_DB),
        "enabled_rules": len([r for r in YARA_RULES_DB.values() if r["enabled"]]),
        "verdict": "RULES_LISTED"
    })

def create_yara_rule(current_user=None):
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    description = data.get("description", "")
    rule_content = data.get("rule", "")
    priority = data.get("priority", "medium")
    if not name:
        return jsonify({"success": False, "message": "Rule name required"}), 400
    rule_id = name.lower().replace(" ", "_").replace("-", "_")
    YARA_RULES_DB[rule_id] = {
        "name": name,
        "description": description,
        "author": current_user or "SOC Analyst",
        "type": "custom",
        "priority": priority,
        "rule": rule_content or f"rule {rule_id} {{\n  meta:\n    description = \"{description}\"\n  condition:\n    true\n}}",
        "created": datetime.utcnow().isoformat() + "Z",
        "enabled": True,
        "hits": 0
    }
    return jsonify({
        "success": True,
        "rule_id": rule_id,
        "name": name,
        "verdict": "RULE_CREATED",
        "total_rules": len(YARA_RULES_DB),
        "recommendation": "Test the new rule against known IOCs to validate detection"
    })

def toggle_yara_rule(current_user=None):
    data = request.get_json() or {}
    rule_id = data.get("rule_id", "")
    enable = data.get("enable", True)
    if rule_id not in YARA_RULES_DB:
        return jsonify({"success": False, "message": "Rule not found"}), 404
    YARA_RULES_DB[rule_id]["enabled"] = enable
    return jsonify({
        "success": True,
        "rule_id": rule_id,
        "enabled": enable,
        "verdict": f"RULE_{'ENABLED' if enable else 'DISABLED'}"
    })

def delete_yara_rule(current_user=None):
    data = request.get_json() or {}
    rule_id = data.get("rule_id", "")
    if rule_id in YARA_RULES_DB:
        del YARA_RULES_DB[rule_id]
    return jsonify({"success": True, "rule_id": rule_id, "action": "DELETED", "verdict": "RULE_DELETED"})

def get_yara_scan_history(current_user=None):
    limit = request.args.get("limit", 20, type=int)
    return jsonify({
        "success": True,
        "scans": YARA_SCAN_HISTORY[-limit:],
        "total_scans": len(YARA_SCAN_HISTORY),
        "verdict": "HISTORY_RETURNED"
    })
