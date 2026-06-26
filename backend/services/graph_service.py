import json, os, re
from datetime import datetime
from flask import jsonify, request

import requests

MS_GRAPH_TOKENS = {}
MS_GRAPH_MOCK_USERS = [
    {"id": "user001", "displayName": "Admin User", "userPrincipalName": "admin@cybershield.com", "mail": "admin@cybershield.com", "riskLevel": "none", "signInActivity": {"lastSignInDateTime": "2026-06-23T06:30:00Z"}, "jobTitle": "SOC Administrator"},
    {"id": "user002", "displayName": "John Analyst", "userPrincipalName": "john@cybershield.com", "mail": "john@cybershield.com", "riskLevel": "medium", "signInActivity": {"lastSignInDateTime": "2026-06-23T04:15:00Z"}, "jobTitle": "Security Analyst"},
    {"id": "user003", "displayName": "Sarah Engineer", "userPrincipalName": "sarah@cybershield.com", "mail": "sarah@cybershield.com", "riskLevel": "low", "signInActivity": {"lastSignInDateTime": "2026-06-22T22:00:00Z"}, "jobTitle": "DevOps Engineer"},
    {"id": "user004", "displayName": "Mike Threat Actor", "userPrincipalName": "mike@suspicious-tenant.com", "mail": "mike@suspicious-tenant.com", "riskLevel": "high", "signInActivity": {"lastSignInDateTime": "2026-06-23T07:45:00Z"}, "jobTitle": "External Contractor"}
]
MS_GRAPH_MOCK_MESSAGES = [
    {"id": "mail001", "from": {"emailAddress": {"address": "external@phishing.com"}}, "subject": "Invoice Payment Required", "receivedDateTime": "2026-06-23T08:00:00Z", "isRead": False, "importance": "high", "threat_score": 82},
    {"id": "mail002", "from": {"emailAddress": {"address": "reports@partner.com"}}, "subject": "Monthly Security Report", "receivedDateTime": "2026-06-23T07:30:00Z", "isRead": True, "importance": "normal", "threat_score": 5}
]

def _get_graph_token():
    tenant_id = os.getenv("GRAPH_TENANT_ID", "")
    client_id = os.getenv("GRAPH_CLIENT_ID", "")
    client_secret = os.getenv("GRAPH_CLIENT_SECRET", "")
    if not all([tenant_id, client_id, client_secret]):
        return None
    try:
        r = requests.post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token", data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default"}, timeout=10)
        if r.status_code == 200:
            return r.json().get("access_token")
    except Exception:
        pass
    return None

def _graph_headers():
    token = _get_graph_token()
    if token:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return None

def graph_connect(current_user=None):
    data = request.get_json() or {}
    access_token = data.get("access_token", os.getenv("GRAPH_ACCESS_TOKEN", ""))
    tenant_id = data.get("tenant_id", os.getenv("GRAPH_TENANT_ID", "cybershield-soc.onmicrosoft.com"))
    client_id = data.get("client_id", os.getenv("GRAPH_CLIENT_ID", ""))
    client_secret = data.get("client_secret", os.getenv("GRAPH_CLIENT_SECRET", ""))
    if client_id and client_secret and tenant_id:
        env_set = {"GRAPH_TENANT_ID": tenant_id, "GRAPH_CLIENT_ID": client_id, "GRAPH_CLIENT_SECRET": client_secret}
        for k, v in env_set.items():
            os.environ[k] = v
    token = _get_graph_token()
    real_api = token is not None
    if real_api:
        try:
            r = requests.get("https://graph.microsoft.com/v1.0/organization", headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if r.status_code == 200:
                org = r.json().get("value", [{}])[0]
                tenant_name = org.get("displayName", tenant_id)
                MS_GRAPH_TOKENS["default"] = {"token": token, "tenant": tenant_id, "connected": datetime.utcnow().isoformat()}
                return jsonify({"success": True, "tenant": tenant_name, "connection_status": "CONNECTED", "api_version": "v1.0", "real_api": True, "scope": ["User.Read", "Mail.Read", "AuditLog.Read.All", "IdentityRiskEvent.Read.All"], "verdict": "GRAPH_CONNECTED", "recommendation": "Use Graph API for identity protection and mail flow monitoring"})
        except Exception as e:
            pass
    MS_GRAPH_TOKENS["default"] = {"token": token or "mock_graph_token_xyz", "tenant": tenant_id, "connected": datetime.utcnow().isoformat()}
    return jsonify({"success": True, "tenant": tenant_id, "connection_status": "CONNECTED", "api_version": "v1.0", "real_api": False, "scope": ["User.Read", "Mail.Read", "AuditLog.Read.All", "IdentityRiskEvent.Read.All"], "verdict": "GRAPH_CONNECTED", "recommendation": "Use Graph API for identity protection and mail flow monitoring"})

def graph_list_users(current_user=None):
    data = request.get_json() or {}
    filter_param = data.get("filter", "")
    risk_level = data.get("risk_level", "")
    headers = _graph_headers()
    if headers:
        try:
            url = "https://graph.microsoft.com/v1.0/users"
            if risk_level:
                url += f"?$filter=riskLevel eq '{risk_level}'"
            elif filter_param:
                url += f"?$filter=startswith(displayName,'{filter_param}')"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                users = r.json().get("value", [])
                return jsonify({"success": True, "users": users, "total_users": len(users), "high_risk_users": len([u for u in users if u.get("riskLevel") == "high"]), "source": "graph_api", "verdict": "USERS_LISTED"})
        except Exception:
            pass
    results = MS_GRAPH_MOCK_USERS
    if risk_level:
        results = [u for u in results if u.get("riskLevel") == risk_level]
    elif filter_param:
        results = [u for u in results if filter_param.lower() in u.get("displayName", "").lower()]
    return jsonify({"success": True, "users": results, "total_users": len(results), "high_risk_users": len([u for u in MS_GRAPH_MOCK_USERS if u.get("riskLevel") == "high"]), "source": "mock", "verdict": "USERS_LISTED"})

def graph_scan_mail(current_user=None):
    data = request.get_json() or {}
    max_results = data.get("max_results", 10)
    headers = _graph_headers()
    if headers:
        try:
            r = requests.get(f"https://graph.microsoft.com/v1.0/me/messages?$top={max_results}&$select=id,from,subject,receivedDateTime,isRead,importance,bodyPreview&$orderby=receivedDateTime desc", headers=headers, timeout=10)
            if r.status_code == 200:
                messages = r.json().get("value", [])
                threats = []
                for msg in messages:
                    subject = msg.get("subject", "")
                    preview = msg.get("bodyPreview", "")
                    threat_score = 85 if re.search(r"urgent|verify|password|account.*suspend|click here|invoice|payment", subject + preview, re.I) else 0
                    if threat_score >= 50:
                        threats.append({"id": msg.get("id"), "from": msg.get("from", {}).get("emailAddress", {}).get("address", ""), "subject": subject, "threat_score": threat_score})
                return jsonify({"success": True, "total_scanned": len(messages), "threats_found": len(threats), "threats": threats, "source": "graph_api", "verdict": "MAIL_SCAN_COMPLETE", "recommendation": f"{len(threats)} threats found via Graph API"})
        except Exception:
            pass
    threats = [m for m in MS_GRAPH_MOCK_MESSAGES if m.get("threat_score", 0) >= 50]
    return jsonify({"success": True, "total_scanned": min(max_results, len(MS_GRAPH_MOCK_MESSAGES)), "threats_found": len(threats), "threats": threats, "source": "mock", "verdict": "MAIL_SCAN_COMPLETE"})

def graph_audit_logs(current_user=None):
    data = request.get_json() or {}
    days = data.get("days", 7)
    headers = _graph_headers()
    if headers:
        try:
            r = requests.get(f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=50&$filter=createdDateTime ge {datetime.utcnow().isoformat()}", headers=headers, timeout=10)
            if r.status_code == 200:
                events = r.json().get("value", [])
                return jsonify({"success": True, "events": events, "total_events": len(events), "critical_events": len([e for e in events if e.get("riskLevelDuringSignIn") == "high"]), "timeframe_days": days, "source": "graph_api", "verdict": "AUDIT_LOGS_RETURNED"})
        except Exception:
            pass
    events = [
        {"id": "audit001", "activity": "User login", "user": "admin@cybershield.com", "ip": "203.0.113.42", "timestamp": "2026-06-23T06:30:00Z", "status": "success", "risk": "low"},
        {"id": "audit002", "activity": "Failed login attempt", "user": "john@cybershield.com", "ip": "45.33.32.156", "timestamp": "2026-06-23T04:00:00Z", "status": "failure", "risk": "high"},
        {"id": "audit003", "activity": "MFA enrollment change", "user": "sarah@cybershield.com", "ip": "10.0.0.42", "timestamp": "2026-06-22T15:00:00Z", "status": "success", "risk": "medium"},
        {"id": "audit004", "activity": "Mailbox permission change", "user": "mike@suspicious-tenant.com", "ip": "185.220.101.1", "timestamp": "2026-06-23T07:45:00Z", "status": "success", "risk": "critical"},
        {"id": "audit005", "activity": "Admin role assignment", "user": "admin@cybershield.com", "ip": "192.168.1.100", "timestamp": "2026-06-21T10:00:00Z", "status": "success", "risk": "medium"}
    ]
    return jsonify({"success": True, "events": events, "total_events": len(events), "critical_events": len([e for e in events if e.get("risk") == "critical"]), "timeframe_days": days, "source": "mock", "verdict": "AUDIT_LOGS_RETURNED"})

def graph_disconnect(current_user=None):
    MS_GRAPH_TOKENS.clear()
    for k in ["GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET"]:
        os.environ.pop(k, None)
    return jsonify({"success": True, "action": "DISCONNECTED", "verdict": "GRAPH_DISCONNECTED"})
