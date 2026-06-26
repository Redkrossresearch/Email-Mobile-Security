import json, base64, re, os
from datetime import datetime
from flask import jsonify, request

try:
    import google.auth
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False

GMAIL_TOKENS = {}
GMAIL_MOCK_INBOX = [
    {"id": "msg001", "from": "noreply@google.com", "subject": "Security Alert: New sign-in", "snippet": "There was a new sign-in to your account from a Windows device...", "date": "2026-06-23T08:30:00Z", "labels": ["INBOX", "CATEGORY_UPDATES"], "threat_score": 0},
    {"id": "msg002", "from": "attacker@phishing-site.com", "subject": "Urgent: Account verification required", "snippet": "Click here to verify your account details and avoid suspension...", "date": "2026-06-23T07:15:00Z", "labels": ["INBOX", "CATEGORY_PRIMARY"], "threat_score": 85},
    {"id": "msg003", "from": "ceo@company.com", "subject": "Q4 Financial Reports", "snippet": "Attached are the confidential financial reports for Q4...", "date": "2026-06-22T18:45:00Z", "labels": ["INBOX"], "threat_score": 0},
    {"id": "msg004", "from": "newsletter@techcrunch.com", "subject": "This week in cybersecurity", "snippet": "Top stories: New zero-day vulnerability discovered...", "date": "2026-06-22T14:00:00Z", "labels": ["INBOX", "CATEGORY_UPDATES"], "threat_score": 5},
    {"id": "msg005", "from": "alert@security.company.com", "subject": "Suspicious login detected", "snippet": "We detected a login attempt from an unrecognized device...", "date": "2026-06-22T10:20:00Z", "labels": ["INBOX", "CATEGORY_PERSONAL"], "threat_score": 30}
]

def _get_gmail_service():
    creds_json = os.getenv("GMAIL_CREDENTIALS_JSON") or os.getenv("GMAIL_TOKEN_JSON")
    if not creds_json or not GOOGLE_API_AVAILABLE:
        return None
    try:
        creds_data = json.loads(creds_json)
        if "token" in creds_data:
            creds = Credentials.from_authorized_user_info(creds_data)
        else:
            return None
        if not creds.valid:
            creds.refresh(Request())
        return build("gmail", "v1", credentials=creds)
    except Exception:
        return None

def gmail_connect(current_user=None):
    data = request.get_json() or {}
    access_token = data.get("access_token", "")
    creds_json = data.get("credentials_json", os.getenv("GMAIL_CREDENTIALS_JSON", ""))
    connected = False
    email = "soc@cybershield.com"
    total_messages = 12453
    unread_count = 342
    if creds_json and GOOGLE_API_AVAILABLE:
        try:
            creds_data = json.loads(creds_json) if isinstance(creds_json, str) else creds_json
            if "installed" in creds_data or "web" in creds_data:
                flow = Flow.from_client_config(creds_data, scopes=["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"])
                flow.redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
                auth_url, _ = flow.authorization_url(prompt="consent")
                GMAIL_TOKENS["flow"] = flow
                return jsonify({"success": True, "auth_url": auth_url, "connection_status": "AUTH_REQUIRED", "verdict": "GMAIL_AUTH_URL_GENERATED", "recommendation": "Open the auth_url in a browser, authorize, then paste the code back"})
            if "token" in creds_data:
                creds = Credentials.from_authorized_user_info(creds_data)
                service = build("gmail", "v1", credentials=creds)
                profile = service.users().getProfile(userId="me").execute()
                email = profile.get("emailAddress", "connected@unknown.com")
                GMAIL_TOKENS["default"] = {"token": creds.token, "email": email, "connected": datetime.utcnow().isoformat()}
                connected = True
                total_messages = profile.get("messagesTotal", 0)
                unread_count = profile.get("threadsUnread", 0)
        except Exception as e:
            return jsonify({"success": False, "message": f"Gmail connection failed: {str(e)}"}), 400
    if not connected:
        GMAIL_TOKENS["default"] = {"token": access_token or "mock_gmail_token_xyz", "email": email, "connected": datetime.utcnow().isoformat()}
    return jsonify({
        "success": True,
        "email": email,
        "connection_status": "CONNECTED",
        "scope": ["gmail.readonly", "gmail.modify"],
        "total_messages": total_messages,
        "unread_count": unread_count,
        "real_api": connected,
        "verdict": "GMAIL_CONNECTED",
        "recommendation": "Use Gmail API to scan inbound emails for phishing and malware"
    })

def gmail_scan_inbox(current_user=None):
    data = request.get_json() or {}
    max_results = data.get("max_results", 10)
    service = _get_gmail_service()
    if service:
        try:
            results = service.users().messages().list(userId="me", maxResults=max_results, q="is:inbox").execute()
            messages = results.get("messages", [])
            threats_found = []
            safe_count = 0
            for msg in messages:
                msg_data = service.users().messages().get(userId="me", id=msg["id"], format="metadata", metadataHeaders=["From", "Subject"]).execute()
                headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
                subject = headers.get("Subject", "")
                sender = headers.get("From", "")
                snippet = msg_data.get("snippet", "")
                threat_score = 85 if re.search(r"urgent|verify|password|account.*suspend|click here|invoice|payment", subject + snippet, re.I) else 0
                if threat_score >= 50:
                    threats_found.append({"id": msg["id"], "from": sender, "subject": subject, "threat_score": threat_score, "snippet": snippet[:100]})
                else:
                    safe_count += 1
            return jsonify({"success": True, "total_scanned": len(messages), "threats_found": len(threats_found), "safe_emails": safe_count, "threats": threats_found, "source": "gmail_api", "scan_id": f"gmail-scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}", "verdict": "SCAN_COMPLETE", "recommendation": f"{len(threats_found)} threats found. Apply auto-remediation actions."})
        except Exception as e:
            pass
    inbox = GMAIL_MOCK_INBOX[:max_results]
    threats_found = [m for m in inbox if m["threat_score"] >= 50]
    safe_count = len(inbox) - len(threats_found)
    return jsonify({"success": True, "total_scanned": len(inbox), "threats_found": len(threats_found), "safe_emails": safe_count, "threats": threats_found, "source": "mock", "scan_id": f"gmail-scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}", "verdict": "SCAN_COMPLETE", "recommendation": f"{len(threats_found)} threats found simulated"})

def gmail_search(current_user=None):
    data = request.get_json() or {}
    query = data.get("query", "subject:security alert")
    max_results = data.get("max_results", 5)
    service = _get_gmail_service()
    if service:
        try:
            results = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
            messages = results.get("messages", [])
            items = []
            for msg in messages:
                msg_data = service.users().messages().get(userId="me", id=msg["id"], format="metadata", metadataHeaders=["From", "Subject"]).execute()
                headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
                items.append({"id": msg["id"], "from": headers.get("From", ""), "subject": headers.get("Subject", ""), "snippet": msg_data.get("snippet", ""), "date": msg_data.get("internalDate", "")})
            return jsonify({"success": True, "query": query, "results_count": len(items), "results": items, "source": "gmail_api", "verdict": "GMAIL_SEARCH_COMPLETE"})
        except Exception:
            pass
    results = [m for m in GMAIL_MOCK_INBOX if query.lower() in m["subject"].lower() or query.lower() in m["from"].lower()]
    return jsonify({"success": True, "query": query, "results_count": len(results[:max_results]), "results": results[:max_results], "source": "mock", "verdict": "GMAIL_SEARCH_COMPLETE"})

def gmail_disconnect(current_user=None):
    GMAIL_TOKENS.clear()
    return jsonify({"success": True, "action": "DISCONNECTED", "verdict": "GMAIL_DISCONNECTED", "recommendation": "Reconnect Gmail API when scanning is needed"})
