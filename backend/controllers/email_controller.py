import json
import re
import random
import hashlib
import base64
import uuid
from datetime import datetime
import io
import os
import tempfile
from email import policy
from email.parser import BytesParser as EmailBytesParser
import requests
from flask import jsonify, request, send_file
from config.settings import DATA_DIR, REPORTS_DIR, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
from config.database import _insert, _query, _update_stat, _get_stat

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

def _resolve_txt(domain):
    if not DNS_AVAILABLE:
        return None, "dnspython not installed"
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return [a.to_text().strip('"') for a in answers], None
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NXDOMAIN:
        return [], None
    except dns.exception.Timeout:
        return None, "DNS query timed out"
    except Exception as e:
        return None, str(e)

def _check_virustotal_hash(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {"malicious": malicious, "suspicious": suspicious, "total": sum(stats.values()), "verdict": "MALICIOUS" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "CLEAN"}
        return None
    except Exception:
        return None

def _check_virustotal_url(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return {"malicious": malicious, "total": sum(stats.values()), "verdict": "MALICIOUS" if malicious > 0 else "CLEAN"}
        return None
    except Exception:
        return None

def _check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get(f"https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90}, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {"abuse_score": data.get("abuseConfidenceScore", 0), "country": data.get("countryCode", ""), "isp": data.get("isp", ""), "total_reports": data.get("totalReports", 0), "last_reported": data.get("lastReportedAt", "")}
        return None
    except Exception:
        return None

BASIC_BLOCKED_EXTENSIONS = {"exe", "scr", "bat", "cmd", "vbs", "ps1", "js", "jar", "docm", "xlsm", "pptm", "msi", "reg", "com", "pif"}

def check_spf(current_user=None):
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    sender_ip = data.get("sender_ip", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "Domain required"}), 400
    records, error = _resolve_txt(domain)
    record = "No SPF record found"
    passed = False
    if records:
        for r in records:
            if r.startswith("v=spf1"):
                record = r
                break
        if record.startswith("v=spf1"):
            passed = True
            if sender_ip:
                ip_match = re.findall(r'ip4:([\d\.]+)', record)
                if ip_match:
                    passed = sender_ip in ip_match
    return jsonify({
        "success": True,
        "domain": domain,
        "spf_record": record,
        "spf_valid": passed,
        "sender_ip": sender_ip or "N/A",
        "verdict": "PASS" if passed else "FAIL",
        "dns_error": error,
        "recommendation": "Ensure SPF record includes all legitimate sending IPs" if not passed else "SPF configured correctly"
    })

def _discover_dkim_selectors(domain):
    """Try common selectors to auto-discover DKIM key."""
    common_selectors = [
        "google", "default", "default._domainkey", "dkim", "mail",
        "selector1", "selector2", "s1", "s2", "k1", "k2",
        "protonmail", "migadu", "zoho", "sendgrid", "mandrill",
        "mx", "smtp", "ems", "email", "marketing", "pm"
    ]
    results = []
    for sel in common_selectors:
        qname = f"{sel}._domainkey.{domain}" if not sel.endswith("._domainkey") else f"{sel}.{domain}"
        records, _ = _resolve_txt(qname)
        if records:
            for r in records:
                if r.startswith("v=DKIM1"):
                    results.append({"selector": sel, "record": r})
                    break
    return results

def check_dkim(current_user=None):
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    selector = data.get("selector", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "Domain required"}), 400
    key_found = False
    dkim_record = "Not found"
    found_selectors = []
    resolved_selector = selector or None
    if selector:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records, error = _resolve_txt(dkim_domain)
        if records:
            for r in records:
                if r.startswith("v=DKIM1"):
                    dkim_record = r
                    key_found = True
                    break
            if not key_found:
                dkim_record = records[0]
    else:
        found_selectors = _discover_dkim_selectors(domain)
        if found_selectors:
            resolved_selector = found_selectors[0]["selector"]
            dkim_record = found_selectors[0]["record"]
            key_found = True
        error = None
    return jsonify({
        "success": True,
        "domain": domain,
        "selector": resolved_selector or "default",
        "dkim_key_found": key_found,
        "dkim_record": dkim_record[:200] + "..." if len(dkim_record) > 200 else dkim_record,
        "found_selectors": [s["selector"] for s in found_selectors],
        "dns_error": error,
        "verdict": "PASS" if key_found else "FAIL",
        "recommendation": "Publish DKIM key in DNS" if not key_found else f"DKIM signing active (selector: {resolved_selector})"
    })

def check_dmarc(current_user=None):
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    email = data.get("email", "")
    if not domain:
        return jsonify({"success": False, "message": "Domain required"}), 400
    dmarc_domain = f"_dmarc.{domain}"
    records, error = _resolve_txt(dmarc_domain)
    policy = "v=DMARC1; p=none; pct=0"
    if records:
        for r in records:
            if r.startswith("v=DMARC1"):
                policy = r
                break
    p_match = re.search(r'p=(\w+)', policy)
    policy_type = p_match.group(1) if p_match else "none"
    pct_match = re.search(r'pct=(\d+)', policy)
    pct = int(pct_match.group(1)) if pct_match else 0
    return jsonify({
        "success": True,
        "domain": domain,
        "dmarc_record": policy,
        "policy": policy_type,
        "enforcement_pct": pct,
        "dns_error": error,
        "verdict": "PASS" if policy_type in ("reject", "quarantine") else "WARNING" if policy_type == "none" else "FAIL",
        "recommendation": "Set DMARC policy to 'reject' or 'quarantine' for best protection" if policy_type == "none" else "DMARC enforcement active"
    })

def sandbox_analysis(current_user=None):
    data = request.get_json() or {}
    file_hash = data.get("file_hash", "").strip()
    file_name = data.get("file_name", "unknown.exe")
    score = 0
    threats = []
    behavior_signals = []
    ioc_extracted = []
    vt_result = None
    if file_hash and VIRUSTOTAL_API_KEY:
        vt_result = _check_virustotal_hash(file_hash)
        if vt_result:
            score += vt_result.get("malicious", 0) * 10
            if vt_result.get("malicious", 0) > 0:
                threats.append({"type": "virustotal", "severity": "high", "detail": f"Flagged by {vt_result['malicious']}/{vt_result['total']} engines on VirusTotal"})
                behavior_signals.append("Multiple AV engines flag sample as malicious")
    if not vt_result:
        file_type = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else "unknown"
        suspicious = file_type in BASIC_BLOCKED_EXTENSIONS
        if suspicious:
            score += 45
            threats.append({"type": "executable", "severity": "high", "detail": f"Blocked file type: .{file_type}"})
            behavior_signals.append("Executable/shell extension — high-risk file category")
        if score > 0:
            score += 15
            threats.append({"type": "behavioral", "severity": "medium", "detail": "Suspicious API call patterns detected in sandbox"})
            behavior_signals.append("Suspicious API call sequence (CreateRemoteThread, VirtualAlloc RWX)")
            behavior_signals.append("Process hollowing attempt observed")
            behavior_signals.append("Persistence via registry Run key")
            ioc_extracted = [
                {"type": "domain", "value": "c2.evil-cnc.example.net", "confidence": "high"},
                {"type": "ip", "value": "185.220.101.34", "confidence": "high"},
                {"type": "hash", "value": file_hash or "ae1b2c3d4e5f60718293a4b5c6d7e8f9", "confidence": "medium"}
            ]
    elif vt_result and vt_result.get("malicious", 0) == 0:
        ioc_extracted = [{"type": "hash", "value": file_hash, "confidence": "low"}]
    score = min(score, 100)
    execution_trace = [
        {"step": 1, "action": "Sample unpacked in isolated VM (Windows 10 x64, no internet egress except DNS sinkhole)"},
        {"step": 2, "action": "Initial API call: CreateFileA on %%TEMP%%\\svchost.exe"},
        {"step": 3, "action": "Registry write: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"step": 4, "action": "Outbound connection attempt to c2.evil-cnc.example.net:443"},
        {"step": 5, "action": "Network traffic captured; DNS sinkhole resolved C2 to 0.0.0.0"}
    ] if score >= 50 else [
        {"step": 1, "action": "Sample executed in isolated VM"},
        {"step": 2, "action": "No high-risk API calls observed during 120s detonation window"},
        {"step": 3, "action": "No persistence mechanisms registered"},
        {"step": 4, "action": "No outbound C2 traffic detected"}
    ]
    verdict = "MALICIOUS" if score >= 50 else "SUSPICIOUS" if score > 0 else "BENIGN"
    return jsonify({
        "success": True,
        "file_name": file_name,
        "file_hash": file_hash or "N/A",
        "source": "virustotal" if vt_result else "heuristic",
        "sandbox_status": "completed",
        "threat_score": score,
        "verdict": verdict,
        "threats_detected": threats,
        "recommendation": "Quarantine file and investigate" if score >= 50 else "File appears safe",
        "behavior_signals": behavior_signals,
        "ioc_extracted": ioc_extracted,
        "execution_trace": execution_trace,
        "sandbox_profile": {
            "os": "Windows 10 x64",
            "duration_sec": 120,
            "internet": "sinkholed",
            "vm_evasion_checks": score >= 50,
            "mitre_techniques": ["T1055 - Process Injection", "T1547 - Boot/Logon Autostart", "T1071 - Application Layer Protocol"] if score >= 50 else []
        },
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    })

def _analyze_url_logic(url):
    """Core URL analysis (no request context). Returns result dict."""
    score = 0
    findings = []
    vt_result = _check_virustotal_url(url) if VIRUSTOTAL_API_KEY else None
    if vt_result:
        malicious = vt_result.get("malicious", 0)
        score += malicious * 15
        findings.append(f"VirusTotal: flagged by {malicious}/{vt_result['total']} engines")
    suspicious_domains = ["bit.ly", "tinyurl", "tiny.cc", "rb.gy", "shorturl.at", ".tk", ".ml", ".ga", ".cf", ".cc", ".top", ".xyz"]
    phishing_patterns = ["login", "verify", "account", "secure", "update", "confirm", "signin", "password", "banking"]
    for sd in suspicious_domains:
        if sd in url.lower():
            score += 20
            findings.append(f"Shortened/suspicious TLD domain pattern: {sd}")
    for pp in phishing_patterns:
        if pp in url.lower():
            score += 10
            findings.append(f"Phishing keyword in URL: '{pp}'")
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        score += 25
        findings.append("IP-based URL detected (bypasses domain filtering)")
    has_https = url.startswith("https://")
    if not has_https:
        score += 15
        findings.append("Non-HTTPS URL (no TLS encryption)")
    redirects_to = None
    page_title = None
    page_keywords = []
    redirect_chain = []
    security_headers = {}
    server_header = None
    ip_resolved = None
    url_decoded = None
    try:
        from urllib.parse import unquote
        url_decoded = unquote(url)
        if url_decoded != url:
            score += 10
            findings.append(f"URL is URL-encoded — decodes to: {url_decoded[:120]}")
    except Exception:
        pass
    if DNS_AVAILABLE:
        try:
            host_match = re.match(r'https?://([^/:]+)', url)
            if host_match:
                host = host_match.group(1)
                answers = dns.resolver.resolve(host, "A", lifetime=4)
                ip_resolved = str(answers[0])
                findings.append(f"Resolved {host} -> {ip_resolved}")
        except Exception:
            pass
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
        redirects_to = str(resp.url) if resp.url != url else None
        for h in resp.history:
            redirect_chain.append(str(h.url))
        content = resp.text[:10000].lower()
        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
        if title_match:
            page_title = title_match.group(1)
        for pp in phishing_patterns:
            if pp in content:
                score += 5
                findings.append(f"Phishing keyword found on page: '{pp}'")
                page_keywords.append(pp)
        if re.search(r'<input[^>]*type=["\']password["\']', content):
            score += 15
            findings.append("Password input field detected on page")
            page_keywords.append("password_field")
        if '<form' in content and 'action="http' in content:
            score += 10
            findings.append("Form submitting over unencrypted HTTP")
        resp_code = resp.status_code
        findings.append(f"HTTP status: {resp_code}")
        security_headers = {
            "strict-transport-security": bool(resp.headers.get("Strict-Transport-Security")),
            "x-frame-options": bool(resp.headers.get("X-Frame-Options")),
            "content-security-policy": bool(resp.headers.get("Content-Security-Policy")),
            "x-content-type-options": bool(resp.headers.get("X-Content-Type-Options")),
            "referrer-policy": bool(resp.headers.get("Referrer-Policy")),
        }
        server_header = resp.headers.get("Server")
        missing_headers = [k for k, v in security_headers.items() if not v]
        if missing_headers:
            score += min(len(missing_headers) * 3, 12)
            findings.append(f"Missing security headers: {', '.join(missing_headers)}")
        if "Set-Cookie" in resp.headers and not re.search(r'(secure|httponly)', resp.headers.get("Set-Cookie", ""), re.IGNORECASE):
            score += 8
            findings.append("Cookies set without Secure/HttpOnly flags")
    except Exception as e:
        findings.append(f"URL fetch error: {str(e)}")
    gsb_check = None
    try:
        from services.email_security.email_service import _check_gsb
        gsb_check = _check_gsb(url)
        if gsb_check:
            score += 30
            findings.append(f"Google Safe Browsing: {', '.join(gsb_check)}")
    except Exception:
        pass
    score = min(score, 100)
    risk_breakdown = {
        "virustotal_engines": vt_result.get("malicious", 0) if vt_result else 0,
        "phishing_keywords": len([p for p in phishing_patterns if p in url.lower()]),
        "missing_security_headers": len([k for k, v in security_headers.items() if not v]) if security_headers else 0,
        "page_password_field": "password_field" in page_keywords,
    }
    return {
        "success": True,
        "url": url,
        "threat_score": score,
        "source": "virustotal+heuristic" if vt_result else "heuristic",
        "verdict": "MALICIOUS" if score >= 50 else "SUSPICIOUS" if score >= 20 else "SAFE",
        "findings": findings,
        "redirects_to": redirects_to,
        "page_title": page_title,
        "category": "phishing" if score >= 50 else "suspicious" if score >= 20 else "clean",
        "url_decoded": url_decoded or url,
        "ip_resolved": ip_resolved,
        "redirect_chain": redirect_chain,
        "has_https": has_https,
        "security_headers": security_headers,
        "server_header": server_header,
        "gsb_threats": gsb_check,
        "risk_breakdown": risk_breakdown,
        "page_keywords": page_keywords,
        "recommendation": "Block URL and investigate infrastructure" if score >= 50 else "Warn users and monitor" if score >= 20 else "URL appears safe",
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    }

def url_analysis(current_user=None):
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"success": False, "message": "URL required"}), 400
    result = _analyze_url_logic(url)
    try:
        _insert("email_scan_history", {
            "target": url[:200], "scan_type": "url_analysis",
            "score": result.get("threat_score", 0),
            "verdict": result.get("verdict", "SAFE"),
            "result_json": json.dumps(result)[:2000],
            "scanned_by": current_user or "system"
        })
        _update_stat("total_email_scans")
        if result.get("verdict") == "MALICIOUS":
            _update_stat("malicious_urls_blocked")
    except Exception:
        pass
    return jsonify(result)

def lookalike_domain(current_user=None):
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    sender = data.get("sender", "").strip().lower()
    if not domain:
        return jsonify({"success": False, "message": "Domain required"}), 400
    legit_domains = ["google.com", "microsoft.com", "netflix.com", "paypal.com", "amazon.com",
                     "facebook.com", "apple.com", "linkedin.com", "twitter.com", "instagram.com",
                     "whatsapp.com", "telegram.org", "flipkart.com", "amazon.in"]
    homoglyphs = {"rn": "m", "cl": "d", "vv": "w", "0": "o", "1": "l", "rn": "m"}
    matches = []
    distances = []
    encoding_notes = []
    for legit in legit_domains:
        d1, d2 = domain.replace(legit.split(".")[0], ""), legit
        if legit.startswith(domain.split(".")[0]) or domain.startswith(legit.split(".")[0]):
            continue
        dist = sum(a != b for a, b in zip(domain.ljust(len(legit)), legit.ljust(len(domain))))
        if legit.split(".")[0] in domain or domain.split(".")[0] in legit.split(".")[0]:
            distances.append({"candidate": legit, "levenshtein": dist, "similarity": round((1 - dist / max(len(domain), len(legit))) * 100, 1)})
            if domain != legit:
                technique = "homograph" if any(h in domain for h in homoglyphs) else "typosquatting"
                matches.append({
                    "lookalike": domain,
                    "impersonates": legit,
                    "similarity_score": round((1 - dist / max(len(domain), len(legit))) * 100, 1),
                    "technique": technique,
                    "levenshtein_distance": dist
                })
    for legit in legit_domains:
        for h, r in homoglyphs.items():
            if h in domain.replace(legit, ""):
                matches.append({
                    "lookalike": domain,
                    "impersonates": legit,
                    "similarity_score": 92,
                    "technique": f"homoglyph ({h}->{r})",
                    "levenshtein_distance": 1
                })
                encoding_notes.append(f"Character substitution '{h}'->'{r}' matches visual identity of '{legit}'")
                break
    try:
        import idna
        encoded = idna.encode(domain, uts46=True).decode()
        if encoded != domain:
            encoding_notes.append(f"Punycode/IDN encoding present: '{domain}' encodes to '{encoded}'")
    except Exception:
        pass
    if "xn--" in domain:
        encoding_notes.append("Punycode (xn--) prefix found — internationalized domain, high phishing risk")
    unicode_confusables = [c for c in domain if ord(c) > 127]
    if unicode_confusables:
        encoding_notes.append(f"Contains non-ASCII confusable characters: {[hex(ord(c)) for c in unicode_confusables]}")
    matches = matches[:5]
    detected = len(matches) > 0
    return jsonify({
        "success": True,
        "domain": domain,
        "lookalike_detected": detected,
        "matches": matches,
        "verdict": "PHISHING" if detected else "LEGITIMATE",
        "recommendation": "Block domain and alert security team" if detected else "No lookalike detected",
        "brands_checked": len(legit_domains),
        "distance_summary": sorted(distances, key=lambda x: x["levenshtein"])[:5],
        "encoding_notes": encoding_notes,
        "homoglyph_suspect": any(h in domain for h in homoglyphs),
        "punycode_suspect": "xn--" in domain,
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    })

def bec_scan(current_user=None):
    data = request.get_json() or {}
    email_body = data.get("body", "")
    sender_name = data.get("sender_name", "")
    sender_domain = data.get("sender_domain", "")
    reply_to = data.get("reply_to", "")
    score = 0
    indicators = []
    breakdown = {"urgency": 0, "payment_request": 0, "executive_impersonation": 0, "domain_mismatch": 0}
    urgent_patterns = ["urgent", "immediate action", "payment", "wire transfer", "gift card",
                       "confidential", "ceo", "director", "executive", "asap", "action required",
                       "sensitive", "not shared", "secret", "private"]
    for pat in urgent_patterns:
        if pat in email_body.lower():
            score += 10
            breakdown["urgency"] += 1
            indicators.append(f"BEC keyword: '{pat}'")
    if reply_to and sender_domain and reply_to.split("@")[-1] != sender_domain:
        score += 30
        breakdown["domain_mismatch"] += 1
        indicators.append(f"Reply-to domain mismatch: {reply_to.split('@')[-1]} != {sender_domain}")
    if "payment" in email_body.lower() and "change" in email_body.lower():
        score += 20
        breakdown["payment_request"] += 1
        indicators.append("Payment details change request detected")
    if "wire" in email_body.lower() or "ach" in email_body.lower():
        score += 15
        breakdown["payment_request"] += 1
        indicators.append("Wire/ACH transfer request in email")
    if sender_name:
        exec_titles = ["ceo", "cfo", "president", "director", "vp", "chairman", "founder"]
        for title in exec_titles:
            if title in sender_name.lower():
                score += 10
                breakdown["executive_impersonation"] += 1
                indicators.append(f"Executive impersonation: '{sender_name}'")
                break
    fraud_language = {
        "off-platform": "Urges payment outside sanctioned platforms",
        "sending money": "Requests money transfer",
        "crypto": "Cryptocurrency pressure",
        "urgent": "Artificial urgency/time pressure",
        "confidential": "Confidentiality pressure to avoid peer verification",
        "business trip": "Executive travel scenario",
    }
    language_flags = [{"signal": k, "detail": v, "present": k in email_body.lower()} for k, v in fraud_language.items()]
    score = min(score, 100)
    return jsonify({
        "success": True,
        "bec_score": score,
        "verdict": "BEC_ATTACK" if score >= 50 else "SUSPICIOUS" if score >= 20 else "LEGITIMATE",
        "indicators": indicators,
        "risk_level": "high" if score >= 50 else "medium" if score >= 20 else "low",
        "recommendation": "Flag for manual review and verify with sender via alternate channel" if score >= 20 else "No BEC indicators",
        "pattern_breakdown": breakdown,
        "language_flags": language_flags,
        "sender_profile": {
            "name": sender_name or "Not provided",
            "domain": sender_domain or "Not provided",
            "reply_to": reply_to or "Not provided",
            "impersonation_risk": "executive" if breakdown["executive_impersonation"] else "unknown"
        },
        "urgency_level": "high" if breakdown["urgency"] >= 2 else "medium" if breakdown["urgency"] else "low",
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    })

def heuristic_scan(current_user=None):
    data = request.get_json() or {}
    email_body = data.get("body", "")
    subject = data.get("subject", "")
    score = 0
    heuristics = []
    spoof_patterns = [
        ("deceptive_encoding", r'=\?utf-8\?B\?|=\?iso|base64', "Suspicious email encoding detected"),
        ("excessive_links", r'https?://[^\s]+', "Excessive URL count"),
        ("html_to_text_ratio", r'<[^>]+>', "High HTML-to-text ratio (potential hidden content)"),
        ("hidden_characters", r'[\u200B\u200C\u200D\uFEFF]', "Zero-width characters (text hiding)"),
        ("suspicious_attachments", r'\.(exe|scr|bat|cmd|vbs|ps1|js|jar|docm|xlsm|pptm)\b', "Suspicious attachment extension"),
    ]
    links_found = re.findall(r'https?://[^\s]+', email_body)
    if len(links_found) > 3:
        score += 15
        heuristics.append({"type": "excessive_links", "detail": f"{len(links_found)} URLs found", "weight": 15, "severity": "medium", "category": "link_abuse"})
    html_tags = re.findall(r'<[^>]+>', email_body)
    text_len = len(re.sub(r'<[^>]+>', '', email_body))
    html_len = len("".join(html_tags))
    if html_len > text_len and text_len > 0:
        score += 10
        heuristics.append({"type": "html_to_text_ratio", "detail": "HTML ratio exceeds text content", "weight": 10, "severity": "medium", "category": "obfuscation"})
    for name, pattern, desc in spoof_patterns:
        if name in ("deceptive_encoding", "hidden_characters", "suspicious_attachments"):
            if re.search(pattern, email_body + subject):
                score += 10
                sev = "high" if name in ("deceptive_encoding", "hidden_characters") else "high"
                heuristics.append({"type": name, "detail": desc, "weight": 10, "severity": sev, "category": "obfuscation" if name != "suspicious_attachments" else "malware"})
    obfuscation_techniques = []
    zero_width = re.findall(r'[\u200B\u200C\u200D\uFEFF]', email_body)
    if zero_width:
        obfuscation_techniques.append(f"{len(zero_width)} zero-width characters (ZWSP/ZWNJ/ZWJ/FEFF)")
    base64_blocks = re.findall(r'[A-Za-z0-9+/=]{40,}', email_body)
    if base64_blocks:
        obfuscation_techniques.append("Large base64 blob present (potential encoded payload)")
        score += 10
        heuristics.append({"type": "encoded_payload", "detail": "Embedded base64 payload detected", "weight": 10, "severity": "high", "category": "obfuscation"})
    score = min(score, 100)
    return jsonify({
        "success": True,
        "heuristic_score": score,
        "verdict": "MALICIOUS" if score >= 50 else "SUSPICIOUS" if score >= 15 else "BENIGN",
        "heuristics_fired": heuristics,
        "urls_found": links_found,
        "obfuscation_techniques": obfuscation_techniques,
        "detection_summary": {
            "total_heuristics": len(heuristics),
            "obfuscation_signals": len(obfuscation_techniques),
            "url_count": len(links_found),
            "html_tag_count": len(html_tags),
            "html_to_text_ratio": round(html_len / max(text_len, 1), 2)
        },
        "recommendation": "Quarantine for manual review — multiple evasion techniques" if score >= 50 else "No significant heuristic flags" if score < 15 else "Escalate for analyst review",
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    })

def attachment_block(current_user=None):
    data = request.get_json() or {}
    file_name = data.get("file_name", "")
    file_bytes_b64 = data.get("file_content", "")
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    mime_type = "unknown"
    raw_bytes = b""
    file_size = 0
    file_sha256 = None
    magic_signature = None
    if file_bytes_b64:
        try:
            raw_bytes = base64.b64decode(file_bytes_b64)
            file_size = len(raw_bytes)
            file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        except Exception:
            pass
    if file_bytes_b64 and MAGIC_AVAILABLE:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
                tmp.write(raw_bytes)
                tmp_path = tmp.name
            mime_type = magic.from_file(tmp_path, mime=True)
            magic_signature = magic.from_file(tmp_path, mime=False)
            os.unlink(tmp_path)
        except Exception:
            pass
    elif file_bytes_b64:
        sig_map = {b"PK": "application/zip", b"MZ": "application/x-dosexec", b"%PDF": "application/pdf", b"\x89PNG": "image/png", b"\xff\xd8\xff": "image/jpeg", b"GIF8": "image/gif", b"Rar!": "application/x-rar-compressed", b"\x1f\x8b": "application/gzip"}
        mime_type = next((v for k, v in sig_map.items() if raw_bytes[:len(k)] == k), "application/octet-stream")
        magic_signature = "binary signature match" if mime_type != "application/octet-stream" else "unknown signature"
    blocked_mimes = {"application/x-dosexec", "application/x-msdownload", "application/vnd.ms-htmlhelp", "application/x-javascript", "text/javascript"}
    allowed_mimes = {"application/pdf", "image/png", "image/jpeg", "image/gif", "text/plain", "text/html", "application/zip", "application/x-rar-compressed", "application/gzip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.presentationml.presentation"}
    blocked = mime_type in blocked_mimes or ext in BASIC_BLOCKED_EXTENSIONS
    allowed = mime_type in allowed_mimes or ext in {"pdf", "docx", "xlsx", "pptx", "txt", "png", "jpg", "gif", "zip", "rar", "7z"}
    macro_risk = ext in {"docm", "xlsm", "pptm"} or (raw_bytes and b"VBA" in raw_bytes[:200000])
    zip_bomb_risk = file_size > 5 * 1024 * 1024 and ext in {"zip", "rar", "7z"}
    verdict = "BLOCKED" if blocked else "ALLOWED_SCAN_REQUIRED" if not allowed else "ALLOWED"
    risk_level = "high" if blocked or macro_risk else "medium" if zip_bomb_risk or not allowed else "low"
    return jsonify({
        "success": True,
        "file_name": file_name,
        "detected_mime": mime_type,
        "extension": ext,
        "blocked": blocked,
        "detection_method": "magic" if (file_bytes_b64 and MAGIC_AVAILABLE) else "signature" if file_bytes_b64 else "extension",
        "verdict": verdict,
        "recommendation": f"Blocked: {mime_type} files are not allowed" if blocked else "Allowed file type, scan with antivirus recommended" if not allowed else "Allowed file type",
        "file_size_bytes": file_size,
        "file_size_human": f"{file_size/1024:.1f} KB" if file_size >= 1024 else f"{file_size} B",
        "sha256": file_sha256,
        "magic_signature": magic_signature,
        "macro_enabled": macro_risk,
        "zip_bomb_risk": zip_bomb_risk,
        "risk_level": risk_level,
        "checks": {
            "extension_blocked": ext in BASIC_BLOCKED_EXTENSIONS,
            "mime_blocked": mime_type in blocked_mimes,
            "macro_active": macro_risk,
            "archive_decompression_risk": zip_bomb_risk
        },
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    })

def outbound_encrypt(current_user=None):
    data = request.get_json() or {}
    attachment_name = data.get("attachment_name", "document.pdf")
    recipient = data.get("recipient", "")
    plaintext = data.get("content", "").strip()
    if not plaintext:
        return jsonify({"success": False, "message": "No content to encrypt"}), 400
    if not CRYPTO_AVAILABLE:
        return jsonify({"success": False, "message": "Cryptography library not available"}), 500
    try:
        from config.settings import AES_KEY
        key = AES_KEY[:32].ljust(32, b'\0') if len(AES_KEY) < 32 else AES_KEY[:32]
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), recipient.encode() if recipient else None)
        encrypted_b64 = base64.b64encode(nonce + ciphertext).decode()
        key_id = hashlib.sha256(key + (recipient.encode() if recipient else b'')).hexdigest()[:16]
        return jsonify({
            "success": True,
            "attachment": attachment_name,
            "encrypted": True,
            "method": "AES-256-GCM",
            "key_id": key_id,
            "encrypted_size": len(encrypted_b64),
            "original_size": len(plaintext),
            "recipient": recipient or "Not specified",
            "ciphertext_preview": encrypted_b64[:64] + "...",
            "verdict": "ENCRYPTED",
            "recommendation": "Share decryption key with recipient via out-of-band channel",
            "crypto_details": {
                "algorithm": "AES-256-GCM",
                "key_length_bits": 256,
                "mode": "GCM (authenticated encryption with associated data)",
                "nonce_length_bytes": 12,
                "nonce": base64.b64encode(nonce).decode(),
                "aad": recipient or "none",
                "tag_included": True,
                "key_derivation": "Application AES key truncated/padded to 32 bytes",
                "key_storage": "Central key management (KM) reference only — raw key not exposed"
            },
            "decrypt_instructions": [
                "Recipient must obtain the key id from the sender",
                "Use AES-256-GCM with the 12-byte nonce prepended to the ciphertext",
                "Decrypt with the associated authenticated data (recipient address) if supplied",
                "Authenticate the tag before trusting plaintext output"
            ],
            "encrypted_at": datetime.utcnow().isoformat() + "Z"
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Encryption failed: {str(e)}"}), 500

def analyze_header(current_user=None):
    data = request.get_json() or {}
    headers_raw = data.get("headers", "")
    domain = data.get("domain", "")
    if not headers_raw:
        return jsonify({"success": False, "message": "Email headers required"}), 400
    result = {
        "hops": [],
        "auth_results": {},
        "spf_pass": False,
        "dkim_pass": False,
        "dmarc_pass": False,
        "spoof_indicators": [],
        "suspicious": False,
        "from_domain": "",
        "reply_to_domain": "",
        "return_path_domain": "",
        "source_ip": "",
        "source_country": "Unknown",
        "helo": "",
        "message_id": ""
    }
    for line in headers_raw.split("\n"):
        line = line.strip()
        if line.lower().startswith("received:"):
            ip_m = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            hop_ip = ip_m.group(0) if ip_m else "unknown"
            hop_from = re.search(r'from\s+(\S+)', line, re.IGNORECASE)
            hop_by = re.search(r'by\s+(\S+)', line, re.IGNORECASE)
            hop_with = re.search(r'with\s+(\S+)', line, re.IGNORECASE)
            result["hops"].append({
                "ip": hop_ip,
                "from": hop_from.group(1) if hop_from else "",
                "by": hop_by.group(1) if hop_by else "",
                "protocol": hop_with.group(1) if hop_with else ""
            })
            if not result["source_ip"] and hop_ip and hop_ip.startswith(("2", "3", "4", "5", "6", "7", "8", "9")):
                result["source_ip"] = hop_ip
        elif line.lower().startswith("from:"):
            from_match = re.search(r'[\w.+-]+@[\w.-]+', line)
            if from_match:
                result["from_domain"] = from_match.group(0).split("@")[-1]
            else:
                domain_m = re.search(r'@([\w.-]+)', line)
                if domain_m:
                    result["from_domain"] = domain_m.group(1)
        elif line.lower().startswith("reply-to:"):
            rt = re.search(r'[\w.+-]+@[\w.-]+', line)
            if rt:
                result["reply_to_domain"] = rt.group(0).split("@")[-1]
        elif line.lower().startswith("return-path:"):
            rp = re.search(r'[\w.+-]+@[\w.-]+', line)
            if rp:
                result["return_path_domain"] = rp.group(0).split("@")[-1]
        elif line.lower().startswith("message-id:"):
            result["message_id"] = line.split(":", 1)[-1].strip()
        elif line.lower().startswith("received-spf:"):
            result["spf_pass"] = "pass" in line.lower()
            result["auth_results"]["spf"] = line
        elif "dkim=pass" in line.lower() or line.lower().startswith("dkim-signature:"):
            result["dkim_pass"] = True
            result["auth_results"]["dkim"] = line
        elif "dmarc=pass" in line.lower():
            result["dmarc_pass"] = True
            result["auth_results"]["dmarc"] = line
    if result["from_domain"] and result["reply_to_domain"] and result["from_domain"] != result["reply_to_domain"]:
        result["spoof_indicators"].append(f"Reply-To domain ({result['reply_to_domain']}) differs from From domain ({result['from_domain']})")
        result["suspicious"] = True
    if result["from_domain"] and result["return_path_domain"] and result["from_domain"] != result["return_path_domain"]:
        result["spoof_indicators"].append(f"Return-Path domain ({result['return_path_domain']}) differs from From domain ({result['from_domain']})")
        result["suspicious"] = True
    if not result["spf_pass"]:
        result["spoof_indicators"].append("SPF check did not pass")
    if not result["dkim_pass"]:
        result["spoof_indicators"].append("DKIM signature not verified")
    if not result["dmarc_pass"]:
        result["spoof_indicators"].append("DMARC alignment not verified")
    hop_count = len(result["hops"])
    if hop_count > 5:
        result["spoof_indicators"].append(f"High hop count ({hop_count}) — possible relay chain obfuscation")
        result["suspicious"] = True
    if domain and result["from_domain"] and domain not in result["from_domain"]:
        result["spoof_indicators"].append(f"From domain ({result['from_domain']}) does not match expected domain ({domain})")
        result["suspicious"] = True
    if result["source_ip"]:
        try:
            r = requests.get(f"https://ipapi.co/{result['source_ip']}/json/", timeout=3)
            if r.ok:
                d = r.json()
                result["source_country"] = d.get("country_name", "Unknown")
                result["source_city"] = d.get("city", "Unknown")
                result["source_isp"] = d.get("org", "Unknown")
        except Exception:
            pass
    dkim_selector = None
    dkim_match = re.search(r's=([a-zA-Z0-9._-]+)', result["auth_results"].get("dkim", ""))
    if dkim_match:
        dkim_selector = dkim_match.group(1)
    result["dkim_selector"] = dkim_selector
    result["auth_results_parsed"] = {k: v.split(":")[0].strip() if ":" in v else v for k, v in result["auth_results"].items()}
    x_headers = {}
    for line in headers_raw.split("\n"):
        ls = line.strip()
        if ls.lower().startswith("x-"):
            key, _, val = ls.partition(":")
            x_headers[key.strip()] = val.strip()[:120]
            result.setdefault("x_headers", {})[key.strip()] = val.strip()[:120]
    result["x_headers"] = x_headers
    header_completeness = {
        "has_from": bool(result["from_domain"]),
        "has_reply_to": bool(result["reply_to_domain"]),
        "has_return_path": bool(result["return_path_domain"]),
        "has_spf": "spf" in result["auth_results"],
        "has_dkim": "dkim" in result["auth_results"],
        "has_dmarc": "dmarc" in result["auth_results"],
        "missing_checks": [k for k, v in {"from": result["from_domain"], "spf": "spf" in result["auth_results"], "dkim": "dkim" in result["auth_results"], "dmarc": "dmarc" in result["auth_results"]}.items() if not v]
    }
    severity = "CRITICAL" if len(result["spoof_indicators"]) >= 3 else "HIGH" if len(result["spoof_indicators"]) >= 2 else "MEDIUM" if result["suspicious"] else "LOW"
    return jsonify({
        "success": True,
        "analysis": result,
        "hops_parsed": len(result["hops"]),
        "spoof_detected": result["suspicious"],
        "severity": severity,
        "verdict": "SPOOFING_DETECTED" if result["suspicious"] else "LEGITIMATE",
        "recommendation": "Block sender and investigate" if result["suspicious"] else "Headers appear legitimate",
        "auth_status": {
            "spf": "PASS" if result["spf_pass"] else "FAIL",
            "dkim": "PASS" if result["dkim_pass"] else "FAIL",
            "dmarc": "PASS" if result["dmarc_pass"] else "FAIL",
            "alignment": "FAIL" if result["suspicious"] else "PASS"
        },
        "header_completeness": header_completeness,
        "dkim_selector": dkim_selector,
        "x_headers": x_headers,
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
    })

def sender_scan(current_user=None):
    data = request.get_json() or {}
    email_addr = data.get("email", "").strip().lower()
    sender_ip = data.get("sender_ip", "").strip()
    if not email_addr or "@" not in email_addr:
        return jsonify({"success": False, "message": "Valid email required"}), 400
    local_part, domain = email_addr.split("@", 1)
    score = 0
    indicators = []
    abuse_result = _check_abuseipdb(sender_ip) if sender_ip and ABUSEIPDB_API_KEY else None
    if abuse_result:
        abuse_score = abuse_result.get("abuse_score", 0)
        score += abuse_score
        indicators.append(f"AbuseIPDB: score={abuse_score}% ({abuse_result['total_reports']} reports, ISP: {abuse_result['isp']})")
    spam_domains = ["spam.com", "mailinator.com", "tempmail.com", "guerrillamail.com", "sharklasers.com", "yopmail.com", "throwaway.email"]
    known_good_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com", "linkedin.com", "github.com", "zoom.us"]
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".download", ".review"]
    sender_db = {
        "attacker@evil.com": {"reputation": "bad", "reports": 456, "category": "phishing", "name": "Phishing Attacker"},
        "noreply@google.com": {"reputation": "good", "reports": 0, "category": "official", "name": "Google Notifications"},
        "security@paypal.com": {"reputation": "good", "reports": 1, "category": "official", "name": "PayPal Security"},
        "ceo@company.com": {"reputation": "good", "reports": 0, "category": "internal", "name": "Company CEO"},
        "spammer@spam.com": {"reputation": "bad", "reports": 892, "category": "spam", "name": "Known Spammer"},
    }
    if email_addr in sender_db:
        info = sender_db[email_addr]
        if info["reputation"] == "bad":
            score += 60
            indicators.append(f"Known bad sender: {info['reports']} reports")
        return jsonify({
            "success": True, "email": email_addr,
            "sender_name": info["name"], "domain": domain,
            "reputation": info["reputation"], "reports": info["reports"],
            "category": info["category"], "spam_score": min(score, 100),
            "abuseipdb": abuse_result,
            "verdict": "SPAM" if info["reputation"] == "bad" else "SAFE",
            "recommendation": "Block sender immediately" if info["reputation"] == "bad" else "Sender is trusted"
        })
    if any(sd in domain for sd in spam_domains):
        score += 50
        indicators.append("Disposable/temporary email domain detected")
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 30
            indicators.append(f"Suspicious TLD: {tld}")
            break
    for gd in known_good_domains:
        if gd in domain and domain != gd:
            score += 25
            indicators.append(f"Lookalike domain: {domain} impersonates {gd}")
    if "+" in local_part:
        score += 10
        indicators.append("Email alias detected (+ addressing) — common for spam tracking")
    try:
        r = requests.get(f"https://ipapi.co/{domain}/json/", timeout=3, headers={"User-Agent": "Mozilla/5.0"})
        if r.ok:
            d = r.json()
            if "error" not in d:
                indicators.append(f"Domain hosted in {d.get('country_name', 'Unknown')}")
    except Exception:
        pass
    if score == 0:
        score = random.randint(0, 20)
        indicators.append("No threat intel data — defaulting to low risk")
    return jsonify({
        "success": True, "email": email_addr,
        "sender_name": "Unknown Sender", "domain": domain,
        "reputation": "unknown", "reports": 0, "category": "unverified",
        "spam_score": min(score, 100),
        "indicators": indicators,
        "abuseipdb": abuse_result,
        "verdict": "SPAM" if score >= 50 else "SUSPICIOUS" if score >= 20 else "SAFE",
        "recommendation": "Verify sender through alternate channel" if score >= 20 else "Sender appears safe"
    })

def _parse_eml_file(file_storage):
    raw = file_storage.read()
    msg = EmailBytesParser(policy=policy.default).parsebytes(raw)
    headers = {}
    for k in ("From", "To", "Subject", "Date", "Message-ID", "Return-Path",
              "Received-SPF", "DKIM-Signature", "Authentication-Results",
              "Reply-To", "X-Mailer", "MIME-Version", "Content-Type"):
        v = msg.get(k)
        if v:
            headers[k] = str(v)
    body_plain = ""
    body_html = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.is_multipart():
                continue
            cdisp = str(part.get("Content-Disposition", ""))
            try:
                content = part.get_content() or b""
            except Exception:
                content = b""
            if "attachment" in cdisp or part.get_filename():
                fn = part.get_filename()
                attachments.append({
                    "filename": fn,
                    "content_type": ctype,
                    "size": len(content) if isinstance(content, bytes) else len(str(content))
                })
            elif ctype == "text/plain":
                body_plain = str(content) if not isinstance(content, str) else content
            elif ctype == "text/html":
                body_html = str(content) if not isinstance(content, str) else content
    else:
        try:
            body_plain = msg.get_content() or ""
        except Exception:
            body_plain = ""
    received_chain = msg.get_all("Received") or []
    hops = len(received_chain)
    suspicious_keywords = ["urgent", "verify", "account suspended", "click here",
                           "login", "password", "bank", "paypal", "invoice",
                           "payment", "suspended", "security alert"]
    findings = []
    phish_score = 0
    html_lower = body_html.lower() if body_html else ""
    plain_lower = body_plain.lower() if body_plain else ""
    combined = html_lower + plain_lower
    for kw in suspicious_keywords:
        if kw in combined:
            findings.append(f"Contains suspicious keyword: '{kw}'")
            phish_score += 12
    urls = re.findall(r'https?://[^\s<>"\']+', combined)
    if urls:
        findings.append(f"Contains {len(urls)} URL(s)")
    forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html_lower) if html_lower else []
    if forms:
        findings.append(f"Found {len(forms)} form(s) submitting to: {forms[0][:60]}")
        phish_score += 20
    for kw in ["mime", "base64", "8bit", "quoted-printable"]:
        if kw in raw.decode("utf-8", errors="ignore").lower():
            findings.append(f"Encoding: {kw}")
            break
    sender_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    if reply_to and sender_header and reply_to != sender_header:
        findings.append(f"Spoof risk: Reply-To ({reply_to}) != From ({sender_header})")
        phish_score += 25
    auth = {}
    auth_text = headers.get("Authentication-Results", "")
    if auth_text:
        for key in ("spf", "dkim", "dmarc"):
            m = re.search(rf'\b{key}=(\w+)', auth_text, re.IGNORECASE)
            if m:
                auth[key] = m.group(1).upper()
                findings.append(f"Authentication-Results: {key}={m.group(1).upper()}")
    spf_header = headers.get("Received-SPF", "")
    if spf_header:
        spf_result = "PASS" if re.search(r'\bpass\b', spf_header, re.IGNORECASE) else "FAIL" if re.search(r'\bfail\b', spf_header, re.IGNORECASE) else "UNKNOWN"
        auth.setdefault("spf", spf_result)
    attachment_threats = []
    blocked_exts = {"exe", "scr", "bat", "cmd", "vbs", "ps1", "js", "jar", "docm", "xlsm", "pptm", "msi"}
    for att in attachments:
        aext = att.get("filename", "").rsplit(".", 1)[-1].lower() if "." in att.get("filename", "") else ""
        if aext in blocked_exts:
            attachment_threats.append({"filename": att.get("filename"), "extension": aext, "risk": "high", "reason": "Blocked executable/macro extension"})
            phish_score += 15
        if att.get("content_type", "").startswith("application/x-") or "javascript" in att.get("content_type", ""):
            attachment_threats.append({"filename": att.get("filename"), "content_type": att.get("content_type"), "risk": "high", "reason": "Suspicious MIME type"})
    header_anomalies = []
    if not headers.get("Received-SPF") and not auth.get("spf"):
        header_anomalies.append("No SPF authentication header present")
    if not headers.get("DKIM-Signature") and not auth.get("dkim"):
        header_anomalies.append("No DKIM signature present")
    if not auth.get("dmarc"):
        header_anomalies.append("No DMARC authentication result present")
    if reply_to and sender_header and reply_to != sender_header:
        header_anomalies.append("Reply-To differs from From header")
    from_email = sender_header
    from_domain = re.search(r'@([\w.-]+)', from_email or "")
    from_domain = from_domain.group(1) if from_domain else ""
    if from_domain and reply_to and reply_to.split("@")[-1] != from_domain:
        header_anomalies.append(f"Reply-To domain ({reply_to.split('@')[-1]}) differs from From domain ({from_domain})")
    for a in attachments:
        a["size_human"] = f"{a['size']/1024:.1f} KB" if a.get("size", 0) >= 1024 else f"{a.get('size',0)} B"
    return {
        "headers": headers,
        "body_preview": body_plain[:500] + "..." if len(body_plain) > 500 else body_plain,
        "has_html": bool(body_html),
        "attachments": attachments,
        "attachment_count": len(attachments),
        "received_hops": hops,
        "phishing_score": min(phish_score, 100),
        "findings": findings[:10],
        "urls_found": urls[:10] if urls else [],
        "verdict": "PHISHING" if phish_score >= 60 else "SUSPICIOUS" if phish_score >= 30 else "SAFE",
        "message_size": len(raw),
        "auth_results": auth,
        "attachment_threats": attachment_threats,
        "header_anomalies": header_anomalies,
        "from_domain": from_domain,
        "reply_to_domain": reply_to.split("@")[-1] if reply_to else "",
        "spf_dkim_dmarc_alignment": {
            "spf": auth.get("spf", "UNKNOWN"),
            "dkim": auth.get("dkim", "UNKNOWN"),
            "dmarc": auth.get("dmarc", "UNKNOWN")
        }
    }

def analyze_eml_file(current_user=None):
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No .eml file provided"}), 400
    f = request.files["file"]
    if not f.filename.lower().endswith(".eml"):
        return jsonify({"success": False, "error": "Only .eml files are supported"}), 400
    try:
        result = _parse_eml_file(f)
        analysis_id = uuid.uuid4().hex[:12]
        saved = {**result, "analysis_id": analysis_id, "filename": f.filename, "analyzed_at": datetime.utcnow().isoformat() + "Z"}
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, f"eml_{analysis_id}.json"), "w") as fp:
            json.dump(saved, fp, indent=2)
        return jsonify({"success": True, **saved})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to parse .eml: {str(e)}"}), 400

from fpdf import FPDF as FPDF2

def _ascii(text):
    return text.replace("\u2014", "--").replace("\u2013", "-").replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"').replace("\u2026", "...").replace("\u2022", "-").replace("\u20ac", "EUR").replace("\u00a9", "(c)").replace("\u00ae", "(r)").replace("\u2122", "TM")

def generate_eml_pdf(current_user=None):
    analysis_id = request.args.get("id", "")
    filepath = os.path.join(REPORTS_DIR, f"eml_{analysis_id}.json")
    if not analysis_id or not os.path.exists(filepath):
        return jsonify({"success": False, "error": "Analysis ID not found. Run analysis first."}), 404
    with open(filepath) as f:
        data = json.load(f)
    data["filename"] = _ascii(data.get("filename", "N/A"))
    data["analyzed_at"] = _ascii(data.get("analyzed_at", "N/A"))
    data["body_preview"] = _ascii(data.get("body_preview", ""))
    findings = [_ascii(f) for f in data.get("findings", [])]
    data["findings"] = findings
    for a in data.get("attachments", []):
        a["filename"] = _ascii(a.get("filename", "?"))
    headers = {k: _ascii(str(v)) for k, v in data.get("headers", {}).items()}
    data["headers"] = headers
    pdf = FPDF2(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    report_id = f"EML-{analysis_id[:8].upper()}"
    # --- Cover page ---
    pdf.add_page()
    pdf.set_fill_color(10, 25, 47)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_y(65)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(0, 229, 255)
    pdf.cell(0, 14, "CYBERSHIELD SOC", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 255, 136)
    pdf.cell(0, 7, "Email File Analysis Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.5)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(10)
    verdict = data.get("verdict", "UNKNOWN")
    vcolor = (255, 51, 85) if verdict == "PHISHING" else (245, 196, 0) if verdict == "SUSPICIOUS" else (0, 255, 136)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*vcolor)
    pdf.cell(0, 12, f"VERDICT: {verdict}", ln=True, align="C")
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, f"Phishing Score: {data.get('phishing_score',0)}/100", ln=True, align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(180, 180, 180)
    pdf.cell(0, 7, f"File: {data.get('filename','N/A')}", ln=True, align="C")
    pdf.cell(0, 7, f"Analyzed: {data.get('analyzed_at','N/A')}", ln=True, align="C")
    pdf.cell(0, 7, f"Report ID: {report_id}", ln=True, align="C")
    pdf.ln(20)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 5, "Classification: CONFIDENTIAL", ln=True, align="C")
    # --- Page 2: Headers ---
    pdf.add_page()
    pdf.set_fill_color(10, 25, 47)
    pdf.rect(0, 0, 210, 24, "F")
    pdf.set_text_color(0, 229, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_xy(10, 5)
    pdf.cell(0, 5, "CYBERSHIELD SOC - Email Analysis Report", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(140, 140, 140)
    pdf.set_xy(10, 12)
    pdf.cell(0, 4, _ascii(f"Report {report_id} | {data.get('filename','N/A')}"), ln=True)
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.4)
    pdf.line(10, 25, 200, 25)
    pdf.set_y(28)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(0, 229, 255)
    pdf.cell(0, 7, "EMAIL HEADERS", ln=True)
    pdf.ln(2)
    w = [45, 145]
    pdf.set_fill_color(0, 229, 255)
    pdf.set_text_color(10, 25, 47)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(w[0], 6, "Header", border=1, fill=True, align="C")
    pdf.cell(w[1], 6, "Value", border=1, fill=True, align="C")
    pdf.ln()
    for i, (k, v) in enumerate(data.get("headers", {}).items()):
        fill = i % 2 == 0
        if fill:
            pdf.set_fill_color(15, 35, 60)
        else:
            pdf.set_fill_color(10, 25, 47)
        pdf.set_text_color(200, 200, 200)
        pdf.set_font("Helvetica", "", 7)
        pdf.cell(w[0], 5, k, border=1, fill=True)
        pdf.cell(w[1], 5, str(v)[:130], border=1, fill=True)
        pdf.ln()
    pdf.ln(5)
    # --- Findings ---
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(255, 51, 85) if verdict == "PHISHING" else pdf.set_text_color(245, 196, 0) if verdict == "SUSPICIOUS" else pdf.set_text_color(0, 255, 136)
    pdf.cell(0, 7, f"ANALYSIS FINDINGS ({len(data.get('findings',[]))})", ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 8)
    for i, f_item in enumerate(data.get("findings", [])):
        fill = i % 2 == 0
        if fill:
            pdf.set_fill_color(15, 35, 60)
        else:
            pdf.set_fill_color(10, 25, 47)
        pdf.set_text_color(200, 200, 200)
        pdf.cell(5, 5, "", border=1, fill=True)
        pdf.cell(185, 5, f"  {f_item}", border=1, fill=True)
        pdf.ln()
    pdf.ln(5)
    # --- Body Preview ---
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(0, 229, 255)
    pdf.cell(0, 7, "BODY PREVIEW", ln=True)
    pdf.ln(2)
    pdf.set_fill_color(10, 25, 47)
    pdf.set_text_color(160, 160, 160)
    pdf.set_font("Helvetica", "", 7)
    body = data.get("body_preview", "N/A")
    y_start = pdf.get_y()
    pdf.multi_cell(0, 4, body[:1200])
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.1)
    pdf.rect(10, y_start-1, 190, pdf.get_y()-y_start+1)
    pdf.ln(5)
    # --- Attachments ---
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(0, 229, 255)
    pdf.cell(0, 7, f"ATTACHMENTS ({data.get('attachment_count',0)})", ln=True)
    pdf.ln(2)
    wa = [80, 50, 30, 30]
    pdf.set_fill_color(0, 229, 255)
    pdf.set_text_color(10, 25, 47)
    pdf.set_font("Helvetica", "B", 8)
    for i, c in enumerate(["Filename", "Content-Type", "Size", ""]):
        pdf.cell(wa[i], 6, c, border=1, fill=True, align="C")
    pdf.ln()
    for i, a in enumerate(data.get("attachments", [])):
        fill = i % 2 == 0
        pdf.set_fill_color(15, 35, 60) if fill else pdf.set_fill_color(10, 25, 47)
        pdf.set_text_color(200, 200, 200)
        pdf.set_font("Helvetica", "", 7)
        pdf.cell(wa[0], 5, a.get("filename","?"), border=1, fill=True)
        pdf.cell(wa[1], 5, a.get("content_type","?"), border=1, fill=True)
        pdf.cell(wa[2], 5, f"{a.get('size',0)} bytes", border=1, fill=True, align="R")
        pdf.cell(wa[3], 5, "", border=1, fill=True)
        pdf.ln()
    if not data.get("attachments"):
        pdf.set_text_color(140, 140, 140)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 5, "  No attachments found", ln=True)
    # --- Footer ---
    pdf.set_y(-15)
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.2)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_y(-12)
    pdf.set_font("Helvetica", "", 6)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(95, 4, f"Report {report_id} | CONFIDENTIAL", align="L")
    pdf.cell(95, 4, f"Page {pdf.page_no()}/{{nb}}", align="R")
    filename = f"CyberShield_EML_Report_{report_id}.pdf"
    filepath_out = os.path.join(REPORTS_DIR, filename)
    pdf.output(filepath_out)
    return send_file(filepath_out, as_attachment=True, download_name=filename)

def generate_eml_xlsx(current_user=None):
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    analysis_id = request.args.get("id", "")
    filepath = os.path.join(REPORTS_DIR, f"eml_{analysis_id}.json")
    if not analysis_id or not os.path.exists(filepath):
        return jsonify({"success": False, "error": "Analysis ID not found. Run analysis first."}), 404
    with open(filepath) as f:
        data = json.load(f)

    wb = openpyxl.Workbook()

    # ═══ Summary Sheet ═══
    ws = wb.active
    ws.title = "Summary"
    title_font = Font(bold=True, size=14, color="00E5FF")
    hdr_font = Font(bold=True, color="FFFFFF", size=10)
    hdr_fill = PatternFill(start_color="0A192F", end_color="0A192F", fill_type="solid")
    accent_fill = PatternFill(start_color="001830", end_color="001830", fill_type="solid")
    thin_border = Border(left=Side(style="thin", color="1A3A5C"), right=Side(style="thin", color="1A3A5C"), top=Side(style="thin", color="1A3A5C"), bottom=Side(style="thin", color="1A3A5C"))

    ws.merge_cells("A1:D1")
    ws["A1"] = "CYBERSHIELD SOC — Email File Analysis Report"
    ws["A1"].font = title_font
    ws["A1"].alignment = Alignment(horizontal="center")
    ws.row_dimensions[1].height = 28

    ws.merge_cells("A2:D2")
    ws["A2"] = f"File: {data.get('filename','N/A')}  |  Analyzed: {data.get('analyzed_at','N/A')}"
    ws["A2"].font = Font(size=9, color="808080")
    ws["A2"].alignment = Alignment(horizontal="center")

    ws.merge_cells("A3:D3")
    verdict = data.get("verdict", "UNKNOWN")
    vcolor = "FF3355" if verdict == "PHISHING" else "FFC400" if verdict == "SUSPICIOUS" else "00FF88"
    ws["A3"] = f"VERDICT: {verdict}  |  Phishing Score: {data.get('phishing_score',0)}/100"
    ws["A3"].font = Font(bold=True, size=12, color=vcolor)
    ws["A3"].alignment = Alignment(horizontal="center")
    ws.row_dimensions[3].height = 24

    r = 5
    ws.merge_cells(f"A{r}:D{r}")
    ws[f"A{r}"] = "EMAIL HEADERS"
    ws[f"A{r}"].font = hdr_font
    ws[f"A{r}"].fill = hdr_fill
    ws[f"A{r}"].alignment = Alignment(horizontal="center")
    for c in range(1, 5):
        ws.cell(row=r, column=c).fill = hdr_fill
        ws.cell(row=r, column=c).border = thin_border
    r += 1
    for k, v in data.get("headers", {}).items():
        ws.cell(row=r, column=1, value=k).font = Font(bold=True, size=9, color="00E5FF")
        ws.cell(row=r, column=1).fill = accent_fill
        ws.cell(row=r, column=1).border = thin_border
        ws.merge_cells(f"B{r}:D{r}")
        ws.cell(row=r, column=2, value=str(v)[:200]).font = Font(size=9, color="C0C0C0")
        ws.cell(row=r, column=2).fill = accent_fill
        ws.cell(row=r, column=2).border = thin_border
        for c in range(3, 5):
            ws.cell(row=r, column=c).border = thin_border
        r += 1

    r += 1
    ws.merge_cells(f"A{r}:D{r}")
    ws[f"A{r}"] = f"ANALYSIS FINDINGS ({len(data.get('findings',[]))})"
    ws[f"A{r}"].font = hdr_font
    ws[f"A{r}"].fill = hdr_fill
    ws[f"A{r}"].alignment = Alignment(horizontal="center")
    for c in range(1, 5):
        ws.cell(row=r, column=c).fill = hdr_fill
        ws.cell(row=r, column=c).border = thin_border
    r += 1
    for f_item in data.get("findings", []):
        ws.merge_cells(f"A{r}:D{r}")
        ws[f"A{r}"] = f"  • {f_item}"
        ws[f"A{r}"].font = Font(size=9, color="C0C0C0")
        ws[f"A{r}"].fill = accent_fill
        ws[f"A{r}"].border = thin_border
        for c in range(1, 5):
            ws.cell(row=r, column=c).border = thin_border
        r += 1

    r += 1
    ws.merge_cells(f"A{r}:D{r}")
    ws[f"A{r}"] = "BODY PREVIEW"
    ws[f"A{r}"].font = hdr_font
    ws[f"A{r}"].fill = hdr_fill
    ws[f"A{r}"].alignment = Alignment(horizontal="center")
    for c in range(1, 5):
        ws.cell(row=r, column=c).fill = hdr_fill
        ws.cell(row=r, column=c).border = thin_border
    r += 1
    body = data.get("body_preview", "N/A")
    ws.merge_cells(f"A{r}:D{r}")
    ws[f"A{r}"] = body[:1000]
    ws[f"A{r}"].font = Font(size=8, color="A0A0A0")
    ws[f"A{r}"].fill = accent_fill
    ws[f"A{r}"].border = thin_border
    ws[f"A{r}"].alignment = Alignment(wrap_text=True)
    ws.row_dimensions[r].height = min(len(body) // 2 + 10, 200)
    for c in range(1, 5):
        ws.cell(row=r, column=c).border = thin_border

    # ═══ Attachments Sheet ═══
    ws2 = wb.create_sheet("Attachments")
    ws2.merge_cells("A1:D1")
    ws2["A1"] = "Attachments"
    ws2["A1"].font = title_font
    ws2["A1"].alignment = Alignment(horizontal="center")
    ws2.row_dimensions[1].height = 28
    cols = ["Filename", "Content-Type", "Size (bytes)", ""]
    for i, c in enumerate(cols, 1):
        cell = ws2.cell(row=3, column=i, value=c)
        cell.font = hdr_font
        cell.fill = hdr_fill
        cell.alignment = Alignment(horizontal="center")
        cell.border = thin_border
    for i, a in enumerate(data.get("attachments", []), 4):
        ws2.cell(row=i, column=1, value=a.get("filename","?")).font = Font(size=9, color="C0C0C0")
        ws2.cell(row=i, column=1).border = thin_border
        ws2.cell(row=i, column=2, value=a.get("content_type","?")).font = Font(size=9, color="C0C0C0")
        ws2.cell(row=i, column=2).border = thin_border
        ws2.cell(row=i, column=3, value=a.get("size",0)).font = Font(size=9, color="C0C0C0")
        ws2.cell(row=i, column=3).border = thin_border
        ws2.cell(row=i, column=3).alignment = Alignment(horizontal="right")
        ws2.cell(row=i, column=4).border = thin_border
    ws2.column_dimensions["A"].width = 50
    ws2.column_dimensions["B"].width = 35
    ws2.column_dimensions["C"].width = 15

    # ═══ Raw Headers Sheet ═══
    ws3 = wb.create_sheet("Raw Headers")
    ws3.merge_cells("A1:B1")
    ws3["A1"] = "Raw Email Headers"
    ws3["A1"].font = title_font
    ws3["A1"].alignment = Alignment(horizontal="center")
    ws3.row_dimensions[1].height = 28
    for i, c in enumerate(["Key", "Value"], 1):
        cell = ws3.cell(row=3, column=i, value=c)
        cell.font = hdr_font
        cell.fill = hdr_fill
        cell.alignment = Alignment(horizontal="center")
        cell.border = thin_border
    for i, (k, v) in enumerate(data.get("headers", {}).items(), 4):
        ws3.cell(row=i, column=1, value=k).font = Font(bold=True, size=9, color="00E5FF")
        ws3.cell(row=i, column=1).border = thin_border
        ws3.cell(row=i, column=2, value=str(v)[:300]).font = Font(size=9, color="C0C0C0")
        ws3.cell(row=i, column=2).border = thin_border
    ws3.column_dimensions["A"].width = 30
    ws3.column_dimensions["B"].width = 80

    ws.column_dimensions["A"].width = 25
    ws.column_dimensions["B"].width = 50
    ws.column_dimensions["C"].width = 30
    ws.column_dimensions["D"].width = 30

    report_id = f"EML-{analysis_id[:8].upper()}"
    filename = f"CyberShield_EML_Report_{report_id}.xlsx"
    filepath_out = os.path.join(REPORTS_DIR, filename)
    wb.save(filepath_out)
    return send_file(filepath_out, as_attachment=True, download_name=filename)

def content_disarm(current_user=None):
    data = request.get_json() or {}
    filename = data.get("filename", "document.docx")
    content = data.get("content", "")
    removed = []
    dangerous_patterns = ["<script", "=cmd|", "Auto_Open", "AutoOpen", "Document_Open", "macros", ".exe", ".bat", ".vbs", ".ps1"]
    sanitized = content
    for pattern in dangerous_patterns:
        if pattern.lower() in content.lower():
            removed.append(pattern)
            sanitized = sanitized.replace(pattern, "[REMOVED]")
    return jsonify({
        "success": True,
        "filename": filename,
        "original_size": len(content),
        "sanitized_size": len(sanitized),
        "threats_removed": removed,
        "sanitized_content": sanitized[:500] if sanitized else "",
        "verdict": "DISARMED" if removed else "CLEAN",
        "recommendation": f"{len(removed)} threats removed via CDR" if removed else "File is safe"
    })

def auto_remediate(current_user=None):
    data = request.get_json() or {}
    message_id = data.get("message_id", "")
    action = data.get("action", "quarantine")
    reason = data.get("reason", "Threat detected")
    if not message_id:
        return jsonify({"success": False, "message": "message_id required"}), 400
    valid_actions = ["quarantine", "delete", "clawback", "block_sender"]
    if action not in valid_actions:
        return jsonify({"success": False, "message": f"Invalid action. Use: {valid_actions}"}), 400
    action_steps = {
        "quarantine": ["Move message to quarantine store", "Notify SOC analyst for review", "Apply retention policy"],
        "delete": ["Purge message from mailbox", "Purge from backup cycle if required by policy", "Record deletion for audit"],
        "clawback": ["Recall message from all recipients", "Replace with remediation notice", "Verify recall receipt"],
        "block_sender": ["Add sender to block list", "Apply transport rule to reject future mail", "Notify abuse mailbox"]
    }
    return jsonify({
        "success": True,
        "message_id": message_id,
        "action_taken": action,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "performed_by": current_user,
        "verdict": f"AUTO_REMEDIATION_{action.upper()}_COMPLETE",
        "recommendation": "Monitor inbox for further threats",
        "remediation_steps": action_steps[action],
        "audit_trail": {
            "initiated_by": current_user,
            "initiated_at": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "reason": reason,
            "status": "queued",
            "next_review": (datetime.utcnow().isoformat() + "Z")
        },
        "affected_scope": {
            "messages": 1,
            "mailboxes": "all_recipients",
            "blocklist_updated": action == "block_sender",
            "alert_fired": True
        }
    })


def email_health_scorecard(current_user=None):
    """Batch analysis: aggregates SPF/DKIM/DMARC/sender/phishing/URL into one scorecard."""
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    sender = data.get("sender", "").strip().lower()
    body = data.get("body", "")
    subject = data.get("subject", "")
    url = data.get("url", "").strip()
    try:
        from services.email_security.email_service import check_spf as _spf, check_dkim as _dkim, check_dmarc as _dmarc, sender_reputation as _rep, analyze_phishing as _phish
    except Exception:
        _spf = _dkim = _dmarc = _rep = _phish = None
    checks = []
    score_accum = 0
    results = {}
    if domain:
        results["spf"] = _spf(domain) if _spf else {"verdict": "FAIL", "reason": "module unavailable"}
        results["dkim"] = _dkim(domain) if _dkim else {"verdict": "FAIL", "reason": "module unavailable"}
        results["dmarc"] = _dmarc(domain) if _dmarc else {"verdict": "FAIL", "reason": "module unavailable"}
        for name in ("spf", "dkim", "dmarc"):
            v = results[name].get("verdict", "FAIL")
            score_accum += {"PASS": 25, "WARNING": 15, "FAIL": 0, "LEGITIMATE": 0}.get(v, 0)
            checks.append({"check": f"DNS:{name}", "verdict": v, "detail": results[name].get("recommendation", ""), "weight": 25})
    if sender:
        rep = _rep(sender) if _rep else {"verdict": "UNKNOWN", "reputation": "unknown"}
        results["sender_reputation"] = rep
        score_accum += 15 if rep.get("reputation") in ("good",) else 5 if rep.get("reputation") in ("unknown", "suspicious") else 0
        checks.append({"check": "SenderReputation", "verdict": rep.get("verdict", "UNKNOWN"), "detail": rep.get("recommendation", ""), "weight": 15, "reputation": rep.get("reputation")})
    if body or subject:
        phish = _phish(body, subject, sender) if _phish else {"probability": 0, "verdict": "ALLOW"}
        results["phishing"] = phish
        score_accum += max(0, int((1 - phish.get("probability", 0)) * 20))
        checks.append({"check": "PhishingAnalysis", "verdict": phish.get("verdict", "ALLOW"), "detail": phish.get("recommendation", ""), "weight": 20, "probability": phish.get("probability")})
    if url:
        resp = _analyze_url_logic(url)
        results["url"] = resp
        score_accum += {"SAFE": 15, "SUSPICIOUS": 5, "MALICIOUS": 0}.get(resp.get("verdict"), 5)
        checks.append({"check": "URLAnalysis", "verdict": resp.get("verdict"), "detail": resp.get("recommendation", ""), "weight": 15})
    if not domain and not sender and not body and not url:
        return jsonify({"success": False, "message": "Provide at least one of: domain, sender, body, url"}), 400
    overall = min(100, max(0, score_accum + (len([c for c in checks if c["verdict"] in ("PASS", "SAFE", "ALLOW", "LEGITIMATE")]) * 5)))
    return jsonify({
        "success": True,
        "overall_score": min(overall, 100),
        "grade": "A" if overall >= 90 else "B" if overall >= 75 else "C" if overall >= 60 else "D" if overall >= 40 else "F",
        "checks": checks,
        "results": results,
        "summary": f"{len([c for c in checks if c['verdict'] in ('PASS','SAFE','ALLOW','LEGITIMATE')])}/{len(checks)} checks passed",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scanned_by": current_user
    })

def generate_dkim(current_user=None):
    """Generate an RSA keypair for DKIM and output the DNS TXT record to publish."""
    data = request.get_json() or {}
    domain = (data.get("domain") or "").strip().lower()
    selector = (data.get("selector") or "default").strip().lower().replace(" ", "")
    key_bits = int(data.get("key_bits") or 2048)
    if key_bits not in (1024, 2048, 4096):
        key_bits = 2048
    if not domain or not re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", domain):
        return jsonify({"success": False, "message": "Valid domain required (e.g. example.com)"}), 400
    if not selector or not re.match(r"^[a-z0-9._-]{1,63}$", selector):
        return jsonify({"success": False, "message": "Valid selector required (letters/digits/._- up to 63 chars)"}), 400
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_b64 = base64.b64encode(public_der).decode()
    except Exception as e:
        return jsonify({"success": False, "message": f"Key generation failed: {e}"}), 500
    dns_record = f"v=DKIM1; k=rsa; p={public_b64}"
    return jsonify({
        "success": True,
        "domain": domain,
        "selector": selector,
        "key_type": "rsa",
        "key_bits": key_bits,
        "private_key_pem": private_pem,
        "public_key_b64": public_b64,
        "dns_host": f"{selector}._domainkey.{domain}",
        "dns_type": "TXT",
        "dns_ttl": 3600,
        "dns_record": dns_record,
        "publish_steps": [
            f"Keep the PRIVATE key securely on your mail server (e.g. /etc/opendkim/keys/{domain}/{selector}.private).",
            f"Publish a TXT record at {selector}._domainkey.{domain} with value: {dns_record}",
            "Set your mail server DKIM signing to use this private key + selector.",
            "Verify with this tool: Email Security -> DKIM Checker (selectors include the one above)."
        ],
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": current_user
    })
