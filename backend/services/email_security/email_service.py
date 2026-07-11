import re
import json
import hashlib
import requests
import dns.resolver
import dns.exception
from datetime import datetime
from services._shared.siem_logger import log_event
from config.settings import VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_KEY

DNS_AVAILABLE = True
ALLOW_LIST = set()
BLOCK_LIST = set()

# Lightweight ML phishing classifier using keyword + pattern weights
PHISHING_WEIGHTS = {
    "urgent": 0.15, "action required": 0.12, "verify your account": 0.18,
    "click here": 0.10, "login": 0.08, "password expired": 0.15,
    "update your information": 0.14, "suspended": 0.13, "unauthorized login": 0.12,
    "security alert": 0.10, "confirm your identity": 0.14, "bank": 0.06,
    "paypal": 0.08, "amazon": 0.05, "irs": 0.12, "refund": 0.10,
    "lottery": 0.18, "inheritance": 0.20, "prince": 0.15, "wire transfer": 0.16,
    "western union": 0.14, "money gram": 0.14, "cryptocurrency": 0.08,
    "bitcoin": 0.08, "reset your password": 0.12, "account locked": 0.13,
    "unusual activity": 0.12, "sign in": 0.08, "dear customer": 0.10,
    "dear user": 0.10, "click the link": 0.14, "temporary suspension": 0.12,
    "security measure": 0.08, "within 24 hours": 0.10, "failure to comply": 0.14,
}

def _phishing_ml_score(email_body, subject=""):
    text = (subject + " " + (email_body or "")).lower()
    score = 0.0
    matched_patterns = []
    for pattern, weight in PHISHING_WEIGHTS.items():
        if pattern in text:
            score += weight
            matched_patterns.append(pattern)
    link_count = len(re.findall(r'https?://\S+', text))
    score += min(link_count * 0.02, 0.10)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.download', '.review', '.work', '.click', '.loan', '.date', '.men', '.win', '.bid', '.trade', '.webcam', '.science', '.party']
    for tld in suspicious_tlds:
        if tld in text:
            score += 0.05
    urgency_words = ["immediately", "urgent", "asap", "without delay", "now", "expires", "limited time"]
    for word in urgency_words:
        if word in text:
            score += 0.03
    if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text):
        score += 0.05
    score = min(score, 1.0)
    return score, matched_patterns

def _resolve_txt(domain):
    if not DNS_AVAILABLE:
        return None, "dnspython not installed"
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return [a.to_text().strip('"') for a in answers], None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None
    except dns.exception.Timeout:
        return None, "DNS query timed out"
    except Exception as e:
        return None, str(e)

def _check_gsb(url):
    if not GOOGLE_SAFE_BROWSING_KEY:
        return None
    try:
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}", json={"client": {"clientId": "cybershield", "clientVersion": "6.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}, timeout=5)
        if r.ok and r.json().get("matches"):
            return [m["threatType"] for m in r.json()["matches"]]
        return []
    except Exception:
        return None

def check_spf(domain):
    records, error = _resolve_txt(domain)
    spf_record = None
    if records:
        for r in records:
            if r.startswith("v=spf1"):
                spf_record = r
                break
    return {"domain": domain, "spf_found": spf_record is not None, "spf_record": (spf_record[:300] + "...") if spf_record and len(spf_record) > 300 else spf_record, "dns_error": error, "verdict": "PASS" if spf_record else "FAIL", "recommendation": "Publish SPF record" if not spf_record else "SPF configured"}

def check_dkim(domain, selector=None):
    if selector:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records, error = _resolve_txt(dkim_domain)
        key_found = bool(records and any(r.startswith("v=DKIM1") for r in records))
        dkim_record = (records[0][:300] + "...") if records and len(records[0]) > 300 else (records[0] if records else "Not found")
        return {"domain": domain, "selector": selector, "dkim_key_found": key_found, "dkim_record": dkim_record, "dns_error": error, "verdict": "PASS" if key_found else "FAIL", "recommendation": "Publish DKIM key" if not key_found else "DKIM active"}
    common_selectors = ["google", "default", "dkim", "mail", "selector1", "selector2", "s1", "s2", "protonmail", "sendgrid"]
    for sel in common_selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        records, _ = _resolve_txt(dkim_domain)
        if records and any(r.startswith("v=DKIM1") for r in records):
            dkim_record = records[0][:300] + "..." if len(records[0]) > 300 else records[0]
            return {"domain": domain, "selector": sel, "dkim_key_found": True, "dkim_record": dkim_record, "dns_error": None, "verdict": "PASS", "recommendation": f"DKIM active (selector: {sel})"}
    return {"domain": domain, "selector": "default", "dkim_key_found": False, "dkim_record": "Not found", "dns_error": None, "verdict": "FAIL", "recommendation": "Publish DKIM key"}

def check_dmarc(domain):
    records, error = _resolve_txt(f"_dmarc.{domain}")
    policy = "v=DMARC1; p=none"
    if records:
        for r in records:
            if r.startswith("v=DMARC1"):
                policy = r
                break
    p_match = re.search(r'p=(\w+)', policy)
    policy_type = p_match.group(1) if p_match else "none"
    pct_match = re.search(r'pct=(\d+)', policy)
    pct = int(pct_match.group(1)) if pct_match else 100
    return {"domain": domain, "dmarc_found": policy != "v=DMARC1; p=none", "policy": policy[:300], "policy_type": policy_type, "pct": pct, "dns_error": error, "verdict": "PASS" if policy != "v=DMARC1; p=none" else "FAIL", "recommendation": "Publish DMARC policy" if not policy != "v=DMARC1; p=none" else f"DMARC policy: {policy_type} (pct={pct})"}

def analyze_phishing(email_body, subject="", sender="", reply_to=""):
    probability, matched = _phishing_ml_score(email_body, subject)
    is_phishing = probability > 0.85
    gsb_result = None
    urls = re.findall(r'https?://\S+', (email_body or "") + " " + subject)
    if urls:
        gsb_result = _check_gsb(urls[0])
    if is_phishing:
        log_event("PHISHING_DETECTED", "HIGH", "email", {"subject": subject, "sender": sender, "probability": probability}, sender)
    return {
        "success": True,
        "probability": round(probability, 4),
        "is_phishing": is_phishing,
        "verdict": "BLOCK" if is_phishing else "ALLOW",
        "matched_patterns": matched,
        "gsb_threats": gsb_result,
        "recommendation": "Block and quarantine immediately" if is_phishing else "No phishing indicators",
        "classification": "phishing" if is_phishing else ("suspicious" if probability > 0.60 else "clean"),
        "block_threshold": 0.85
    }

def check_allow_block(sender_email):
    sender_lower = sender_email.lower()
    if sender_lower in BLOCK_LIST:
        return "block"
    if sender_lower in ALLOW_LIST:
        return "allow"
    return "unknown"

def add_to_allow_list(sender):
    ALLOW_LIST.add(sender.lower())
    log_event("ALLOW_LIST_ADD", "INFO", "email", {"sender": sender})
    return True

def add_to_block_list(sender):
    BLOCK_LIST.add(sender.lower())
    log_event("BLOCK_LIST_ADD", "INFO", "email", {"sender": sender})
    return True

def content_disarm(content):
    stripped = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
    stripped = re.sub(r'javascript\s*:', '', stripped, flags=re.IGNORECASE)
    stripped = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', stripped, flags=re.IGNORECASE)
    stripped = re.sub(r'<object[^>]*>.*?</object>', '', stripped, flags=re.IGNORECASE | re.DOTALL)
    return {"original_size": len(content), "sanitized_size": len(stripped), "sanitized_content": stripped[:2000], "verdict": "SANITIZED"}

def sender_reputation(email_addr, sender_ip=""):
    local_part, domain = email_addr.split("@", 1) if "@" in email_addr else ("", email_addr)
    score = 0
    spam_domains = ["mailinator.com", "tempmail.com", "guerrillamail.com", "yopmail.com", "sharklasers.com", "throwaway.email"]
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".download", ".review"]
    known_bad = {"attacker@evil.com": {"reports": 456, "category": "phishing"}, "spammer@spam.com": {"reports": 892, "category": "spam"}}
    known_good = {"noreply@google.com": {"name": "Google"}, "security@paypal.com": {"name": "PayPal"}, "noreply@microsoft.com": {"name": "Microsoft"}}
    if email_addr in known_bad:
        score = 85
        return {"email": email_addr, "domain": domain, "sender_name": email_addr, "reputation": "bad", "spam_score": score, "reports": known_bad[email_addr]["reports"], "category": known_bad[email_addr]["category"], "verdict": "SPAM", "recommendation": "Block sender"}
    if email_addr in known_good:
        score = 5
        return {"email": email_addr, "domain": domain, "sender_name": known_good[email_addr]["name"], "reputation": "good", "spam_score": score, "reports": 0, "category": "official", "verdict": "SAFE", "recommendation": "Sender is trusted"}
    if any(sd in domain for sd in spam_domains):
        score += 50
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 30
            break
    return {"email": email_addr, "domain": domain, "spam_score": min(score, 100), "reputation": "bad" if score > 40 else "suspicious" if score > 20 else "good", "verdict": "SPAM" if score > 40 else "SUSPICIOUS" if score > 20 else "SAFE", "recommendation": "Monitor sender" if score > 20 else "No issues"}
