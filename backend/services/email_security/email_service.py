import re
import json
import hashlib
import base64
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

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.download',
                   '.review', '.work', '.click', '.loan', '.date', '.men', '.win',
                   '.bid', '.trade', '.webcam', '.science', '.party', '.rest', '.monster']
URGENCY_WORDS = ["immediately", "urgent", "asap", "without delay", "now", "expires", "limited time"]
SPAM_DOMAINS = ["mailinator.com", "tempmail.com", "guerrillamail.com", "yopmail.com",
                "sharklasers.com", "throwaway.email", "getnada.com", "10minutemail.com",
                "maildrop.cc", "trashmail.com", "0-mail.com", "discard.email"]


def _phishing_ml_score(email_body, subject=""):
    """Return (score, matched_patterns). Kept for compatibility."""
    score, breakdown = _phishing_ml_breakdown(email_body, subject)
    return score, breakdown.get("matched_patterns", [])


def _phishing_ml_breakdown(email_body, subject=""):
    """Full phishing heuristic breakdown with per-category detail."""
    text = (subject + " " + (email_body or "")).lower()
    score = 0.0
    matched_patterns = []
    keyword_score = 0.0
    link_score = 0.0
    tld_score = 0.0
    urgency_score = 0.0
    phone_score = 0.0
    for pattern, weight in PHISHING_WEIGHTS.items():
        if pattern in text:
            keyword_score += weight
            matched_patterns.append({"pattern": pattern, "weight": weight, "severity": "high" if weight >= 0.14 else "medium" if weight >= 0.10 else "low"})
    link_count = len(re.findall(r'https?://\S+', text))
    link_score += min(link_count * 0.02, 0.10)
    for tld in SUSPICIOUS_TLDS:
        if tld in text:
            tld_score += 0.05
    for word in URGENCY_WORDS:
        if word in text:
            urgency_score += 0.03
    if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text):
        phone_score += 0.05
    score = keyword_score + link_score + tld_score + urgency_score + phone_score
    score = min(score, 1.0)
    return score, {
        "score": score,
        "matched_patterns": matched_patterns,
        "link_count": link_count,
        "keyword_score": round(keyword_score, 4),
        "link_score": round(link_score, 4),
        "tld_score": round(tld_score, 4),
        "urgency_score": round(urgency_score, 4),
        "phone_score": round(phone_score, 4),
    }


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


def _resolve_txt_detail(domain):
    """Return (records, error, ttl) for TXT records."""
    if not DNS_AVAILABLE:
        return None, "dnspython not installed", None
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        ttl = answers.rrset.ttl if answers.rrset is not None else None
        return [a.to_text().strip('"') for a in answers], None, ttl
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None, None
    except dns.exception.Timeout:
        return None, "DNS query timed out", None
    except Exception as e:
        return None, str(e), None


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


def _parse_spf_record(record):
    """Parse an SPF record into individual mechanisms."""
    tokens = record.split()
    mechanisms = []
    for tok in tokens:
        if tok == "v=spf1":
            mechanisms.append({"token": tok, "type": "version", "value": "spf1", "note": "SPF version identifier"})
        elif tok.startswith("ip4:"):
            value = tok.split(":", 1)[1]
            mechanisms.append({"token": tok, "type": "ip4", "value": value, "note": f"Authorizes IPv4 {value}"})
        elif tok.startswith("ip6:"):
            value = tok.split(":", 1)[1]
            mechanisms.append({"token": tok, "type": "ip6", "value": value, "note": f"Authorizes IPv6 {value}"})
        elif tok.startswith("include:"):
            value = tok.split(":", 1)[1]
            mechanisms.append({"token": tok, "type": "include", "value": value, "note": f"Delegates to SPF policy of {value}"})
        elif tok.startswith("redirect="):
            value = tok.split("=", 1)[1]
            mechanisms.append({"token": tok, "type": "redirect", "value": value, "note": f"Redirects evaluation to {value}"})
        elif tok.startswith("exp="):
            value = tok.split("=", 1)[1]
            mechanisms.append({"token": tok, "type": "exp", "value": value, "note": "Explanatory text lookup"})
        elif tok == "a":
            mechanisms.append({"token": tok, "type": "a", "value": "", "note": "Authorizes domain A record"})
        elif tok.startswith("a:"):
            value = tok.split(":", 1)[1]
            mechanisms.append({"token": tok, "type": "a", "value": value, "note": f"Authorizes A record of {value}"})
        elif tok == "mx":
            mechanisms.append({"token": tok, "type": "mx", "value": "", "note": "Authorizes MX hosts"})
        elif tok.startswith("mx:"):
            value = tok.split(":", 1)[1]
            mechanisms.append({"token": tok, "type": "mx", "value": value, "note": f"Authorizes MX hosts of {value}"})
        elif tok == "ptr":
            mechanisms.append({"token": tok, "type": "ptr", "value": "", "note": "PTR-based lookup (deprecated, discouraged)"})
        elif tok == "exists":
            mechanisms.append({"token": tok, "type": "exists", "value": "", "note": "Arbitrary existence query"})
        elif tok.startswith("exists:"):
            value = tok.split(":", 1)[1]
            mechanisms.append({"token": tok, "type": "exists", "value": value, "note": f"Existence query {value}"})
        elif tok in ("~all", "-all", "+all", "?all"):
            qualifier = tok[0] if len(tok) > 1 else "+"
            qual_name = {"~": "SOFTFAIL", "-": "HARDFAIL", "+": "PASS", "?": "NEUTRAL"}.get(qualifier, "PASS")
            mechanisms.append({"token": tok, "type": "all", "value": tok, "note": f"All mechanism: {qual_name}"})
        else:
            mechanisms.append({"token": tok, "type": "unknown", "value": tok, "note": "Unrecognized SPF token"})
    return mechanisms


def _get_all_mechanism(record):
    if not record:
        return None
    for tok in record.split():
        if tok in ("~all", "-all", "+all", "?all"):
            return {"token": tok, "qualifier": tok[0], "meaning": {"~": "SOFTFAIL (accept, flag)", "-": "HARDFAIL (reject)", "+": "PASS (accept)", "?": "NEUTRAL"}.get(tok[0], "PASS")}
    return None


def check_spf(domain):
    records, error, ttl = _resolve_txt_detail(domain)
    spf_record = None
    if records:
        for r in records:
            if r.startswith("v=spf1"):
                spf_record = r
                break
    mechanisms = _parse_spf_record(spf_record) if spf_record else []
    all_mech = _get_all_mechanism(spf_record)
    has_include = any(m["type"] == "include" for m in mechanisms)
    has_ptr = any(m["type"] == "ptr" for m in mechanisms)
    total_allowed = sum(1 for m in mechanisms if m["type"] in ("ip4", "ip6", "a", "mx", "include", "exists"))
    policy_quality = "GOOD"
    notes = []
    if not spf_record:
        policy_quality = "MISSING"
    elif all_mech is None:
        policy_quality = "WEAK"
        notes.append("SPF record has no 'all' mechanism — unknown senders can pass")
    elif all_mech["qualifier"] == "~":
        notes.append("Softfail policy: unauthorized mail accepted but flagged (recommend '-all')")
    elif all_mech["qualifier"] == "+":
        notes.append("Permissive '+all' policy — SPF provides no real protection")
    elif all_mech["qualifier"] == "-":
        notes.append("Hardfail policy: unauthorized mail rejected")
    if has_ptr:
        notes.append("PTR mechanism is deprecated by RFC 7208 and should be removed")
    if has_include:
        notes.append("Record includes one or more include: delegations")
    if not spf_record:
        notes.append("SPF is completely absent — spoofing protection disabled")
    return {"domain": domain, "spf_found": spf_record is not None, "spf_record": (spf_record[:300] + "...") if spf_record and len(spf_record) > 300 else spf_record, "dns_error": error, "verdict": "PASS" if spf_record else "FAIL", "recommendation": "Publish SPF record" if not spf_record else "SPF configured", "record_count": len(records) if records else 0, "dns_ttl": ttl, "mechanisms": mechanisms, "all_mechanism": all_mech, "has_include": has_include, "total_authorized_entries": total_allowed, "policy_quality": policy_quality, "policy_notes": notes}


def _dkim_key_info(record):
    """Estimate key type and bit strength from a DKIM public key record."""
    if not record:
        return None, None, None
    k_match = re.search(r'\bk=(\w+)', record)
    key_type = k_match.group(1) if k_match else "rsa"
    p_match = re.search(r'\bp=([A-Za-z0-9+/=]+)', record)
    if key_type == "ed25519":
        return key_type, 256, "ED25519 signature (curve25519, 256-bit)"
    if p_match:
        try:
            raw = base64.b64decode(p_match.group(1) + "==")
            bits = (len(raw) - 19) * 8
            if bits > 0:
                return key_type, bits, f"RSA public key, {bits}-bit modulus"
        except Exception:
            pass
    return key_type, None, "Public key present; size could not be determined"


def check_dkim(domain, selector=None):
    common_selectors = ["google", "default", "dkim", "mail", "selector1", "selector2", "s1", "s2", "protonmail", "sendgrid"]
    selectors_tested = []
    if selector:
        selectors_tested = [selector]
        dkim_domain = f"{selector}._domainkey.{domain}"
        records, error, ttl = _resolve_txt_detail(dkim_domain)
        key_found = bool(records and any(r.startswith("v=DKIM1") for r in records))
        dkim_record = (records[0][:300] + "...") if records and len(records[0]) > 300 else (records[0] if records else "Not found")
        key_type, key_bits, key_note = _dkim_key_info(records[0] if records else None)
        return {"domain": domain, "selector": selector, "dkim_key_found": key_found, "dkim_record": dkim_record, "dns_error": error, "verdict": "PASS" if key_found else "FAIL", "recommendation": "Publish DKIM key" if not key_found else "DKIM active", "selectors_tested": selectors_tested, "dns_ttl": ttl, "key_type": key_type, "key_bits": key_bits, "key_note": key_note}
    for sel in common_selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        records, error, ttl = _resolve_txt_detail(dkim_domain)
        selectors_tested.append(sel)
        if records and any(r.startswith("v=DKIM1") for r in records):
            dkim_record = records[0][:300] + "..." if len(records[0]) > 300 else records[0]
            key_type, key_bits, key_note = _dkim_key_info(records[0])
            return {"domain": domain, "selector": sel, "dkim_key_found": True, "dkim_record": dkim_record, "dns_error": None, "verdict": "PASS", "recommendation": f"DKIM active (selector: {sel})", "selectors_tested": selectors_tested, "dns_ttl": ttl, "key_type": key_type, "key_bits": key_bits, "key_note": key_note}
    return {"domain": domain, "selector": "default", "dkim_key_found": False, "dkim_record": "Not found", "dns_error": None, "verdict": "FAIL", "recommendation": "Publish DKIM key", "selectors_tested": selectors_tested, "dns_ttl": None, "key_type": None, "key_bits": None, "key_note": "No DKIM key published under common selectors"}


def _parse_dmarc_tags(record):
    tags = {}
    for tok in record.split(";"):
        tok = tok.strip()
        if "=" in tok:
            k, v = tok.split("=", 1)
            tags[k.strip()] = v.strip()
    return tags


def check_dmarc(domain):
    records, error, ttl = _resolve_txt_detail(f"_dmarc.{domain}")
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
    tags = _parse_dmarc_tags(policy)
    subdomain_policy = tags.get("sp", "same-as-domain")
    rua = tags.get("rua", "")
    ruf = tags.get("ruf", "")
    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")
    fo = tags.get("fo", "0")
    policy_level = {"reject": 3, "quarantine": 2, "none": 1}.get(policy_type, 0)
    guidance = []
    if policy_type == "none":
        guidance.append("Policy 'none' only monitors — no enforcement")
    elif policy_type == "quarantine":
        guidance.append("Failing mail is sent to spam/quarantine")
    elif policy_type == "reject":
        guidance.append("Failing mail is rejected outright")
    if not rua:
        guidance.append("No rua (aggregate report) address configured")
    if not ruf:
        guidance.append("No ruf (forensic report) address configured")
    if pct < 100:
        guidance.append(f"Enforcement applies to only {pct}% of traffic")
    alignment_note = {"r": "Relaxed alignment", "s": "Strict alignment"}.get(adkim, adkim)
    return {"domain": domain, "dmarc_found": policy != "v=DMARC1; p=none", "policy": policy[:300], "policy_type": policy_type, "pct": pct, "dns_error": error, "verdict": "PASS" if policy != "v=DMARC1; p=none" else "FAIL", "recommendation": "Publish DMARC policy" if not policy != "v=DMARC1; p=none" else f"DMARC policy: {policy_type} (pct={pct})", "dns_ttl": ttl, "subdomain_policy": subdomain_policy, "rua": rua, "ruf": ruf, "adkim": adkim, "aspf": aspf, "alignment_note": alignment_note, "failure_options": fo, "policy_level": policy_level, "guidance": guidance}


def analyze_phishing(email_body, subject="", sender="", reply_to=""):
    probability, breakdown = _phishing_ml_breakdown(email_body, subject)
    is_phishing = probability > 0.85
    gsb_result = None
    urls = re.findall(r'https?://\S+', (email_body or "") + " " + subject)
    if urls:
        gsb_result = _check_gsb(urls[0])
    risk_factors = []
    for m in breakdown["matched_patterns"]:
        risk_factors.append({"factor": f"Phishing keyword '{m['pattern']}'", "severity": m["severity"], "weight": m["weight"]})
    if urls:
        risk_factors.append({"factor": f"{len(urls)} URL(s) present in message", "severity": "medium" if len(urls) > 1 else "low", "weight": min(len(urls) * 0.02, 0.10)})
    for tld in SUSPICIOUS_TLDS:
        if tld in (email_body or "").lower() + subject.lower():
            risk_factors.append({"factor": f"Suspicious TLD '{tld}' in message", "severity": "medium", "weight": 0.05})
            break
    if sender and reply_to and sender != reply_to:
        risk_factors.append({"factor": f"Reply-To ({reply_to}) differs from sender ({sender})", "severity": "high", "weight": 0.15})
    if gsb_result:
        risk_factors.append({"factor": f"Google Safe Browsing flagged URL: {', '.join(gsb_result)}", "severity": "critical", "weight": 0.30})
    if is_phishing:
        log_event("PHISHING_DETECTED", "HIGH", "email", {"subject": subject, "sender": sender, "probability": probability}, sender)
    return {
        "success": True,
        "probability": round(probability, 4),
        "is_phishing": is_phishing,
        "verdict": "BLOCK" if is_phishing else "ALLOW",
        "matched_patterns": [m["pattern"] for m in breakdown["matched_patterns"]],
        "gsb_threats": gsb_result,
        "recommendation": "Block and quarantine immediately" if is_phishing else "No phishing indicators",
        "classification": "phishing" if is_phishing else ("suspicious" if probability > 0.60 else "clean"),
        "block_threshold": 0.85,
        "score_breakdown": {k: v for k, v in breakdown.items() if k in ("keyword_score", "link_score", "tld_score", "urgency_score", "phone_score")},
        "link_count": breakdown["link_count"],
        "urls_found": urls[:10],
        "risk_factors": risk_factors,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
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
    original = content
    stripped = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
    stripped = re.sub(r'javascript\s*:', '', stripped, flags=re.IGNORECASE)
    stripped = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', stripped, flags=re.IGNORECASE)
    stripped = re.sub(r'<object[^>]*>.*?</object>', '', stripped, flags=re.IGNORECASE | re.DOTALL)
    removed_items = []
    if re.search(r'<script[^>]*>.*?</script>', original, flags=re.IGNORECASE | re.DOTALL):
        removed_items.append("inline <script> blocks")
    if re.search(r'javascript\s*:', original, flags=re.IGNORECASE):
        removed_items.append("javascript: URI schemes")
    if re.search(r'on\w+\s*=\s*["\'][^"\']*["\']', original, flags=re.IGNORECASE):
        removed_items.append("inline event handlers (onload/onclick/etc)")
    if re.search(r'<object[^>]*>.*?</object>', original, flags=re.IGNORECASE | re.DOTALL):
        removed_items.append("<object> embed elements")
    stripped_forms = re.findall(r'<form[^>]*>', original, re.IGNORECASE)
    active_content = re.findall(r'(?:<script|javascript:|on\w+\s*=|<\s*object)', original, re.IGNORECASE)
    return {"original_size": len(content), "sanitized_size": len(stripped), "sanitized_content": stripped[:2000], "verdict": "SANITIZED", "techniques_applied": ["strip_scripts", "remove_javascript_uri", "remove_event_handlers", "remove_object_embed"], "items_removed": removed_items, "active_content_detected": len(active_content), "forms_detected": len(stripped_forms), "analysis_id": hashlib.md5(content.encode()).hexdigest()[:12]}


def sender_reputation(email_addr, sender_ip=""):
    local_part, domain = email_addr.split("@", 1) if "@" in email_addr else ("", email_addr)
    score = 0
    spam_domains = ["mailinator.com", "tempmail.com", "guerrillamail.com", "yopmail.com", "sharklasers.com", "throwaway.email"]
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".download", ".review"]
    known_bad = {"attacker@evil.com": {"reports": 456, "category": "phishing"}, "spammer@spam.com": {"reports": 892, "category": "spam"}}
    known_good = {"noreply@google.com": {"name": "Google"}, "security@paypal.com": {"name": "PayPal"}, "noreply@microsoft.com": {"name": "Microsoft"}}
    checks = []
    if email_addr in known_bad:
        score = 85
        return {"email": email_addr, "domain": domain, "sender_name": email_addr, "reputation": "bad", "spam_score": score, "reports": known_bad[email_addr]["reports"], "category": known_bad[email_addr]["category"], "verdict": "SPAM", "recommendation": "Block sender", "indicators": [f"Known malicious sender — {known_bad[email_addr]['reports']} reports ({known_bad[email_addr]['category']})"], "check_summary": {"disposable_domain": False, "suspicious_tld": False, "lookalike_brand": False, "threat_intel": "known_bad"}}
    if email_addr in known_good:
        score = 5
        return {"email": email_addr, "domain": domain, "sender_name": known_good[email_addr]["name"], "reputation": "good", "spam_score": score, "reports": 0, "category": "official", "verdict": "SAFE", "recommendation": "Sender is trusted", "indicators": [f"Verified official sender ({known_good[email_addr]['name']})"], "check_summary": {"disposable_domain": False, "suspicious_tld": False, "lookalike_brand": False, "threat_intel": "known_good"}}
    if any(sd in domain for sd in spam_domains):
        score += 50
        checks.append({"check": "disposable_domain", "flagged": True, "detail": "Disposable/temporary email domain"})
    else:
        checks.append({"check": "disposable_domain", "flagged": False, "detail": "Not a known disposable domain"})
    tld_flag = False
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 30
            tld_flag = True
            checks.append({"check": "suspicious_tld", "flagged": True, "detail": f"Suspicious TLD: {tld}"})
            break
    if not tld_flag:
        checks.append({"check": "suspicious_tld", "flagged": False, "detail": "TLD is not on suspicious list"})
    lookalike_flag = False
    for brand in ["google", "microsoft", "apple", "amazon", "paypal", "linkedin"]:
        if brand in domain and domain != f"{brand}.com":
            score += 25
            lookalike_flag = True
            checks.append({"check": "lookalike_brand", "flagged": True, "detail": f"Domain resembles {brand} brand"})
            break
    if not lookalike_flag:
        checks.append({"check": "lookalike_brand", "flagged": False, "detail": "No brand impersonation detected"})
    if "+" in local_part:
        score += 10
        checks.append({"check": "alias_addressing", "flagged": True, "detail": "Email alias (+ addressing) present"})
    else:
        checks.append({"check": "alias_addressing", "flagged": False, "detail": "No alias addressing"})
    if score == 0:
        score = 8
    return {"email": email_addr, "domain": domain, "spam_score": min(score, 100), "reputation": "bad" if score > 40 else "suspicious" if score > 20 else "good", "verdict": "SPAM" if score > 40 else "SUSPICIOUS" if score > 20 else "SAFE", "recommendation": "Monitor sender" if score > 20 else "No issues", "indicators": [c["detail"] for c in checks if c["flagged"]], "check_summary": {"disposable_domain": any(c["check"] == "disposable_domain" and c["flagged"] for c in checks), "suspicious_tld": tld_flag, "lookalike_brand": lookalike_flag}, "reports": 0, "category": "unknown", "sender_name": "Unknown Sender", "checks": checks}
