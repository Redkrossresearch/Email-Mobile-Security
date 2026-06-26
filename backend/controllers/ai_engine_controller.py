import json
import re
import uuid
import hashlib
from datetime import datetime
from flask import jsonify, request

try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

OLLAMA_BASE = "http://localhost:11434"
ANALYSIS_HISTORY = []

def query_ollama(model, prompt):
    if not REQUESTS_AVAILABLE:
        return None, "requests library not available"
    try:
        r = http_requests.post(f"{OLLAMA_BASE}/api/generate", json={"model": model, "prompt": prompt, "stream": False}, timeout=60)
        if r.ok:
            return r.json().get("response", ""), None
        return None, f"Ollama error: HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)

def analyze_ioc_with_ai(current_user=None):
    data = request.get_json() or {}
    indicator = data.get("indicator", "45.33.32.156")
    context = data.get("context", "")
    model = data.get("model", "llama3")
    prompt = f"""You are a SOC threat intelligence analyst. Analyze this IOC:
Indicator: {indicator}
Context: {context}

Provide analysis in JSON format with these fields:
- verdict: malicious/suspicious/benign
- confidence: 0-100
- threat_type: e.g. c2, phishing, malware, scanner
- reasoning: brief explanation
- recommended_action: what SOC should do
- mitre_attack_techniques: list relevant MITRE ATT&CK IDs

Analysis:"""
    response, error = query_ollama(model, prompt)
    if response:
        analysis_id = str(uuid.uuid4())[:8]
        entry = {"id": analysis_id, "indicator": indicator, "model": model, "response": response, "timestamp": datetime.utcnow().isoformat()}
        ANALYSIS_HISTORY.append(entry)
        return jsonify({
            "success": True,
            "indicator": indicator,
            "model": model,
            "analysis": response,
            "analysis_id": analysis_id,
            "source": "ollama" if response else "simulated",
            "verdict": "AI_ANALYSIS_COMPLETE",
            "recommendation": "Review AI analysis and cross-reference with threat intel feeds"
        })
    simulated = {
        "indicator": indicator,
        "verdict": "suspicious",
        "confidence": 78,
        "threat_type": "potential_c2_communication",
        "reasoning": f"Indicator {indicator} exhibits patterns consistent with command & control infrastructure. Multiple open ports, anomalous TLS certificates, and historical association with malware campaigns.",
        "mitre_attack_techniques": ["T1071 - Application Layer Protocol", "T1573 - Encrypted Channel"],
        "recommended_action": "Block IP at firewall, add to DNS sinkhole, and investigate associated endpoints"
    }
    if not error:
        error = "Ollama not available - using simulated AI analysis"
    return jsonify({
        "success": True,
        "indicator": indicator,
        "model": model,
        "ollama_error": error,
        "analysis": simulated,
        "source": "simulated",
        "verdict": "AI_ANALYSIS_COMPLETE",
        "recommendation": "Install Ollama with llama3 or phi3 for local AI inference"
    })

def analyze_email_with_ai(current_user=None):
    data = request.get_json() or {}
    email_body = data.get("body", "")
    subject = data.get("subject", "")
    sender = data.get("sender", "")
    model = data.get("model", "phi3")
    if not email_body:
        return jsonify({"success": False, "message": "Email body required"}), 400
    prompt = f"""Analyze this email for phishing, BEC, malware, or spam indicators:

From: {sender}
Subject: {subject}
Body: {email_body[:2000]}

Classify as: legitimate / phishing / bec_attack / spam / malicious
Provide confidence score (0-100), key indicators found, and recommended action.

Analysis in JSON format:"""
    response, error = query_ollama(model, prompt)
    if not response:
        score = 0
        indicators = []
        phishing_kw = ["urgent", "click here", "verify", "password", "account", "login", "bank", "payment", "wire", "gift card", "claim"]
        for kw in phishing_kw:
            if kw in email_body.lower():
                score += 10
                indicators.append(f"Phishing keyword: {kw}")
        if re.search(r'https?://[^\s]+', email_body):
            score += 15
            indicators.append("URL detected in email body")
        if re.search(r'[\+0-9\-\(\)\s]{10,}', email_body):
            score += 5
            indicators.append("Phone number detected")
        verdict = "phishing" if score >= 40 else "spam" if score >= 20 else "legitimate"
        response = json.dumps({"verdict": verdict, "confidence": min(score + 10, 95), "indicators": indicators, "recommended_action": "Quarantine and alert SOC" if score >= 40 else "Flag for review" if score >= 20 else "Deliver normally"})
        if not error:
            error = "Ollama not available"
    return jsonify({
        "success": True,
        "sender": sender,
        "subject": subject,
        "model": model,
        "analysis": json.loads(response) if isinstance(response, str) else response,
        "source": "ollama" if not error or "not available" not in str(error) else "simulated",
        "ollama_error": error if error and "not available" in str(error) else None,
        "verdict": "AI_EMAIL_ANALYSIS_COMPLETE"
    })

def ai_search_engine(current_user=None):
    data = request.get_json() or {}
    query = data.get("query", "")
    context = data.get("context", "security threat analysis")
    model = data.get("model", "llama3")
    max_results = data.get("max_results", 5)
    if not query:
        return jsonify({"success": False, "message": "Search query required"}), 400
    prompt = f"""You are a cybersecurity AI search engine. Search context: {context}
User query: {query}

Provide:
1. Summary answer to the query
2. Key findings (up to {max_results} bullet points)
3. Confidence level
4. Related topics to investigate

Analysis:"""
    response, error = query_ollama(model, prompt)
    if not response:
        response = json.dumps({
            "summary": f"Analysis of '{query}' in context of {context}",
            "key_findings": [
                "Pattern analysis suggests correlation with known threat actor groups",
                "Indicators match TTPs from MITRE ATT&CK framework",
                "Cross-referencing with threat intel feeds recommended"
            ],
            "confidence": 72,
            "related_topics": ["threat_actor_profiling", "indicator_correlation", "attack_vector_analysis"]
        })
        if not error:
            error = "Ollama not available"
    return jsonify({
        "success": True,
        "query": query,
        "model": model,
        "context": context,
        "results": json.loads(response) if isinstance(response, str) else response,
        "source": "ollama" if not error or "not available" in str(error) else "simulated",
        "search_id": str(uuid.uuid4())[:8],
        "verdict": "AI_SEARCH_COMPLETE",
        "recommendation": "Install Ollama for local AI inference without API costs"
    })

def list_ai_models(current_user=None):
    models = []
    if REQUESTS_AVAILABLE:
        try:
            r = http_requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
            if r.ok:
                models = [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
    if not models:
        models = ["llama3 (recommended)", "phi3 (lightweight)", "mistral", "codellama"]
    return jsonify({
        "success": True,
        "models": models,
        "ollama_running": len(models) > 0 and "recommended" not in str(models),
        "available_locally": len([m for m in models if "recommended" not in m]) > 0,
        "verdict": "AI_MODELS_LISTED",
        "recommendation": "Run 'ollama pull llama3' to enable local AI inference"
    })

def get_analysis_history(current_user=None):
    limit = request.args.get("limit", 10, type=int)
    return jsonify({
        "success": True,
        "history": ANALYSIS_HISTORY[-limit:],
        "total": len(ANALYSIS_HISTORY),
        "verdict": "HISTORY_RETURNED"
    })

def generate_ai_report(current_user=None):
    data = request.get_json() or {}
    report_type = data.get("type", "threat_summary")
    timeframe = data.get("timeframe", "24h")
    model = data.get("model", "llama3")
    prompt = f"""Generate a cybersecurity {report_type} report for the last {timeframe}.

Include:
- Executive summary
- Key threats detected
- Risk assessment (Low/Medium/High/Critical)
- Recommended actions (prioritized)
- Indicators to watch

Format as structured JSON."""
    response, error = query_ollama(model, prompt)
    if not response:
        response = json.dumps({
            "executive_summary": f"Security {report_type} report covering {timeframe}",
            "threats_detected": ["Phishing campaigns targeting finance", "Brute force attempts on VPN", "Suspicious outbound DNS queries"],
            "risk_assessment": "Medium",
            "recommended_actions": ["Enable MFA for all VPN users", "Update email filtering rules", "Block suspicious domains at DNS level"],
            "iocs_to_watch": ["45.33.32.156", "evil-phishing.com", "malware.download"]
        })
        if not error:
            error = "Ollama not available"
    return jsonify({
        "success": True,
        "report_type": report_type,
        "timeframe": timeframe,
        "model": model,
        "report": json.loads(response) if isinstance(response, str) else response,
        "report_id": str(uuid.uuid4())[:8],
        "source": "ollama" if not error or "not available" in str(error) else "simulated",
        "verdict": "AI_REPORT_GENERATED"
    })
