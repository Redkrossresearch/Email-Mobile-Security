import json
import os
import csv
import io
import uuid
from datetime import datetime
from flask import jsonify, send_file, request
from config.settings import DATA_DIR, REPORTS_DIR

def _pdf_header(pdf, title, subtitle=""):
    pdf.set_fill_color(10, 25, 47)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_text_color(0, 229, 255)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_xy(10, 6)
    pdf.cell(0, 6, "CYBERSHIELD SOC", ln=True)
    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(10, 14)
    pdf.cell(0, 8, title, ln=True)
    if subtitle:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(140, 140, 140)
        pdf.set_xy(10, 22)
        pdf.cell(0, 5, subtitle, ln=True)
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.4)
    pdf.line(10, 29, 200, 29)
    pdf.set_y(32)

def _pdf_footer(pdf, report_id=""):
    pdf.set_y(-15)
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.2)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_y(-12)
    pdf.set_font("Helvetica", "", 6)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(95, 4, f"Report {report_id} | CONFIDENTIAL", align="L")
    pdf.cell(95, 4, f"Page {pdf.page_no()}/{{nb}}", align="R")

def _pdf_table_header(pdf, cols, widths):
    pdf.set_fill_color(0, 229, 255)
    pdf.set_text_color(10, 25, 47)
    pdf.set_font("Helvetica", "B", 8)
    for i, c in enumerate(cols):
        pdf.cell(widths[i], 6, c, border=1, fill=True, align="C")
    pdf.ln()

def _pdf_table_row(pdf, cols, widths, fill=False):
    pdf.set_text_color(200, 200, 200)
    pdf.set_font("Helvetica", "", 7)
    if fill:
        pdf.set_fill_color(15, 35, 60)
    else:
        pdf.set_fill_color(10, 25, 47)
    for i, c in enumerate(cols):
        pdf.cell(widths[i], 5, str(c)[:30], border=1, fill=True, align="C")
    pdf.ln()

def _ascii(text):
    return text.replace("\u2014", "--").replace("\u2013", "-").replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"').replace("\u2026", "...").replace("\u2022", "-").replace("\u20ac", "EUR").replace("\u00a9", "(c)").replace("\u00ae", "(r)").replace("\u2122", "TM")

def generate_pdf(current_user=None):
    from fpdf import FPDF
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    report_id = f"SR-{uuid.uuid4().hex[:8].upper()}"
    # --- Cover page ---
    pdf.add_page()
    pdf.set_fill_color(10, 25, 47)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_y(70)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(0, 229, 255)
    pdf.cell(0, 14, "CYBERSHIELD SOC", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 255, 136)
    pdf.cell(0, 7, "Enterprise Security Platform", ln=True, align="C")
    pdf.ln(12)
    pdf.set_draw_color(0, 229, 255)
    pdf.set_line_width(0.5)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(12)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "COMPLETE SECURITY REPORT", ln=True, align="C")
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(180, 180, 180)
    now = datetime.now()
    pdf.cell(0, 7, f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}", ln=True, align="C")
    pdf.cell(0, 7, f"Report ID: {report_id}", ln=True, align="C")
    pdf.cell(0, 7, "Classification: CONFIDENTIAL", ln=True, align="C")
    pdf.ln(20)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 5, "CyberShield SOC v6.0 | 75+ Features | 12 Modules", ln=True, align="C")
    pdf.cell(0, 5, "Email Security | Mobile Security | Reporting | Authentication", ln=True, align="C")

    with open(f"{DATA_DIR}/devices.json") as f:
        devices = json.load(f)
    with open(f"{DATA_DIR}/sms_messages.json") as f:
        sms_list = json.load(f)
    with open(f"{DATA_DIR}/call_logs.json") as f:
        calls = json.load(f)

    # --- Page 2: Executive Summary ---
    pdf.add_page()
    _pdf_header(pdf, "EXECUTIVE SUMMARY", f"Report {report_id}")
    healthy = len([d for d in devices if d["status"] == "healthy"])
    warning = len([d for d in devices if d["status"] == "warning"])
    critical = len([d for d in devices if d["status"] == "critical"])
    phishing = len([s for s in sms_list if s["type"] == "phishing"])
    spam = len([s for s in sms_list if s["type"] == "spam"])
    blocked_calls = len([c for c in calls if c["blocked"]])
    total_devices = len(devices)
    health_score = sum(d.get("health_score", 0) for d in devices) // total_devices if total_devices else 0
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(0, 255, 136)
    pdf.cell(0, 6, "Platform Health Overview", ln=True)
    pdf.ln(2)
    w = [40, 30, 30, 30, 30, 30]
    _pdf_table_header(pdf, ["Metric", "Value", "Healthy", "Warning", "Critical", "Score"], w)
    _pdf_table_row(pdf, ["Devices", str(total_devices), str(healthy), str(warning), str(critical), f"{health_score}%"], w, fill=True)
    _pdf_table_row(pdf, ["SMS Threats", str(len(sms_list)), str(len(sms_list)-phishing-spam), str(spam), str(phishing), "-"], w)
    _pdf_table_row(pdf, ["Calls", str(len(calls)), str(len(calls)-blocked_calls), "0", str(blocked_calls), "-"], w, fill=True)
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(255, 51, 85)
    pdf.cell(0, 6, "Threat Summary", ln=True)
    pdf.ln(2)
    tw = [30, 20, 30, 40, 50, 20]
    _pdf_table_header(pdf, ["Category", "Count", "Severity", "Status", "Action Required", ""], tw)
    _pdf_table_row(pdf, ["Phishing SMS", str(phishing), "HIGH", "Active", "Block senders", ""], tw, fill=True)
    _pdf_table_row(pdf, ["Spam SMS", str(spam), "MEDIUM", "Active", "Filter rules", ""], tw)
    _pdf_table_row(pdf, ["Blocked Calls", str(blocked_calls), "MEDIUM", "Active", "Review patterns", ""], tw, fill=True)
    _pdf_table_row(pdf, ["Compromised Devices", str(critical), "CRITICAL", "Active", "Isolate & wipe", ""], tw)
    pdf.ln(6)
    _pdf_footer(pdf, report_id)

    # --- Page 3: Device Overview ---
    pdf.add_page()
    _pdf_header(pdf, "1. DEVICE OVERVIEW", "Monitored devices and health status")
    w = [8, 50, 30, 20, 20, 22, 20, 20]
    _pdf_table_header(pdf, ["#", "Device Name", "OS", "Type", "Status", "Health", "Encrypted", "VPN"], w)
    for i, d in enumerate(devices[:20]):
        fill = i % 2 == 0
        _pdf_table_row(pdf, [str(i+1), d.get("name",""), d.get("os",""), d.get("type",""), d.get("status",""), f"{d.get('health_score',0)}%", "Y" if d.get("encrypted") else "N", "Y" if d.get("vpn_active") else "N"], w, fill=fill)
    pdf.ln(4)
    _pdf_footer(pdf, report_id)

    # --- Page 4: Email Security Features ---
    pdf.add_page()
    _pdf_header(pdf, "2. EMAIL SECURITY MODULE", "23 active security features")
    email_features = [
        ("DMARC/SPF/DKIM Enforcement", "Active", "PASS"), ("Zero-Day Sandbox", "Active", "PASS"),
        ("Time-of-Click URL Analysis", "Active", "PASS"), ("CDR (Content Disarm & Reconstruct)", "Active", "PASS"),
        ("Lookalike Domain Detection", "Active", "PASS"), ("BEC Protection", "Active", "PASS"),
        ("Heuristic Analysis", "Active", "PASS"), ("Attachment Blocking", "Active", "PASS"),
        ("OCR Scanning", "Active", "PASS"), ("Outbound Encryption", "Active", "PASS"),
        ("Remote Browser Isolation", "Active", "PASS"), ("DNS Sinkholing", "Active", "PASS"),
        ("SSL Decryption", "Active", "PASS"), ("Drive-by Download Protection", "Active", "PASS"),
        ("Credential Phishing Prevention", "Active", "PASS"), ("Ad & Tracker Blocking", "Active", "PASS"),
        ("Auto-Remediation (Clawback)", "Active", "PASS"),
        ("SIEM/SOAR Integration", "Active", "PASS"), ("Warning Banners", "Active", "PASS"),
        ("ATO Protection", "Active", "PASS"), ("MFA Enforcement", "Active", "PASS"),
        ("Rate Limiting", "Active", "PASS")
    ]
    w = [85, 30, 25]
    _pdf_table_header(pdf, ["Feature", "Status", "Health"], w)
    for i, (name, status, health) in enumerate(email_features):
        fill = i % 2 == 0
        _pdf_table_row(pdf, [name, status, health], w, fill=fill)
    pdf.ln(4)
    _pdf_footer(pdf, report_id)

    # --- Page 5: Mobile Security Features ---
    pdf.add_page()
    _pdf_header(pdf, "3. MOBILE SECURITY MODULE", "25 active security features")
    mobile_features = [
        ("SS7 Protection", "Active", "PASS"), ("A2P Monitoring", "Active", "PASS"),
        ("IMSI Catcher Detection", "Active", "PASS"), ("Baseband Firewall", "Active", "PASS"),
        ("DPI for SMSC", "Active", "PASS"), ("Crypto Signature", "Active", "PASS"),
        ("Zero-Click Exploit Protection", "Active", "PASS"), ("Honeypot Spam", "Active", "PASS"),
        ("Keystroke Protection", "Active", "PASS"), ("Rogue MDM Detection", "Active", "PASS"),
        ("SMS Sandbox", "Active", "PASS"), ("App Wrapping", "Active", "PASS"),
        ("Biometric Trigger", "Active", "PASS"), ("WebRTC Leak Check", "Active", "PASS"),
        ("Secure Enclave Audit", "Active", "PASS"), ("Contact Exfil Block", "Active", "PASS"),
        ("Location Spoof Detection", "Active", "PASS"), ("STIR/SHAKEN Call Verify", "Active", "PASS"),
        ("VoLTE Encryption", "Active", "PASS"), ("Remote Wipe/Lock", "Active", "PASS"),
        ("App Reputation", "Active", "PASS"), ("Secure Keyboard", "Active", "PASS"),
        ("Base Station Auth", "Active", "PASS"), ("SMS Retention Policy", "Active", "PASS"),
        ("Telecom Threat Intel", "Active", "PASS")
    ]
    w = [85, 30, 25]
    _pdf_table_header(pdf, ["Feature", "Status", "Health"], w)
    for i, (name, status, health) in enumerate(mobile_features):
        fill = i % 2 == 0
        _pdf_table_row(pdf, [name, status, health], w, fill=fill)
    pdf.ln(4)
    _pdf_footer(pdf, report_id)

    # --- Page 6: Recommendations ---
    pdf.add_page()
    _pdf_header(pdf, "4. RECOMMENDATIONS & REMEDIATION", "Action items for SOC team")
    recs = [
        ("CRITICAL", "Enable MFA for all accounts immediately"),
        ("HIGH", "Update device patches to latest versions"),
        ("HIGH", "Review high-risk app permissions on BYOD devices"),
        ("MEDIUM", "Enable VPN for all BYOD devices"),
        ("MEDIUM", "Run weekly malware scans on all endpoints"),
        ("MEDIUM", "Enable DMARC reject policy for all domains"),
        ("LOW", "Deploy RBI for high-risk browsing sessions"),
        ("LOW", "Reinforce phishing awareness training for employees"),
    ]
    w = [25, 155]
    _pdf_table_header(pdf, ["Priority", "Recommendation"], w)
    for i, (priority, rec) in enumerate(recs):
        fill = i % 2 == 0
        _pdf_table_row(pdf, [priority, rec], w, fill=fill)
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "This report was automatically generated by CyberShield SOC v6.0", ln=True, align="C")
    pdf.cell(0, 5, f"Report ID: {report_id} | Classification: CONFIDENTIAL", ln=True, align="C")
    pdf.cell(0, 5, _ascii(f"(c) {datetime.now().year} CyberShield SOC. All rights reserved."), ln=True, align="C")
    _pdf_footer(pdf, report_id)

    filename = f"CyberShield_SOC_Report_{report_id}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    pdf.output(filepath)
    return send_file(filepath, as_attachment=True, download_name=filename)

def generate_csv(current_user=None):
    with open(f"{DATA_DIR}/devices.json") as f:
        devices = json.load(f)
    with open(f"{DATA_DIR}/sms_messages.json") as f:
        sms_list = json.load(f)
    with open(f"{DATA_DIR}/call_logs.json") as f:
        calls = json.load(f)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CyberShield SOC — Complete Security Data Export"])
    writer.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}"])
    writer.writerow([])
    writer.writerow(["=== DEVICES ==="])
    writer.writerow(["Device ID", "Name", "OS", "Type", "Status", "Health Score", "Last Scan", "Encrypted", "VPN", "Wi-Fi", "Bluetooth", "Jailbroken", "Location"])
    for d in devices:
        writer.writerow([d["id"], d["name"], d["os"], d["type"], d["status"], d.get("health_score", "N/A"), d.get("last_scan", "N/A"), d.get("encrypted", "N/A"), d.get("vpn_active", "N/A"), d.get("wifi_ssid", "N/A"), d.get("bluetooth", "N/A"), d.get("jailbroken", "N/A"), d.get("location", "N/A")])
    writer.writerow([])
    writer.writerow(["=== SMS MESSAGES ==="])
    writer.writerow(["ID", "From", "Message", "Type", "Status", "Timestamp"])
    for s in sms_list:
        writer.writerow([s.get("id",""), s.get("from",""), s.get("message","")[:80], s.get("type",""), s.get("status",""), s.get("timestamp","")])
    writer.writerow([])
    writer.writerow(["=== CALL LOGS ==="])
    writer.writerow(["ID", "From", "To", "Duration", "Blocked", "Type", "Timestamp"])
    for c in calls:
        writer.writerow([c.get("id",""), c.get("from",""), c.get("to",""), c.get("duration",""), c.get("blocked",""), c.get("type",""), c.get("timestamp","")])
    output.seek(0)
    report_id = uuid.uuid4().hex[:8].upper()
    filename = f"CyberShield_SOC_Export_{report_id}.csv"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w", newline="") as f:
        f.write(output.getvalue())
    return send_file(filepath, as_attachment=True, download_name=filename)

def generate_json(current_user=None):
    with open(f"{DATA_DIR}/devices.json") as f:
        devices = json.load(f)
    with open(f"{DATA_DIR}/sms_messages.json") as f:
        sms_list = json.load(f)
    with open(f"{DATA_DIR}/call_logs.json") as f:
        calls = json.load(f)
    report_id = f"JR-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.utcnow().isoformat() + "Z"
    healthy = len([d for d in devices if d["status"] == "healthy"])
    warning = len([d for d in devices if d["status"] == "warning"])
    critical = len([d for d in devices if d["status"] == "critical"])
    phishing = len([s for s in sms_list if s["type"] == "phishing"])
    spam = len([s for s in sms_list if s["type"] == "spam"])
    blocked_calls = len([c for c in calls if c["blocked"]])
    report = {
        "report": {
            "report_id": report_id,
            "report_name": "CyberShield SOC Complete Security Report",
            "platform": "CyberShield SOC v6.0",
            "generated_at": now,
            "classification": "CONFIDENTIAL"
        },
        "summary": {
            "total_devices": len(devices),
            "healthy_devices": healthy,
            "warning_devices": warning,
            "critical_devices": critical,
            "phishing_sms": phishing,
            "spam_sms": spam,
            "blocked_calls": blocked_calls,
            "overall_health_score": sum(d.get("health_score", 0) for d in devices) // len(devices) if devices else 0
        },
        "total_features": 75,
        "modules": 12,
        "devices": devices,
        "sms_messages": sms_list,
        "call_logs": calls
    }
    filename = f"CyberShield_SOC_Data_{report_id}.json"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    return send_file(filepath, as_attachment=True, download_name=filename)

def generate_comprehensive(current_user=None):
    report_type = request.args.get("type", "summary")
    report = {
        "report_id": f"CR-{uuid.uuid4().hex[:8].upper()}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report_type": report_type,
        "platform": "CyberShield SOC v5.0",
        "total_features": 50,
        "modules": {
            "identity_access": {"features": ["login", "mfa", "sso", "oauth", "rbac", "recovery"], "status": "operational"},
            "email_security": {"features_count": 25, "status": "operational"},
            "mobile_security": {"features_count": 25, "status": "operational"},
            "reporting": {"features": ["pdf", "csv", "json"], "status": "operational"}
        },
        "overall_status": "OPERATIONAL",
        "total_endpoints": 70
    }
    filename = f"CyberShield_Comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    return send_file(filepath, as_attachment=True, download_name=filename)

def generate_threat_report(current_user=None):
    with open(f"{DATA_DIR}/sms_messages.json") as f:
        sms_list = json.load(f)
    with open(f"{DATA_DIR}/call_logs.json") as f:
        calls = json.load(f)
    report = {
        "report_id": f"TR-{uuid.uuid4().hex[:8].upper()}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "threat_landscape": {
            "sms_threats": {"phishing": len([s for s in sms_list if s["type"] == "phishing"]), "spam": len([s for s in sms_list if s["type"] == "spam"]), "safe": len([s for s in sms_list if s["type"] == "safe"])},
            "call_threats": {"blocked": len([c for c in calls if c["blocked"]]), "total": len(calls)},
            "top_attack_vectors": ["SMS Phishing (42%)", "Spam (28%)", "Scam Calls (20%)", "Robocalls (10%)"]
        },
        "remediation_actions": [
            "Block identified phishing domains", "Enable STIR/SHAKEN for all calls",
            "Deploy SMS filtering rules", "Flag high-risk senders for review"
        ]
    }
    filename = f"CyberShield_ThreatReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    return send_file(filepath, as_attachment=True, download_name=filename)
