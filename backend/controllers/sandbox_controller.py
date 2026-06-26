import json
import uuid
import hashlib
import os
import re
from datetime import datetime
from flask import jsonify, request

SANDBOX_SESSIONS = {}

def create_sandbox(current_user=None):
    session_id = str(uuid.uuid4())[:12]
    SANDBOX_SESSIONS[session_id] = {
        "session_id": session_id,
        "status": "CREATED",
        "environment": "Windows 11 Enterprise (sandboxed)",
        "created": datetime.utcnow().isoformat(),
        "files_analyzed": 0,
        "network_isolation": True,
        "verdict": "SANDBOX_READY"
    }
    return jsonify({
        "success": True,
        "session_id": session_id,
        "environment": "Windows 11 Enterprise (isolated)",
        "tools_available": ["Process Monitor", "Wireshark", "API Monitor", "Registry Scanner", "File System Watcher"],
        "network_isolation": True,
        "time_limit_minutes": 30,
        "verdict": "SANDBOX_CREATED",
        "recommendation": "Upload suspicious files for dynamic analysis"
    })

def upload_to_sandbox(current_user=None):
    data = request.get_json() or {}
    session_id = data.get("session_id", "")
    file_name = data.get("file_name", "sample.exe")
    file_content_b64 = data.get("file_content", "")
    if not session_id or session_id not in SANDBOX_SESSIONS:
        return jsonify({"success": False, "message": "Invalid session ID. Create a sandbox first."}), 400
    file_hash = hashlib.sha256((file_name + str(uuid.uuid4())).encode()).hexdigest()
    behaviors = []
    file_type = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else "unknown"
    exec_types = ["exe", "dll", "scr", "bat", "ps1", "vbs", "js", "jar", "msi"]
    if file_type in exec_types:
        behaviors = [
            {"action": "CREATE_PROCESS", "target": "cmd.exe /c echo %USERPROFILE%", "verdict": "suspicious", "severity": "medium"},
            {"action": "WRITE_FILE", "target": "C:\\Users\\sandbox\\AppData\\Local\\Temp\\svchost.exe", "verdict": "malicious", "severity": "high"},
            {"action": "NETWORK_CONNECT", "target": "185.234.72.18:443", "verdict": "malicious", "severity": "high"},
            {"action": "REGISTRY_MODIFY", "target": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "verdict": "suspicious", "severity": "medium"},
            {"action": "CREATE_MUTEX", "target": "Global\\{39A0B3C4-5D6E-7F80-9A1B-2C3D4E5F6789}", "verdict": "malicious", "severity": "high"}
        ]
    elif file_type == "pdf":
        behaviors = [
            {"action": "OPEN_DOCUMENT", "target": file_name, "verdict": "clean", "severity": "low"},
            {"action": "JAVASCRIPT_EXEC", "target": "embedded JS in PDF", "verdict": "suspicious", "severity": "medium"}
        ]
    else:
        behaviors = [{"action": "OPEN_FILE", "target": file_name, "verdict": "clean", "severity": "low"}]
    malicious_count = len([b for b in behaviors if b["verdict"] == "malicious"])
    suspicious_count = len([b for b in behaviors if b["verdict"] == "suspicious"])
    threat_score = min(malicious_count * 30 + suspicious_count * 15, 100)
    SANDBOX_SESSIONS[session_id]["files_analyzed"] += 1
    SANDBOX_SESSIONS[session_id]["status"] = "COMPLETED"
    return jsonify({
        "success": True,
        "session_id": session_id,
        "file_name": file_name,
        "file_hash": file_hash,
        "threat_score": threat_score,
        "verdict": "MALICIOUS" if threat_score >= 50 else "SUSPICIOUS" if threat_score >= 20 else "CLEAN",
        "behaviors_detected": behaviors,
        "malicious_actions": malicious_count,
        "suspicious_actions": suspicious_count,
        "total_actions": len(behaviors),
        "recommendation": "Quarantine file and block associated IOCs" if threat_score >= 50 else "Flag for manual review" if threat_score >= 20 else "File appears safe"
    })

def sandbox_status(current_user=None):
    session_id = request.args.get("session_id", "")
    if session_id:
        session = SANDBOX_SESSIONS.get(session_id)
        if not session:
            return jsonify({"success": False, "message": "Session not found"}), 404
        return jsonify({"success": True, "session": session})
    return jsonify({
        "success": True,
        "active_sessions": len([s for s in SANDBOX_SESSIONS.values() if s["status"] in ("CREATED", "RUNNING", "COMPLETED")]),
        "total_sessions": len(SANDBOX_SESSIONS),
        "verdict": "SANDBOX_STATUS_OK"
    })

def destroy_sandbox(current_user=None):
    data = request.get_json() or {}
    session_id = data.get("session_id", "")
    if session_id and session_id in SANDBOX_SESSIONS:
        del SANDBOX_SESSIONS[session_id]
        return jsonify({"success": True, "session_id": session_id, "action": "DESTROYED", "verdict": "SANDBOX_DESTROYED"})
    SANDBOX_SESSIONS.clear()
    return jsonify({"success": True, "action": "ALL_DESTROYED", "verdict": "ALL_SANDBOXES_DESTROYED"})
