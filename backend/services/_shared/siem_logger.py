import json
import os
from datetime import datetime

SIEM_LOG = []

def log_event(event_type, severity, source, details, user_id=None):
    entry = {
        "id": f"EVT-{len(SIEM_LOG)+1:06d}",
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "user_id": user_id,
        "details": details,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    SIEM_LOG.append(entry)
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "siem_events.json"), "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry["id"]

def get_events(limit=100, severity=None, event_type=None):
    events = SIEM_LOG[-limit:]
    if severity:
        events = [e for e in events if e["severity"] == severity]
    if event_type:
        events = [e for e in events if e["event_type"] == event_type]
    return reversed(events)
