import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "cybershield.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS caller_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        e164 TEXT,
        country_iso TEXT,
        country_name TEXT,
        carrier TEXT,
        number_type TEXT,
        score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'safe',
        verdict TEXT DEFAULT 'VERDICT',
        tags TEXT DEFAULT '[]',
        explanation TEXT,
        recommendation TEXT,
        scanned_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS call_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        name TEXT DEFAULT 'Unknown',
        direction TEXT DEFAULT 'incoming',
        duration INTEGER DEFAULT 0,
        blocked INTEGER DEFAULT 0,
        spam_type TEXT DEFAULT 'legitimate',
        score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'safe',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sms_scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'safe',
        verdict TEXT DEFAULT 'SAFE',
        findings TEXT DEFAULT '[]',
        urls_found TEXT DEFAULT '[]',
        scanned_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS email_scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        verdict TEXT DEFAULT 'SAFE',
        result_json TEXT DEFAULT '{}',
        scanned_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_health (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        battery_level INTEGER DEFAULT 100,
        cpu_usage INTEGER DEFAULT 0,
        ram_usage INTEGER DEFAULT 0,
        storage_used INTEGER DEFAULT 0,
        storage_total INTEGER DEFAULT 128,
        os_version TEXT DEFAULT 'Unknown',
        security_patch TEXT DEFAULT 'Unknown',
        encryption_enabled INTEGER DEFAULT 1,
        root_detected INTEGER DEFAULT 0,
        vpn_active INTEGER DEFAULT 0,
        overall_score INTEGER DEFAULT 100,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS app_scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_name TEXT NOT NULL,
        package_name TEXT,
        scan_type TEXT DEFAULT 'reputation',
        score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'safe',
        issues TEXT DEFAULT '[]',
        scanned_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS malware_scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threats_found INTEGER DEFAULT 0,
        apps_scanned INTEGER DEFAULT 0,
        threats_json TEXT DEFAULT '[]',
        score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'safe',
        scanned_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS dashboard_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stat_key TEXT UNIQUE,
        stat_value INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS registered_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        platform TEXT DEFAULT 'Android',
        os_version TEXT DEFAULT 'Unknown',
        model TEXT DEFAULT 'Unknown',
        imei TEXT DEFAULT '',
        trust_score INTEGER DEFAULT 80,
        is_compromised INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'low',
        encryption_enabled INTEGER DEFAULT 1,
        screen_lock INTEGER DEFAULT 1,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        registered_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

def _insert(table, data):
    conn = get_db()
    cols = ", ".join(data.keys())
    placeholders = ", ".join(["?"] * len(data))
    vals = list(data.values())
    conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", vals)
    conn.commit()
    conn.close()

def _query(sql, params=()):
    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def _query_one(sql, params=()):
    conn = get_db()
    row = conn.execute(sql, params).fetchone()
    conn.close()
    return dict(row) if row else None

def _update_stat(key, delta=1):
    conn = get_db()
    existing = conn.execute("SELECT stat_value FROM dashboard_stats WHERE stat_key=?", (key,)).fetchone()
    if existing:
        conn.execute("UPDATE dashboard_stats SET stat_value=stat_value+?, updated_at=CURRENT_TIMESTAMP WHERE stat_key=?", (delta, key))
    else:
        conn.execute("INSERT INTO dashboard_stats (stat_key, stat_value) VALUES (?, ?)", (key, delta))
    conn.commit()
    conn.close()

def _get_stat(key):
    row = _query_one("SELECT stat_value FROM dashboard_stats WHERE stat_key=?", (key,))
    return row["stat_value"] if row else 0


def seed_devices():
    """Insert default devices if the table is empty."""
    existing = _query_one("SELECT COUNT(*) as cnt FROM registered_devices")
    if existing and existing["cnt"] > 0:
        return
    default_devices = [
        ("d-001", "Mike's Pixel 7", "Android", "14.0", "Pixel 7", "358901234567890", 88, 0, "low", 1, 1),
        ("d-002", "Sarah's iPhone 15", "iOS", "18.5", "iPhone 15", "358901234567891", 95, 0, "low", 1, 1),
        ("d-003", "Alex's Galaxy S24", "Android", "13.0", "Galaxy S24", "358901234567892", 62, 1, "high", 0, 1),
        ("d-004", "Office Tablet", "Android", "12.0", "Unknown", "358901234567893", 45, 1, "critical", 0, 0),
        ("d-005", "Jane's iPad Air", "iOS", "17.4", "iPad Air", "358901234567894", 78, 0, "medium", 1, 1),
    ]
    conn = get_db()
    for d in default_devices:
        conn.execute(
            "INSERT OR IGNORE INTO registered_devices (device_id, name, platform, os_version, model, imei, trust_score, is_compromised, risk_level, encryption_enabled, screen_lock) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            d,
        )
    conn.commit()
    conn.close()
