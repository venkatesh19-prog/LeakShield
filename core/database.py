import sqlite3
from datetime import datetime
from typing import List, Dict, Any

DB_FILE = "leakshield.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_name TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        files_scanned INTEGER DEFAULT 0,
        findings_count INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        risk_score REAL NOT NULL,
        entropy REAL DEFAULT 0.0,
        file_path TEXT NOT NULL,
        line_number INTEGER,
        redacted_evidence TEXT,
        redacted_secret TEXT,
        fingerprint TEXT,
        description TEXT,
        remediation TEXT,
        status TEXT DEFAULT 'Open',
        created_at TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS custom_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        pattern TEXT NOT NULL,
        min_entropy REAL DEFAULT 3.5,
        confidence INTEGER DEFAULT 80,
        description TEXT,
        remediation TEXT,
        enabled INTEGER DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rule_states (
        rule_id TEXT PRIMARY KEY,
        enabled INTEGER DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    # Ensure entropy column exists if upgrading from older table
    try:
        cursor.execute("ALTER TABLE findings ADD COLUMN entropy REAL DEFAULT 0.0")
    except Exception:
        pass

    conn.commit()
    conn.close()

def save_scan_and_findings(scan_name: str, scan_type: str, files_count: int, findings: List[Dict[str, Any]]) -> int:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO scans (scan_name, scan_type, started_at, completed_at, status, files_scanned, findings_count)
        VALUES (?, ?, ?, ?, 'Completed', ?, ?)
    """, (scan_name, scan_type, now_str, now_str, files_count, len(findings)))
    scan_id = cursor.lastrowid

    for f in findings:
        cursor.execute("""
            INSERT INTO findings (
                scan_id, rule_id, rule_name, category, severity, confidence, risk_score,
                entropy, file_path, line_number, redacted_evidence, redacted_secret, fingerprint,
                description, remediation, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?)
        """, (
            scan_id, f["rule_id"], f.get("rule_name", ""), f["category"], f["severity"],
            f["confidence"], f["risk_score"], f.get("entropy", 0.0), f["file_path"], f["line_number"],
            f["redacted_evidence"], f["redacted_secret"], f["fingerprint"],
            f["description"], f["remediation"], now_str
        ))

    conn.commit()
    conn.close()
    return scan_id

def get_all_scans() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_findings_by_scan(scan_id: int) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY risk_score DESC", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_findings() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings ORDER BY risk_score DESC, id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_finding_status(finding_id: int, new_status: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (new_status, finding_id))
    conn.commit()
    conn.close()

def get_custom_rules() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM custom_rules")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def insert_custom_rule(rule: Dict[str, Any]):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO custom_rules (id, name, category, severity, pattern, min_entropy, confidence, description, remediation, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rule["id"], rule["name"], rule["category"], rule["severity"], rule["pattern"],
        rule.get("min_entropy", 3.0), rule.get("confidence", 80), rule.get("description", ""),
        rule.get("remediation", ""), 1 if rule.get("enabled", True) else 0
    ))
    conn.commit()
    conn.close()

def delete_custom_rule(rule_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()

def get_rule_states() -> Dict[str, bool]:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT rule_id, enabled FROM rule_states")
    rows = cursor.fetchall()
    conn.close()
    return {r["rule_id"]: bool(r["enabled"]) for r in rows}

def set_rule_state(rule_id: str, enabled: bool):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO rule_states (rule_id, enabled) VALUES (?, ?)", (rule_id, 1 if enabled else 0))
    conn.commit()
    conn.close()

def clear_all_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
