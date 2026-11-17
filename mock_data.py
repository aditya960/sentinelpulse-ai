"""SQLite-backed demo threat data for SentinelPulse AI."""

from contextlib import contextmanager
from datetime import datetime, timedelta
import os
from pathlib import Path
import random
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SENTINELPULSE_DB", BASE_DIR / "instance" / "sentinelpulse.db"))

MITRE_MAPPING = {
    "Brute Force": "T1110",
    "SQL Injection": "T1190",
    "DDoS": "T1499",
    "Malware": "T1204.002",
    "Phishing": "T1566",
    "Ransomware": "T1486",
    "Port Scan": "T1046",
}

SEVERITY_LOOKUP = {
    "Brute Force": "Critical",
    "SQL Injection": "High",
    "DDoS": "Medium",
    "Malware": "High",
    "Phishing": "High",
    "Ransomware": "Critical",
    "Port Scan": "Low",
}

WEIGHTS = {"Critical": 5, "High": 3, "Medium": 1, "Low": 0}


@contextmanager
def _connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _timestamp(value=None):
    value = value or datetime.now().astimezone()
    return value.isoformat(timespec="seconds")


def _seed_rows():
    now = datetime.now().astimezone()
    rows = [
        (22, "203.0.113.24", "Port Scan", "Low", "Mitigated"),
        (19, "198.51.100.18", "Phishing", "High", "Mitigated"),
        (16, "203.0.113.71", "SQL Injection", "High", "Active"),
        (13, "198.51.100.56", "Brute Force", "Critical", "Mitigated"),
        (10, "203.0.113.109", "DDoS", "Medium", "Active"),
        (7, "198.51.100.32", "Malware", "High", "Active"),
        (4, "203.0.113.88", "Ransomware", "Critical", "Active"),
        (1, "198.51.100.92", "Brute Force", "Critical", "Active"),
    ]
    return [
        (
            _timestamp(now - timedelta(hours=hours_ago)),
            source_ip,
            attack_type,
            MITRE_MAPPING[attack_type],
            severity,
            status,
        )
        for hours_ago, source_ip, attack_type, severity, status in rows
    ]


def _insert_demo_rows(connection):
    connection.executemany(
        """INSERT INTO threats (timestamp, source_ip, attack_type, mitre_id, severity, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        _seed_rows(),
    )


def init_db():
    with _connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                mitre_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('Active', 'Mitigated'))
            )"""
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        seeded = connection.execute("SELECT value FROM app_state WHERE key = 'demo_seeded'").fetchone()
        if seeded is None:
            if connection.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0:
                _insert_demo_rows(connection)
            connection.execute("INSERT INTO app_state (key, value) VALUES ('demo_seeded', '1')")


def get_threats():
    with _connection() as connection:
        rows = connection.execute(
            "SELECT id, timestamp, source_ip, attack_type, mitre_id, severity, status FROM threats ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def add_threat(attack_type: str):
    if attack_type not in MITRE_MAPPING:
        raise ValueError("Unsupported attack type")
    source_ip = f"198.51.100.{random.randint(1, 254)}"
    with _connection() as connection:
        cursor = connection.execute(
            """INSERT INTO threats (timestamp, source_ip, attack_type, mitre_id, severity, status)
               VALUES (?, ?, ?, ?, ?, 'Active')""",
            (_timestamp(), source_ip, attack_type, MITRE_MAPPING[attack_type], SEVERITY_LOOKUP[attack_type]),
        )
        row = connection.execute(
            "SELECT id, timestamp, source_ip, attack_type, mitre_id, severity, status FROM threats WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return dict(row)


def mitigate_threat(log_id: int):
    with _connection() as connection:
        cursor = connection.execute("UPDATE threats SET status = 'Mitigated' WHERE id = ?", (log_id,))
    return cursor.rowcount > 0


def clear_threats():
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM threats")
    return cursor.rowcount


def reset_demo_data():
    with _connection() as connection:
        connection.execute("DELETE FROM threats")
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'threats'")
        _insert_demo_rows(connection)
    return get_threats()


def calculate_health_score() -> int:
    with _connection() as connection:
        rows = connection.execute("SELECT severity FROM threats WHERE status = 'Active'").fetchall()
    deductions = sum(WEIGHTS.get(row["severity"], 0) for row in rows)
    return max(100 - deductions, 0)


def get_kpis():
    with _connection() as connection:
        totals = connection.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN status = 'Active' AND severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
                      SUM(CASE WHEN status = 'Mitigated' THEN 1 ELSE 0 END) AS mitigated
               FROM threats"""
        ).fetchone()
    return {
        "total_logs": totals["total"],
        "active_critical": totals["critical"] or 0,
        "mitigated": totals["mitigated"] or 0,
        "health_score": calculate_health_score(),
    }


def generate_summary():
    threats = get_threats()
    active = [log for log in threats if log["status"] == "Active"]
    critical = [log for log in active if log["severity"] == "Critical"]
    ip_counts = {}
    for log in active:
        ip_counts[log["source_ip"]] = ip_counts.get(log["source_ip"], 0) + 1
    most_common_ip = max(ip_counts, key=ip_counts.get) if ip_counts else None
    return {
        "total_logs": len(threats),
        "active_critical": len(critical),
        "most_dangerous_ip": most_common_ip or "N/A",
        "suggestion": "Prioritize active Critical alerts, verify the source evidence, and follow your response playbook.",
    }


def get_activity(hours=24, buckets=24):
    now = datetime.now().astimezone()
    start = now - timedelta(hours=hours)
    bucket_seconds = (hours * 3600) / buckets
    event_counts = [0] * buckets
    critical_counts = [0] * buckets
    with _connection() as connection:
        rows = connection.execute(
            "SELECT timestamp, severity FROM threats WHERE timestamp >= ? ORDER BY timestamp",
            (_timestamp(start),),
        ).fetchall()
    for row in rows:
        timestamp = datetime.fromisoformat(row["timestamp"])
        offset = (timestamp - start).total_seconds()
        index = min(int(offset // bucket_seconds), buckets - 1)
        if index >= 0:
            event_counts[index] += 1
            if row["severity"] == "Critical":
                critical_counts[index] += 1
    labels = [
        (start + timedelta(seconds=bucket_seconds * (index + 1))).strftime("%H:%M" if hours == 24 else "%b %d %Hh")
        for index in range(buckets)
    ]
    return {"labels": labels, "events": event_counts, "critical": critical_counts, "hours": hours}


def get_threat_forecast():
    """Build a transparent, rule-based six-hour outlook from recorded events."""
    now = datetime.now().astimezone()
    start = now - timedelta(hours=24)
    with _connection() as connection:
        rows = connection.execute(
            "SELECT timestamp, attack_type, severity, status FROM threats WHERE timestamp >= ? ORDER BY timestamp",
            (_timestamp(start),),
        ).fetchall()
        active_critical = connection.execute(
            "SELECT COUNT(*) FROM threats WHERE status = 'Active' AND severity = 'Critical'"
        ).fetchone()[0]

    hourly = [0] * 24
    attack_types = {}
    covered_hours = set()
    for row in rows:
        event_time = datetime.fromisoformat(row["timestamp"])
        offset = max(0, min(23, int((event_time - start).total_seconds() // 3600)))
        hourly[offset] += 1
        covered_hours.add(offset)
        attack_types[row["attack_type"]] = attack_types.get(row["attack_type"], 0) + 1

    recent_rate = sum(hourly[-6:]) / 6
    prior_rate = sum(hourly[-12:-6]) / 6
    daily_rate = sum(hourly) / 24
    # Blend the short-term rate with the full-day baseline, then damp the
    # recent trend so a single simulator event cannot dominate the outlook.
    base_rate = 0.65 * recent_rate + 0.35 * daily_rate
    trend = max(-0.5, min(0.5, (recent_rate - prior_rate) * 0.35))
    projection = [round(max(0, base_rate + trend * (0.72 ** step)), 1) for step in range(1, 7)]
    expected = round(sum(projection), 1)

    risk_score = min(100, round(18 + min(34, recent_rate * 18) + min(24, max(0, recent_rate - prior_rate) * 8) + min(24, active_critical * 8)))
    risk_level = "Critical" if risk_score >= 80 else "High" if risk_score >= 60 else "Elevated" if risk_score >= 35 else "Low"
    confidence = "High" if len(rows) >= 20 and len(covered_hours) >= 10 else "Medium" if len(rows) >= 8 and len(covered_hours) >= 5 else "Low"
    likely_attack = max(attack_types, key=attack_types.get) if attack_types else None
    drivers = []
    if recent_rate > prior_rate:
        drivers.append("Event volume is higher in the latest six hours than in the preceding six.")
    elif recent_rate < prior_rate:
        drivers.append("Event volume has eased in the latest six hours.")
    else:
        drivers.append("Recent event volume is steady against the preceding six hours.")
    if active_critical:
        drivers.append(f"{active_critical} active critical incident{'s' if active_critical != 1 else ''} remain{'s' if active_critical == 1 else ''} unresolved.")
    if confidence == "Low":
        drivers.append("Limited event history makes this outlook less reliable.")

    return {
        "horizon_hours": 6,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "expected_events": expected,
        "likely_attack": likely_attack,
        "type_sample_count": sum(attack_types.values()),
        "hourly_projection": projection,
        "drivers": drivers,
        "method": "Damped hourly trend blended with a 24-hour baseline; this is a heuristic, not a probability.",
        "generated_at": now.isoformat(timespec="seconds"),
    }


init_db()
