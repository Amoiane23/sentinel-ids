from app.storage.db import get_connection
from app.storage.models import SCHEMA_SQL


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def save_alert(record):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO alerts (
            timestamp, src_ip, dst_ip, src_port, dst_port, protocol, source,
            prediction, attack_type, severity, confidence, attack_probability,
            latency_ms, raw_features_json, probabilities_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["timestamp"],
            record["src_ip"],
            record["dst_ip"],
            record["src_port"],
            record["dst_port"],
            record["protocol"],
            record["source"],
            record["prediction"],
            record["attack_type"],
            record["severity"],
            record["confidence"],
            record["attack_probability"],
            record["latency_ms"],
            record["raw_features_json"],
            record["probabilities_json"],
        ),
    )
    conn.commit()
    conn.close()


def get_alerts(limit=200):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_latest_alerts(limit=30):
    return get_alerts(limit)


def clear_alerts():
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


def get_summary():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    attacks = conn.execute(
        "SELECT COUNT(*) AS c FROM alerts WHERE prediction = 'ATTACK'"
    ).fetchone()["c"]
    benign = conn.execute(
        "SELECT COUNT(*) AS c FROM alerts WHERE prediction = 'BENIGN'"
    ).fetchone()["c"]
    avg_conf = conn.execute(
        "SELECT AVG(confidence) AS c FROM alerts"
    ).fetchone()["c"]
    avg_latency = conn.execute(
        "SELECT AVG(latency_ms) AS c FROM alerts"
    ).fetchone()["c"]
    conn.close()

    risk_score = round((attacks / total) * 100, 2) if total else 0.0
    return {
        "total_predictions": total,
        "attack_count": attacks,
        "benign_count": benign,
        "risk_score": risk_score,
        "avg_confidence": round(avg_conf or 0.0, 4),
        "avg_latency": round(avg_latency or 0.0, 2),
    }