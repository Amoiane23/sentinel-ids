import json

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    source TEXT NOT NULL,
    prediction TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    attack_probability REAL NOT NULL,
    latency_ms REAL NOT NULL,
    raw_features_json TEXT,
    probabilities_json TEXT
);
"""


def build_record_from_prediction(
    prediction,
    source,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    raw_features,
    timestamp,
):
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "source": source,
        "prediction": prediction["prediction"],
        "attack_type": prediction["attack_type"],
        "severity": prediction["severity"],
        "confidence": float(prediction["confidence"]),
        "attack_probability": float(prediction["attack_probability"]),
        "latency_ms": float(prediction.get("latency_ms", 0.0)),
        "raw_features_json": json.dumps(raw_features or {}),
        "probabilities_json": json.dumps(prediction.get("probabilities", {})),
    }