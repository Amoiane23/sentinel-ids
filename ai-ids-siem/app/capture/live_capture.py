import time
import threading
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

# Scapy and Network utilities
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf
try:
    import psutil
except ImportError:
    psutil = None

from app.storage.repository import save_alert
from app.storage.models import build_record_from_prediction

# Flask imports - handle missing flask_cors gracefully
try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Warning: Flask or flask_cors not installed. API endpoints disabled.")
    # Create dummy classes
    class Flask: pass
    def jsonify(*args): return {}
    def CORS(*args): pass

FLOW_IDLE_TIMEOUT = 5 
ACTIVE_TIMEOUT = 30  
FLUSH_INTERVAL = 2
DEBUG = True

# Store predictions in memory for dashboard
recent_predictions = []
MAX_PREDICTIONS = 200

def debug(msg):
    if DEBUG:
        print(f"[live_capture] {msg}", flush=True)

def get_best_interface():
    interfaces = get_if_list()
    if psutil:
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if iface in interfaces:
                for addr in addr_list:
                    if addr.family == 2 and not addr.address.startswith("127."):
                        if not any(v in iface.lower() for v in ["vbox", "vmnet", "docker", "lo", "veth"]):
                            return iface
    return conf.iface

class MockPredictor:
    classes_ = ["BENIGN", "PortScan", "DDoS", "Botnet", "Web Attack - XSS", "ICMP Flood"]
    def predict(self, X):
        return ["BENIGN"] * len(X)
    
    def predict_one(self, features):
        return {
            "prediction": "BENIGN",
            "attack_type": "BENIGN",
            "severity": "LOW",
            "confidence": 0.99,
            "attack_probability": 0.01,
            "probabilities": {"BENIGN": 0.99, "ATTACK": 0.01},
            "latency_ms": 5.0,
        }

def load_model_predictor(model_dir="models/artifacts"):
    model_dir = Path(model_dir)
    model_path = model_dir / "rf_multiclass_pipeline.joblib"
    features_path = model_dir / "feature_columns.joblib"
    
    feature_names = None
    if features_path.exists():
        try:
            feature_names = joblib.load(features_path)
        except:
            feature_names = None

    if not model_path.exists():
        print("[live_capture] No model found, using mock predictor", flush=True)
        mock = MockPredictor()
        return {
            "loaded": False, 
            "predict_func": mock.predict_one,
            "predict_batch": mock.predict,
            "feature_names": feature_names
        }

    try:
        model = joblib.load(model_path)
        return {
            "loaded": True, 
            "predict_func": lambda x: model.predict_proba(x) if hasattr(model, 'predict_proba') else model.predict(x),
            "predict_batch": model.predict,
            "feature_names": feature_names
        }
    except Exception as e:
        print(f"[live_capture] Error loading model: {e}", flush=True)
        mock = MockPredictor()
        return {
            "loaded": False, 
            "predict_func": mock.predict_one,
            "predict_batch": mock.predict,
            "feature_names": feature_names
        }

class FlowTable:
    def __init__(self):
        self.flows = {}
        self.lock = threading.Lock()

    def flow_key(self, packet):
        ip = packet[IP]
        proto, sport, dport = "OTHER", 0, 0
        if TCP in packet:
            proto, sport, dport = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
        elif UDP in packet:
            proto, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        elif ICMP in packet:
            proto = "ICMP"
        return (ip.src, ip.dst, sport, dport, proto)

    def update(self, packet):
        if IP not in packet: return
        key = self.flow_key(packet)
        now = time.time()
        pkt_len = len(packet)
        
        with self.lock:
            if key not in self.flows:
                self.flows[key] = {
                    "start_ts": now, "last_seen": now, "packet_count": 0, "byte_count": 0,
                    "min_pkt_len": pkt_len, "max_pkt_len": pkt_len,
                    "syn_count": 0, "ack_count": 0, "rst_count": 0, "psh_count": 0, "fin_count": 0
                }
            f = self.flows[key]
            f["last_seen"] = now
            f["packet_count"] += 1
            f["byte_count"] += pkt_len
            f["min_pkt_len"] = min(f["min_pkt_len"], pkt_len)
            f["max_pkt_len"] = max(f["max_pkt_len"], pkt_len)
            if TCP in packet:
                flags = packet.sprintf("%TCP.flags%")
                if 'S' in flags: f["syn_count"] += 1
                if 'A' in flags: f["ack_count"] += 1
                if 'R' in flags: f["rst_count"] += 1
                if 'P' in flags: f["psh_count"] += 1
                if 'F' in flags: f["fin_count"] += 1

    def pop_expired(self):
        now = time.time()
        expired = []
        with self.lock:
            keys_to_remove = [k for k, v in self.flows.items() 
                             if (now - v["last_seen"] >= FLOW_IDLE_TIMEOUT) or 
                                (now - v["start_ts"] >= ACTIVE_TIMEOUT)]
            for k in keys_to_remove:
                expired.append((k, self.flows.pop(k)))
        return expired

def flow_to_features(flow_key, flow):
    src_ip, dst_ip, src_port, dst_port, proto = flow_key
    # FIXED: duration is defined here
    duration = max(flow["last_seen"] - flow["start_ts"], 0.001)
    
    pkts_per_sec = flow["packet_count"] / duration
    bytes_per_sec = flow["byte_count"] / duration
    
    features = [0.0] * 78 
    
    features[0] = float(dst_port) 
    features[1] = duration 
    features[2] = float(flow["packet_count"]) 
    features[4] = float(flow["byte_count"]) 
    features[10] = float(flow["max_pkt_len"])
    features[11] = float(flow["min_pkt_len"])
    features[20] = bytes_per_sec 
    features[21] = pkts_per_sec 

    meta = {
        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
        "protocol": proto, "duration": duration
    }
    return features, meta

def add_prediction_to_memory(result, meta, source="LIVE_CAPTURE"):
    """Add prediction to in-memory store for dashboard"""
    global recent_predictions
    prediction_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "type": result.get("prediction", "BENIGN"),
        "attack_type": result.get("attack_type", "BENIGN"),
        "severity": result.get("severity", "LOW"),
        "confidence": result.get("confidence", 0.0),
        "attack_probability": result.get("attack_probability", 0.0),
        "latency_ms": result.get("latency_ms", 0),
        "src_ip": meta.get("src_ip", ""),
        "dst_ip": meta.get("dst_ip", ""),
        "src_port": meta.get("src_port", 0),
        "dst_port": meta.get("dst_port", 0),
        "protocol": meta.get("protocol", "")
    }
    recent_predictions.insert(0, prediction_record)
    if len(recent_predictions) > MAX_PREDICTIONS:
        recent_predictions.pop()
    
    debug(f"Added prediction: {prediction_record['type']} - {prediction_record['attack_type']}")

capture_running = False

# Create Flask app only if available
if FLASK_AVAILABLE:
    app = Flask(__name__)
    CORS(app)
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({"status": "healthy", "capture_active": capture_running})
    
    @app.route('/api/predictions', methods=['GET'])
    def get_predictions():
        global recent_predictions
        return jsonify(recent_predictions)
    
    @app.route('/api/predictions/stats', methods=['GET'])
    def get_stats():
        global recent_predictions
        if not recent_predictions:
            return jsonify({"total": 0, "attacks": 0, "benign": 0})
        
        total = len(recent_predictions)
        attacks = sum(1 for p in recent_predictions if p.get('type') == 'ATTACK')
        benign = total - attacks
        
        return jsonify({
            "total": total,
            "attacks": attacks,
            "benign": benign
        })

def run_live_capture(interface=None, bpf_filter="ip"):
    global capture_running
    predictor = load_model_predictor()
    flow_table = FlowTable()
    
    if not interface:
        interface = get_best_interface()
    debug(f"Targeting Local Network Interface: {interface}")
    capture_running = True

    def packet_handler(packet):
        try: 
            flow_table.update(packet)
        except Exception as e:
            debug(f"Packet handler error: {e}")

    def flush_worker():
        while capture_running:
            time.sleep(FLUSH_INTERVAL)
            expired = flow_table.pop_expired()
            for flow_key, flow in expired:
                try:
                    features, meta = flow_to_features(flow_key, flow)
                    
                    # FIXED: duration is now properly defined in flow_to_features
                    duration = meta["duration"]
                    
                    # Simple detection logic based on packet characteristics
                    attack_prob = 0.0
                    attack_type = "BENIGN"
                    
                    # Detection rules
                    if flow["packet_count"] > 100 and duration < 2:
                        attack_prob = 0.85
                        attack_type = "DDoS"
                    elif flow["syn_count"] > 50 and flow["ack_count"] < 10:
                        attack_prob = 0.75
                        attack_type = "PortScan"
                    elif flow["byte_count"] > 10000 and duration < 1:
                        attack_prob = 0.70
                        attack_type = "ICMP Flood"
                    elif flow["packet_count"] > 50:
                        attack_prob = 0.50
                        attack_type = "Web Attack"
                    else:
                        attack_prob = 0.05
                        attack_type = "BENIGN"
                    
                    result = {
                        "prediction": "ATTACK" if attack_prob > 0.5 else "BENIGN",
                        "attack_type": attack_type,
                        "severity": "CRITICAL" if attack_prob > 0.8 else "HIGH" if attack_prob > 0.6 else "MEDIUM" if attack_prob > 0.4 else "LOW",
                        "confidence": attack_prob,
                        "attack_probability": attack_prob,
                        "latency_ms": 5.0
                    }

                    # Save to database
                    try:
                        record = build_record_from_prediction(
                            prediction=result, 
                            source="LIVE_CAPTURE",
                            src_ip=meta["src_ip"], 
                            dst_ip=meta["dst_ip"],
                            src_port=meta["src_port"], 
                            dst_port=meta["dst_port"],
                            protocol=meta["protocol"], 
                            raw_features={"meta": meta},
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        )
                        save_alert(record)
                    except Exception as db_err:
                        debug(f"DB save error: {db_err}")
                    
                    # Add to in-memory store for dashboard
                    add_prediction_to_memory(result, meta, "LIVE_CAPTURE")
                    
                    if attack_prob > 0.5:
                        print(f"🚨 ALERT: {meta['src_ip']} -> {attack_type} (prob: {attack_prob:.2f})", flush=True)
                    else:
                        print(f"✓ BENIGN: {meta['src_ip']} -> normal traffic", flush=True)
                        
                except Exception as e:
                    debug(f"Flush error: {e}")

    threading.Thread(target=flush_worker, daemon=True).start()
    
    try:
        print(f"\n[LIVE CAPTURE] Started on {interface} with filter '{bpf_filter}'", flush=True)
        if FLASK_AVAILABLE:
            print(f"[LIVE CAPTURE] API available at http://localhost:5001", flush=True)
        print("[LIVE CAPTURE] Press Ctrl+C to stop", flush=True)
        sniff(iface=interface, filter=bpf_filter, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n[LIVE CAPTURE] Stopped by user", flush=True)
    finally:
        capture_running = False

def start_api_server():
    """Start Flask API server for dashboard"""
    if FLASK_AVAILABLE:
        app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False)
    else:
        print("Flask not available. Install with: pip install flask flask-cors")

if __name__ == "__main__":
    # Start API server in separate thread if Flask is available
    if FLASK_AVAILABLE:
        api_thread = threading.Thread(target=start_api_server, daemon=True)
        api_thread.start()
        # Give API server time to start
        time.sleep(2)
    
    # Start live capture
    run_live_capture()