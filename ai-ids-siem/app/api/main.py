from pathlib import Path
from datetime import datetime
from typing import List, Optional
import csv
import io

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.storage.repository import (
    init_db,
    save_alert,
    get_alerts,
    get_latest_alerts,
    get_summary,
    clear_alerts,
)
from app.storage.models import build_record_from_prediction
from app.capture.live_capture import load_model_predictor

app = FastAPI(title="Sentinel IDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# dashboard_dir = app/dashboard
dashboard_dir = Path(__file__).resolve().parents[1] / "dashboard"

# Serve everything in app/dashboard under /dashboard-assets
app.mount(
    "/dashboard-assets",
    StaticFiles(directory=str(dashboard_dir)),
    name="dashboard-assets",
)

init_db()
predictor = load_model_predictor()


class PredictRequest(BaseModel):
    features: List[float]
    source: Optional[str] = "MANUAL"


class BatchRequest(BaseModel):
    rows: List[List[float]]
    source: Optional[str] = "BATCH"


@app.get("/")
def root():
    return {"message": "Sentinel IDS API running"}


@app.get("/dashboard")
def dashboard():
    # Serve the HTML file from app/dashboard/index.html
    return FileResponse(dashboard_dir / "index.html")


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": predictor["loaded"],
        "feature_count": predictor["feature_count"],
        "model_type": predictor["model_type"],
    }


@app.get("/model-info")
def model_info():
    return {
        "model_loaded": predictor["loaded"],
        "model_type": predictor["model_type"],
        "feature_count": predictor["feature_count"],
        "classes": predictor["classes"],
        "note": "Live traffic must be mapped to the same feature schema used during training.",
    }


@app.get("/alerts")
def alerts(limit: int = 200):
    return get_alerts(limit=limit)


@app.get("/alerts/latest")
def alerts_latest(limit: int = 30):
    return get_latest_alerts(limit=limit)


@app.get("/metrics/summary")
def metrics_summary():
    return get_summary()


@app.delete("/alerts")
def delete_alerts():
    clear_alerts()
    return {"message": "All alerts cleared"}


@app.post("/predict")
def predict_single(payload: PredictRequest):
    result = predictor["predict_func"](payload.features)
    record = build_record_from_prediction(
        prediction=result,
        source=payload.source or "MANUAL",
        src_ip="manual",
        dst_ip="sensor",
        src_port=0,
        dst_port=0,
        protocol="N/A",
        raw_features={"feature_count": len(payload.features)},
        timestamp=datetime.utcnow().isoformat(),
    )
    save_alert(record)
    return result


@app.post("/predict-batch")
def predict_batch(payload: BatchRequest):
    outputs = []
    for row in payload.rows:
        result = predictor["predict_func"](row)
        record = build_record_from_prediction(
            prediction=result,
            source=payload.source or "BATCH",
            src_ip="batch",
            dst_ip="sensor",
            src_port=0,
            dst_port=0,
            protocol="N/A",
            raw_features={"feature_count": len(row)},
            timestamp=datetime.utcnow().isoformat(),
        )
        save_alert(record)
        outputs.append(result)
    return {"count": len(outputs), "predictions": outputs}


@app.post("/predict-csv")
async def predict_csv(file: UploadFile = File(...)):
    content = await file.read()
    decoded = content.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(decoded))

    predictions = []
    for row in reader:
        features = []
        for i in range(predictor["feature_count"]):
            key = f"feature_{i}"
            features.append(float(row.get(key, 0) or 0))
        result = predictor["predict_func"](features)
        record = build_record_from_prediction(
            prediction=result,
            source="CSV",
            src_ip="csv",
            dst_ip="sensor",
            src_port=0,
            dst_port=0,
            protocol="N/A",
            raw_features={"feature_count": len(features)},
            timestamp=datetime.utcnow().isoformat(),
        )
        save_alert(record)
        predictions.append(result)

    return {"count": len(predictions), "predictions": predictions}