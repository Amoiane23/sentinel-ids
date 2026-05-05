from fastapi import APIRouter
from app.storage.repository import get_alerts, get_latest_alerts, get_summary

router = APIRouter()

@router.get('/health')
def health():
    return {'status': 'healthy', 'model_loaded': True}

@router.get('/model-info')
def model_info():
    return {'model_name': 'Sentinel Mock IDS', 'feature_count': 63, 'classes': ['BENIGN', 'PortScan', 'DDoS', 'Web Attack - XSS', 'Botnet']}

@router.get('/alerts')
def alerts(limit: int = 200):
    return get_alerts(limit)

@router.get('/alerts/latest')
def latest(limit: int = 20):
    return get_latest_alerts(limit)

@router.get('/metrics/summary')
def summary():
    return get_summary()