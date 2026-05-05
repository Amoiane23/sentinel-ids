from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, List
from sklearn.preprocessing import LabelEncoder

class IDSPredictor:
    def __init__(self, model_path: str, features_path: str):
        """Initialize predictor with trained model and feature schema"""
        self.model_path = Path(model_path)
        self.features_path = Path(features_path)
        
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        if not self.features_path.exists():
            raise FileNotFoundError(f"Features not found: {self.features_path}")
        
        self.pipeline = joblib.load(self.model_path)
        self.feature_columns = joblib.load(self.features_path)
        
        self.class_encoder = LabelEncoder()
        self.class_encoder.fit(self.pipeline.classes_)
        
        self.severity_map = {
            'Benign': 'INFO',
            'Bot': 'CRITICAL',
            'DDoS': 'CRITICAL',
            'DoS Hulk': 'HIGH',
            'DoS GoldenEye': 'HIGH', 
            'DoS slowloris': 'HIGH',
            'DoS Slowhttptest': 'HIGH',
            'FTP-Patator': 'HIGH',
            'SSH-Patator': 'HIGH',
            'Heartbleed': 'CRITICAL',
            'Web Attack Brute Force': 'HIGH',
            'Web Attack XSS': 'MEDIUM',
            'Web Attack Sql Injection': 'CRITICAL',
            'Infiltration': 'CRITICAL',
            'PortScan': 'MEDIUM',
        }
    
    def predict_single(self, features: List[float]) -> Dict[str, Any]:
        """Predict a single network flow"""
        if len(features) != len(self.feature_columns):
            raise ValueError(
                f"Expected {len(self.feature_columns)} features, got {len(features)}"
            )
        
        X = pd.DataFrame([dict(zip(self.feature_columns, features))])
        
        prediction = self.pipeline.predict(X)[0]
        probabilities = self.pipeline.predict_proba(X)[0]
        max_proba = float(np.max(probabilities))
        
        # Determine severity
        severity = self.severity_map.get(prediction, 'UNKNOWN')
        
        return {
            'predicted_label': prediction,
            'confidence': max_proba,
            'probabilities': dict(zip(self.pipeline.classes_, probabilities)),
            'severity': severity,
            'features_used': len(features)
        }
    
    def batch_predict(self, features_batch: List[List[float]]) -> List[Dict[str, Any]]:
        """Predict multiple flows"""
        results = []
        for features in features_batch:
            try:
                result = self.predict_single(features)
                results.append(result)
            except Exception as e:
                results.append({
                    'error': str(e),
                    'features_used': len(features) if features else 0
                })
        return results
    
    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata for dashboard"""
        return {
            'model_path': str(self.model_path),
            'num_features': len(self.feature_columns),
            'num_classes': len(self.pipeline.classes_),
            'classes': list(self.pipeline.classes_),
            'feature_columns': self.feature_columns
        }

# Usage example for testing
if __name__ == "__main__":
    predictor = IDSPredictor(
        "models/artifacts/rf_multiclass_pipeline.joblib",
        "models/artifacts/feature_columns.joblib"
    )
    
    # Test prediction
    mock_features = np.random.normal(0, 1, len(predictor.feature_columns)).tolist()
    result = predictor.predict_single(mock_features)
    print("Test prediction:", result)
    
    print("Model info:", predictor.get_model_info())