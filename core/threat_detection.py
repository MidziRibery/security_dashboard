### threat_detection.py - Machine Learning and Threat Detection Logic

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any

class ThreatDetectionEngine:
    def __init__(self):
        self.feature_columns = [
            'packet_size',
            'protocol',
            'flags',
            'packet_rate',
            'flow_duration',
            'bytes_per_second',
            'packets_per_second',
            'avg_packet_size',
            'port_entropy',
            'ip_entropy'
        ]
        self.models = {
            'anomaly': IsolationForest(contamination=0.1, random_state=42),
            'classifier': RandomForestClassifier(n_estimators=100, random_state=42),
            'behavior': IsolationForest(contamination=0.05, random_state=42)
        }
        self.scaler = StandardScaler()
        self._initialize_default_models()

    def extract_features(self, packet: Dict) -> pd.DataFrame:
        """Extract features ensuring consistent column names"""
        features = {col: 0 for col in self.feature_columns}  # Initialize with zeros

        features.update({
            'packet_size': len(packet),
            'protocol': hash(packet.get('protocol', 0)) % 100,
            'flags': len(packet.get('flags', [])),
            'packet_rate': packet.get('packet_rate', 0),
            'flow_duration': packet.get('flow_duration', 0),
            'bytes_per_second': packet.get('bytes_per_second', 0),
            'packets_per_second': packet.get('packets_per_second', 0),
            'avg_packet_size': packet.get('avg_packet_size', 0),
            'port_entropy': self._calculate_entropy(packet.get('ports', [])),
            'ip_entropy': self._calculate_entropy(packet.get('ips', []))
        })

        return pd.DataFrame([features], columns=self.feature_columns)

    def predict_threat(self, packet: Dict) -> Dict[str, Any]:
        """Predict threat ensuring feature names match"""
        features_df = self.extract_features(packet)
        scaled_features = self.scaler.transform(features_df)

        predictions = {
            'anomaly_score': self.models['anomaly'].score_samples(scaled_features)[0],
            'classification': self.models['classifier'].predict(scaled_features)[0],
            'behavior_score': self.models['behavior'].score_samples(scaled_features)[0]
        }

        return {
            **predictions,
            'threat_score': self._calculate_threat_score(predictions),
            'is_threat': self._calculate_threat_score(predictions) > 0.7
        }

    def _initialize_default_models(self):
        """Initialize models and scaler with default values"""
        sample_data = pd.DataFrame({
            'packet_size': [100, 200, 1500, 64, 1000],
            'protocol': [6, 17, 1, 6, 17],
            'flags': [1, 2, 0, 1, 2],
            'packet_rate': [10, 20, 5, 15, 25],
            'flow_duration': [1.0, 2.0, 0.5, 1.5, 2.5],
            'bytes_per_second': [1000, 2000, 500, 1500, 2500],
            'packets_per_second': [10, 20, 5, 15, 25],
            'avg_packet_size': [100, 150, 200, 80, 160],
            'port_entropy': [0.5, 0.7, 0.3, 0.6, 0.8],
            'ip_entropy': [0.3, 0.4, 0.2, 0.5, 0.6]
        })
        self.scaler.fit(sample_data)
        sample_labels = [0, 0, 1, 0, 1]  # 0: normal, 1: anomaly

        self.models['anomaly'].fit(sample_data)
        self.models['classifier'].fit(sample_data, sample_labels)
        self.models['behavior'].fit(sample_data)

        os.makedirs('models', exist_ok=True)
        for name, model in self.models.items():
            joblib.dump(model, f'models/{name}_model.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')

    def _calculate_entropy(self, values: List) -> float:
        """Calculate Shannon entropy for a list of values"""
        if not values:
            return 0.0
        value_counts = pd.Series(values).value_counts(normalize=True)
        return -(value_counts * np.log2(value_counts)).sum()

    def _calculate_threat_score(self, predictions: Dict) -> float:
        """Calculate overall threat score"""
        weights = {
            'anomaly': 0.4,
            'classification': 0.4,
            'behavior': 0.2
        }

        return sum(
            weights[key] * (1 - np.exp(predictions[f'{key}_score']))
            if key != 'classification' else
            weights[key] * predictions[key]
            for key in weights
        )

    def train(self, training_data: pd.DataFrame) -> None:
        """Train ML models with labeled data"""
        X = training_data[self.feature_columns]
        y = training_data['is_threat']

        X_train_scaled = self.scaler.fit_transform(X)
        self.models['anomaly'].fit(X_train_scaled)
        self.models['classifier'].fit(X_train_scaled, y)
        self.models['behavior'].fit(X_train_scaled)

        self._save_models()

    def _save_models(self):
        """Save trained models to disk"""
        for name, model in self.models.items():
            joblib.dump(model, f'models/{name}_model.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')

    def load_models(self):
        """Load trained models from disk"""
        for name in self.models.keys():
            model_path = f'models/{name}_model.pkl'
            if os.path.exists(model_path):
                self.models[name] = joblib.load(model_path)

        scaler_path = 'models/scaler.pkl'
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
