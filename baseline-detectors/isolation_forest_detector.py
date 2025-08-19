import os
import json
import logging
import numpy as np
from kafka import KafkaConsumer, KafkaProducer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from detection_agent import to_native  # import helper from detection_agent.py

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IsolationForestDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.training_data = []
        self.trained = False
        self.kafka_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        self.consumer = KafkaConsumer(
            'device-telemetry',
            bootstrap_servers=[self.kafka_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='isolation-forest-detector',
            auto_offset_reset='earliest'
        )
        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_servers],
            value_serializer=lambda v: json.dumps(to_native(v)).encode('utf-8')
        )
        self.min_samples = 50

    def run(self):
        for msg in self.consumer:
            data = msg.value
            self.training_data.append(self._extract_features(data))
            if not self.trained and len(self.training_data) >= self.min_samples:
                self._train()
            if self.trained:
                self._detect(data)

    def _extract_features(self, data):
        # Example features, adjust to your telemetry schema
        return [
            data.get('heart_rate', 0),
            data.get('spo2', 0),
            data.get('body_temp', 0)
        ]

    def _train(self):
        logger.info("Training Isolation Forest with %d samples", len(self.training_data))
        X = np.array(self.training_data)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.trained = True
        logger.info("Isolation Forest training complete")

    def _detect(self, data):
        feat = np.array(self._extract_features(data)).reshape(1, -1)
        feat_scaled = self.scaler.transform(feat)
        pred = self.model.predict(feat_scaled)[0]
        score = float(self.model.decision_function(feat_scaled))
        if pred == -1:
            alert = {
                'timestamp': data.get('timestamp'),
                'detector_type': 'isolation_forest_only',
                'method': 'isolation_forest',
                'anomaly_score': score,
                'threshold': None,
                'severity': 'high',
                'device_id': data.get('device_id'),
                'confidence': float(min(1, abs(score))),
                'details': f'IsolationForest anomaly (score {score:.4f})'
            }
            try:
                self.producer.send('baseline-alerts', alert)
                self.producer.flush()
                logger.info("🔔 Alert sent to baseline-alerts")
            except Exception as e:
                logger.error(f"Alert sending error: {e}")

if __name__ == "__main__":
    IsolationForestDetector().run()
