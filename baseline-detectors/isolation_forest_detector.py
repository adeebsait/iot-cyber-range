import os
import json
import logging
import numpy as np
from kafka import KafkaConsumer, KafkaProducer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def to_native(obj):
    if isinstance(obj, (np.generic,)):
        return obj.item()
    return obj

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
            auto_offset_reset='earliest',
            consumer_timeout_ms=10000
        )
        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_servers],
            value_serializer=lambda v: json.dumps(to_native(v)).encode('utf-8')
        )
        self.min_samples = 50

    def run(self):
        for msg in self.consumer:
            data = msg.value
            features = self._extract_features(data)
            self.training_data.append(features)
            if not self.trained and len(self.training_data) >= self.min_samples:
                self._train()
            if self.trained:
                self._detect(data, features)

    def _extract_features(self, data):
        return [
            data.get('heart_rate', 0),
            data.get('spo2', 0),
            data.get('body_temp', 0)
        ]

    def _train(self):
        X = np.array(self.training_data)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.trained = True
        logger.info("Isolation Forest training complete")

    def _detect(self, data, features):
        feat_scaled = self.scaler.transform([features])
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
                'confidence': min(1.0, abs(score)),
                'details': data
            }
            try:
                self.producer.send('baseline-alerts', alert)
                self.producer.flush()
                logger.info("🔔 Alert sent to baseline-alerts")
            except Exception as e:
                logger.error(f"Alert sending error: {e}")

if __name__ == "__main__":
    IsolationForestDetector().run()
