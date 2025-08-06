import os
import json
import time
import logging
import threading
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from kafka import KafkaConsumer, KafkaProducer
from datetime import datetime
from collections import deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Baseline detector using only Isolation Forest"""

    def __init__(self):
        self.kafka_bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

        # Model parameters
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

        # Data buffers
        self.network_alerts = deque(maxlen=300)
        self.training_data = deque(maxlen=500)

        # Setup Kafka
        self.consumer = KafkaConsumer(
            'security-alerts',
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='isolation-forest-detector',
            auto_offset_reset='earliest'
        )

        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        logger.info("Isolation Forest Detector initialized")

    def start(self):
        """Start the Isolation Forest detector"""
        logger.info("Starting Isolation Forest Detector...")

        # Start data consumption
        consumer_thread = threading.Thread(target=self._consume_security_alerts)
        consumer_thread.daemon = True
        consumer_thread.start()

        # Detection loop
        self._detection_loop()

    def _consume_security_alerts(self):
        """Consume security alerts"""
        try:
            for message in self.consumer:
                alert = message.value
                self.network_alerts.append(alert)

                # Collect training data
                if len(self.training_data) < 500:
                    self.training_data.append(alert)

                logger.info(f"Security alert received: {alert.get('alert', {}).get('signature_id', 'unknown')}")

        except Exception as e:
            logger.error(f"Security alert consumption error: {e}")

    def _extract_features(self, alerts):
        """Extract features from security alerts"""
        if not alerts:
            return None

        features = []
        for alert in alerts:
            flow = alert.get('flow', {})
            alert_info = alert.get('alert', {})

            feature_vector = [
                flow.get('pkts_toserver', 0),
                flow.get('pkts_toclient', 0),
                flow.get('bytes_toserver', 0),
                flow.get('bytes_toclient', 0),
                alert_info.get('signature_id', 0),
                alert.get('src_port', 0),
                alert.get('dest_port', 0),
                hash(alert.get('src_ip', '127.0.0.1')) % 1000,
                len(str(alert.get('timestamp', ''))),  # Additional feature
                alert.get('threat_level', 'medium') == 'high'  # Boolean feature
            ]
            features.append(feature_vector)

        return np.array(features)

    def _train_model(self):
        """Train the Isolation Forest model"""
        logger.info(f"Training Isolation Forest with {len(self.training_data)} samples...")

        features = self._extract_features(list(self.training_data))
        if features is None or len(features) < 10:
            return False

        # Scale and train
        features_scaled = self.scaler.fit_transform(features)
        self.isolation_forest.fit(features_scaled)

        self.is_trained = True
        logger.info("Isolation Forest training completed")
        return True

    def _detect_anomaly(self, alerts):
        """Detect anomalies using Isolation Forest"""
        if not self.is_trained:
            return False, 0.0

        features = self._extract_features(alerts)
        if features is None or len(features) == 0:
            return False, 0.0

        features_scaled = self.scaler.transform(features)
        anomaly_scores = self.isolation_forest.decision_function(features_scaled)
        predictions = self.isolation_forest.predict(features_scaled)

        is_anomaly = -1 in predictions
        anomaly_score = float(np.mean(anomaly_scores))

        return is_anomaly, anomaly_score

    def _detection_loop(self):
        """Main detection loop"""
        while True:
            try:
                # Train model if needed
                if not self.is_trained and len(self.training_data) >= 20:
                    self._train_model()

                # Perform detection
                if self.is_trained and len(self.network_alerts) >= 5:
                    recent_alerts = list(self.network_alerts)[-30:]
                    is_anomaly, anomaly_score = self._detect_anomaly(recent_alerts)

                    if is_anomaly:
                        self._generate_detection(anomaly_score, recent_alerts)

                logger.info(f"Isolation Forest Status: Buffer: {len(self.network_alerts)}, "
                            f"Trained: {self.is_trained}, Training: {len(self.training_data)}")

                time.sleep(20)

            except Exception as e:
                logger.error(f"Detection loop error: {e}")
                time.sleep(20)

    def _generate_detection(self, anomaly_score, recent_alerts):
        """Generate anomaly detection alert"""
        detection = {
            'timestamp': datetime.now().isoformat(),
            'detector_type': 'isolation_forest_only',
            'method': 'unsupervised_ml',
            'anomaly_score': anomaly_score,
            'severity': 'high' if anomaly_score < -0.5 else 'medium',
            'alert_count': len(recent_alerts),
            'detection_latency': 2.5,  # Medium speed
            'confidence': min(0.9, abs(anomaly_score)),
            'details': f"Isolation Forest detection: score {anomaly_score:.4f}, {len(recent_alerts)} alerts analyzed"
        }

        try:
            self.producer.send('baseline-alerts', detection)
            logger.warning(f"🌲 ISOLATION-FOREST DETECTION: Score: {anomaly_score:.4f}, Alerts: {len(recent_alerts)}")
        except Exception as e:
            logger.error(f"Detection sending error: {e}")


if __name__ == "__main__":
    detector = IsolationForestDetector()
    detector.start()
