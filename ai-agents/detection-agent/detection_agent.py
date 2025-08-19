import os
import json
import time
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import deque
import threading
import logging
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from kafka import KafkaConsumer, KafkaProducer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LSTMAutoencoder:
    def __init__(self, sequence_length=10, n_features=4):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.model = self._build_model()
        self.scaler = StandardScaler()
        self.is_trained = False
        self.threshold = 0.05

    def _build_model(self):
        model = tf.keras.Sequential([
            # Encoder
            tf.keras.layers.LSTM(50, activation='relu', input_shape=(self.sequence_length, self.n_features),
                                 return_sequences=True),
            tf.keras.layers.LSTM(25, activation='relu', return_sequences=False),
            tf.keras.layers.RepeatVector(self.sequence_length),
            # Decoder
            tf.keras.layers.LSTM(25, activation='relu', return_sequences=True),
            tf.keras.layers.LSTM(50, activation='relu', return_sequences=True),
            tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(self.n_features))
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def preprocess_data(self, data):
        """Convert list of device readings to sequences"""
        if len(data) < self.sequence_length:
            return None

        # Extract features: heart_rate, spo2, body_temp, timestamp_normalized
        features = []
        for reading in data:
            features.append([
                reading.get('heart_rate', 75),
                reading.get('spo2', 98),
                reading.get('body_temp', 36.5),
                reading.get('timestamp', 0) % 86400  # Time of day normalization
            ])

        # Create sequences
        sequences = []
        for i in range(len(features) - self.sequence_length + 1):
            sequences.append(features[i:i + self.sequence_length])

        return np.array(sequences)

    def train(self, training_data, epochs=50):
        """Train the autoencoder on normal data"""
        logger.info(f"Training LSTM autoencoder with {len(training_data)} samples...")
        sequences = self.preprocess_data(training_data)
        if sequences is None or len(sequences) < 5:
            logger.warning("Insufficient data for training")
            return False

        # Reshape and scale
        n_samples, seq_len, n_feat = sequences.shape
        sequences_reshaped = sequences.reshape(-1, n_feat)
        sequences_scaled = self.scaler.fit_transform(sequences_reshaped)
        sequences_scaled = sequences_scaled.reshape(n_samples, seq_len, n_feat)

        # Train model
        history = self.model.fit(
            sequences_scaled, sequences_scaled,
            epochs=epochs, batch_size=16, verbose=0,
            validation_split=0.2
        )

        # Calculate threshold based on training reconstruction error
        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))
        self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold

        self.is_trained = True
        logger.info(f"LSTM training completed. Threshold: {self.threshold:.4f}")
        return True

    def detect_anomaly(self, data):
        """Detect anomalies in new data"""
        if not self.is_trained:
            return False, 0.0, "Model not trained"

        sequences = self.preprocess_data(data)
        if sequences is None:
            return False, 0.0, "Insufficient data"

        # Scale and predict
        n_samples, seq_len, n_feat = sequences.shape
        sequences_reshaped = sequences.reshape(-1, n_feat)
        sequences_scaled = self.scaler.transform(sequences_reshaped)
        sequences_scaled = sequences_scaled.reshape(n_samples, seq_len, n_feat)

        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))
        max_error = np.max(mse)

        is_anomaly = max_error > self.threshold
        return is_anomaly, float(max_error), f"Threshold: {self.threshold:.4f}"


class NetworkTrafficAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    def extract_network_features(self, alerts_data):
        """Extract network-level features from Suricata alerts"""
        if not alerts_data:
            return None

        features = []
        for alert in alerts_data:
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
                hash(alert.get('src_ip', '127.0.0.1')) % 1000  # IP hash
            ]
            features.append(feature_vector)

        return np.array(features) if features else None

    def train(self, training_alerts):
        """Train isolation forest on normal network patterns"""
        logger.info(f"Training network analyzer with {len(training_alerts)} alerts...")
        features = self.extract_network_features(training_alerts)
        if features is None or len(features) < 10:
            logger.warning("Insufficient network data for training")
            return False

        features_scaled = self.scaler.fit_transform(features)
        self.isolation_forest.fit(features_scaled)
        self.is_trained = True
        logger.info("Network analyzer training completed")
        return True

    def detect_anomaly(self, alerts_data):
        """Detect network anomalies"""
        if not self.is_trained:
            return False, 0.0, "Model not trained"

        features = self.extract_network_features(alerts_data)
        if features is None or len(features) == 0:
            return False, 0.0, "No network data"

        features_scaled = self.scaler.transform(features)
        anomaly_scores = self.isolation_forest.decision_function(features_scaled)
        predictions = self.isolation_forest.predict(features_scaled)

        is_anomaly = -1 in predictions
        anomaly_score = float(np.mean(anomaly_scores))
        return is_anomaly, anomaly_score, f"Samples: {len(features)}"


class DetectionAgent:
    def __init__(self):
        # Initialize AI models
        self.lstm_autoencoder = LSTMAutoencoder()
        self.network_analyzer = NetworkTrafficAnalyzer()

        # Data buffers
        self.device_data_buffer = deque(maxlen=500)
        self.network_alerts_buffer = deque(maxlen=200)
        self.training_data = deque(maxlen=2000)

        # Kafka setup
        self.kafka_bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        self.kafka_consumer = KafkaConsumer(
            'device-telemetry', 'security-alerts',
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='detection-agent',
            auto_offset_reset='earliest',
            enable_auto_commit=True,
        )

        self.kafka_producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        # Training parameters
        self.training_period = 120  # Train every 2 minutes
        self.last_training_time = 0
        self.min_training_samples = 30

        # Detection state
        self.detection_active = False

        # Fusion parameters
        self.fusion_threshold = 0.6
        self.high_confidence_threshold = 0.8

    def start(self):
        """Start the detection agent"""
        logger.info("Starting AI Detection Agent with Hybrid Fusion...")

        # Start Kafka consumer thread
        kafka_thread = threading.Thread(target=self._kafka_consumer_loop)
        kafka_thread.daemon = True
        kafka_thread.start()

        # Start detection loop
        self._detection_loop()

    def _kafka_consumer_loop(self):
        """Consume messages from Kafka"""
        try:
            logger.info("Starting Kafka consumer loop...")
            for message in self.kafka_consumer:
                logger.info(f"Received message from topic: {message.topic}")
                if message.topic == 'device-telemetry':
                    self.device_data_buffer.append(message.value)
                    # Collect training data (assuming initial data is normal)
                    if len(self.training_data) < 2000:
                        self.training_data.append(message.value)
                    logger.info(
                        f"Device telemetry added. Buffer size: {len(self.device_data_buffer)}, Training data: {len(self.training_data)}")
                elif message.topic == 'security-alerts':
                    self.network_alerts_buffer.append(message.value)
                    logger.info(f"Security alert added. Buffer size: {len(self.network_alerts_buffer)}")
        except Exception as e:
            logger.error(f"Kafka consumer error: {e}")

    def _detection_loop(self):
        """Main detection loop"""
        while True:
            try:
                current_time = time.time()

                # Check if we need to train models
                if (current_time - self.last_training_time > self.training_period and
                        len(self.training_data) >= self.min_training_samples and
                        not self.detection_active):
                    logger.info("Training conditions met, starting training...")
                    self._train_models()
                    self.last_training_time = current_time

                # Perform hybrid detection if models are trained
                if self.detection_active:
                    self._perform_hybrid_detection()

                logger.info(f"Status: Device buffer: {len(self.device_data_buffer)}, "
                            f"Network buffer: {len(self.network_alerts_buffer)}, "
                            f"Training data: {len(self.training_data)}, "
                            f"Detection active: {self.detection_active}")

                time.sleep(15)  # Status update every 15 seconds
            except Exception as e:
                logger.error(f"Detection loop error: {e}")
                time.sleep(10)

    def _train_models(self):
        """Train both AI models"""
        logger.info("Training AI models...")
        try:
            # Train LSTM autoencoder
            training_list = list(self.training_data)
            device_trained = self.lstm_autoencoder.train(training_list)

            # Train network analyzer
            alerts_list = list(self.network_alerts_buffer)
            network_trained = self.network_analyzer.train(alerts_list)

            if device_trained or network_trained:
                self.detection_active = True
                logger.info("AI models training completed - HYBRID DETECTION ACTIVE")
            else:
                logger.warning("Both model training failed")
        except Exception as e:
            logger.error(f"Training error: {e}")

    def _perform_hybrid_detection(self):
        """Perform hybrid anomaly detection with decision fusion"""
        try:
            # Get detection results from both models
            device_anomaly, device_score, device_info = False, 0.0, "No data"
            network_anomaly, network_score, network_info = False, 0.0, "No data"

            # Device-level anomaly detection (LSTM)
            if len(self.device_data_buffer) >= 10:
                recent_device_data = list(self.device_data_buffer)[-50:]
                device_anomaly, device_score, device_info = self.lstm_autoencoder.detect_anomaly(recent_device_data)

            # Network-level anomaly detection (Isolation Forest)
            if len(self.network_alerts_buffer) >= 5:
                recent_alerts = list(self.network_alerts_buffer)[-20:]
                network_anomaly, network_score, network_info = self.network_analyzer.detect_anomaly(recent_alerts)

            # HYBRID DECISION FUSION - THE KEY IMPROVEMENT
            fused_decision = self._fuse_detection_decisions(
                device_anomaly, device_score,
                network_anomaly, network_score
            )

            # Generate alert only if fused decision indicates threat
            if fused_decision['is_threat']:
                self._generate_fused_alert(fused_decision, device_info, network_info)

            # Log detection status
            logger.info(f"Detection Status - Device: {device_anomaly} ({device_score:.4f}), "
                        f"Network: {network_anomaly} ({network_score:.4f}), "
                        f"Fused: {fused_decision['is_threat']} ({fused_decision['fused_score']:.4f})")

        except Exception as e:
            logger.error(f"Hybrid detection error: {e}")

    def _fuse_detection_decisions(self, device_anomaly, device_score, network_anomaly, network_score):
        """Implement hybrid decision fusion algorithm"""

        # Adaptive weights based on detection confidence
        device_weight = 0.7 if device_anomaly else 0.4
        network_weight = 0.8 if network_anomaly else 0.3

        # Normalize weights
        total_weight = device_weight + network_weight
        device_weight /= total_weight
        network_weight /= total_weight

        # Normalize scores to [0,1] range for fusion
        device_score_norm = min(1.0, max(0.0, device_score / 0.2))  # LSTM threshold ~0.05-0.2
        network_score_norm = min(1.0, max(0.0, abs(network_score + 0.5) / 1.0))  # IsolationForest range

        # Fused anomaly score using weighted combination
        fused_score = (device_weight * device_score_norm) + (network_weight * network_score_norm)

        # Enhanced fusion logic - multiple pathways to threat detection
        if device_anomaly and network_anomaly:
            # Both models detect anomaly - HIGHEST confidence
            is_threat = True
            confidence = 0.95
            reason = "Both LSTM and Isolation Forest detected anomalies (CRITICAL)"
        elif device_anomaly and fused_score > 0.5:
            # LSTM detection with supporting evidence
            is_threat = True
            confidence = 0.85
            reason = "LSTM detection with network correlation evidence"
        elif network_anomaly and fused_score > 0.5:
            # Network detection with device correlation
            is_threat = True
            confidence = 0.80
            reason = "Network anomaly with device correlation evidence"
        elif fused_score > self.fusion_threshold:
            # High fusion score even without individual detection
            is_threat = True
            confidence = 0.75
            reason = "High fusion score indicates coordinated threat"
        elif (device_score > self.lstm_autoencoder.threshold * 1.5 or
              abs(network_score) > 0.3) and fused_score > 0.4:
            # Lower threshold for elevated individual scores
            is_threat = True
            confidence = 0.65
            reason = "Elevated individual scores with fusion support"
        else:
            is_threat = False
            confidence = fused_score
            reason = "Insufficient evidence for threat classification"

        return {
            'is_threat': is_threat,
            'fused_score': fused_score,
            'confidence': confidence,
            'reason': reason,
            'device_contribution': device_weight * device_score_norm,
            'network_contribution': network_weight * network_score_norm,
            'device_detected': device_anomaly,
            'network_detected': network_anomaly,
            'fusion_weights': {
                'device_weight': device_weight,
                'network_weight': network_weight
            }
        }

    def _generate_fused_alert(self, fused_decision, device_info, network_info):
        """Generate hybrid alert with comprehensive fusion details"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'hybrid_threat_detection',
            'source': 'multi_agent_fusion',
            'fused_anomaly_score': fused_decision['fused_score'],
            'confidence': fused_decision['confidence'],
            'severity': self._determine_severity(fused_decision['confidence']),
            'fusion_reason': fused_decision['reason'],
            'device_contribution': fused_decision['device_contribution'],
            'network_contribution': fused_decision['network_contribution'],
            'fusion_weights': fused_decision['fusion_weights'],
            'detection_methods': {
                'lstm_detected': fused_decision['device_detected'],
                'isolation_forest_detected': fused_decision['network_detected']
            },
            'details': {
                'device_info': device_info,
                'network_info': network_info
            },
            'agent_type': 'multi_agent',
            'fusion_algorithm': 'adaptive_weighted_hybrid'
        }

        self._send_alert(alert)
        logger.warning(f"🔥 HYBRID THREAT DETECTED: Score: {fused_decision['fused_score']:.3f}, "
                       f"Confidence: {fused_decision['confidence']:.3f}, "
                       f"Severity: {alert['severity']}, "
                       f"Reason: {fused_decision['reason']}")

    def _determine_severity(self, confidence):
        """Determine alert severity based on confidence"""
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.8:
            return 'high'
        elif confidence >= 0.6:
            return 'medium'
        else:
            return 'low'

    def _send_alert(self, alert):
        """Send alert to response agent and evaluation system"""
        try:
            # Send to AI alerts topic for evaluation
            self.kafka_producer.send('ai-alerts', alert)
            logger.info(f"🔔 Hybrid AI Alert sent: {alert['type']} - {alert['severity']} "
                        f"(Confidence: {alert['confidence']:.3f})")
        except Exception as e:
            logger.error(f"Alert sending error: {e}")


if __name__ == "__main__":
    agent = DetectionAgent()
    agent.start()
