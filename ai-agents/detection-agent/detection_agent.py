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
            auto_offset_reset='earliest',  # Changed from 'latest' to 'earliest'
            enable_auto_commit=True,
            consumer_timeout_ms=1000  # Add timeout to prevent hanging
        )

        self.kafka_producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        # Training parameters
        self.training_period = 120  # Train every 2 minutes (reduced for faster demo)
        self.last_training_time = 0
        self.min_training_samples = 30  # Reduced threshold

        # Detection state
        self.detection_active = False

    def start(self):
        """Start the detection agent"""
        logger.info("Starting AI Detection Agent...")

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

                # Perform detection if models are trained
                if self.detection_active:
                    self._perform_detection()

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
                logger.info("AI models training completed - DETECTION ACTIVE")
            else:
                logger.warning("Both model training failed")

        except Exception as e:
            logger.error(f"Training error: {e}")

    def _perform_detection(self):
        """Perform anomaly detection"""
        try:
            alerts_generated = []

            # Device-level anomaly detection
            if len(self.device_data_buffer) >= 10:
                recent_device_data = list(self.device_data_buffer)[-50:]
                device_anomaly, device_score, device_info = self.lstm_autoencoder.detect_anomaly(recent_device_data)

                if device_anomaly:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'device_anomaly',
                        'source': 'lstm_autoencoder',
                        'anomaly_score': device_score,
                        'severity': 'high' if device_score > 0.1 else 'medium',
                        'device_id': recent_device_data[-1].get('device_id', 'unknown'),
                        'latest_vitals': recent_device_data[-1],
                        'details': device_info
                    }
                    alerts_generated.append(alert)
                    logger.warning(f"🚨 DEVICE ANOMALY DETECTED: Score: {device_score:.4f}")

            # Network-level anomaly detection
            if len(self.network_alerts_buffer) >= 5:
                recent_alerts = list(self.network_alerts_buffer)[-20:]
                network_anomaly, network_score, network_info = self.network_analyzer.detect_anomaly(recent_alerts)

                if network_anomaly:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'network_anomaly',
                        'source': 'isolation_forest',
                        'anomaly_score': network_score,
                        'severity': 'high' if network_score < -0.5 else 'medium',
                        'recent_alerts_count': len(recent_alerts),
                        'details': network_info
                    }
                    alerts_generated.append(alert)
                    logger.warning(f"🚨 NETWORK ANOMALY DETECTED: Score: {network_score:.4f}")

            # Send all alerts
            for alert in alerts_generated:
                self._send_alert(alert)

        except Exception as e:
            logger.error(f"Detection error: {e}")

    def _send_alert(self, alert):
        """Send alert to response agent and dashboard"""
        try:
            # Send to Kafka for response agent
            self.kafka_producer.send('ai-alerts', alert)
            logger.info(f"🔔 AI Alert sent: {alert['type']} - {alert['severity']}")

        except Exception as e:
            logger.error(f"Alert sending error: {e}")


if __name__ == "__main__":
    agent = DetectionAgent()
    agent.start()
