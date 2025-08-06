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
import paho.mqtt.client as mqtt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LSTMAutoencoder:
    def __init__(self, sequence_length=10, n_features=6):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.model = self._build_model()
        self.scaler = StandardScaler()
        self.is_trained = False

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

        # Extract features
        features = []
        for reading in data:
            features.append([
                reading.get('heart_rate', 0),
                reading.get('spo2', 0),
                reading.get('body_temp', 0),
                reading.get('blood_pressure_sys', 0),
                reading.get('blood_pressure_dia', 0),
                reading.get('timestamp', 0) % 86400  # Time of day
            ])

        # Create sequences
        sequences = []
        for i in range(len(features) - self.sequence_length + 1):
            sequences.append(features[i:i + self.sequence_length])

        return np.array(sequences)

    def train(self, training_data, epochs=100):
        """Train the autoencoder on normal data"""
        sequences = self.preprocess_data(training_data)
        if sequences is None:
            return False

        # Reshape and scale
        n_samples, seq_len, n_feat = sequences.shape
        sequences_scaled = self.scaler.fit_transform(sequences.reshape(-1, n_feat)).reshape(n_samples, seq_len, n_feat)

        # Train model
        self.model.fit(sequences_scaled, sequences_scaled,
                       epochs=epochs, batch_size=32, verbose=1,
                       validation_split=0.1)

        self.is_trained = True
        return True

    def detect_anomaly(self, data, threshold=0.1):
        """Detect anomalies in new data"""
        if not self.is_trained:
            return False, 0.0

        sequences = self.preprocess_data(data)
        if sequences is None:
            return False, 0.0

        # Scale and predict
        n_samples, seq_len, n_feat = sequences.shape
        sequences_scaled = self.scaler.transform(sequences.reshape(-1, n_feat)).reshape(n_samples, seq_len, n_feat)

        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))

        max_error = np.max(mse)
        is_anomaly = max_error > threshold

        return is_anomaly, float(max_error)


class NetworkTrafficAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    def extract_network_features(self, alerts_data):
        """Extract network-level features from Suricata alerts"""
        features = []
        for alert in alerts_data:
            feature_vector = [
                len(str(alert.get('payload', ''))),  # Payload size
                alert.get('flow', {}).get('pkts_toserver', 0),
                alert.get('flow', {}).get('pkts_toclient', 0),
                alert.get('flow', {}).get('bytes_toserver', 0),
                alert.get('flow', {}).get('bytes_toclient', 0),
                alert.get('alert', {}).get('signature_id', 0),
                hash(alert.get('src_ip', '')) % 1000,  # IP hash
                hash(alert.get('dest_port', '')) % 1000  # Port hash
            ]
            features.append(feature_vector)

        return np.array(features) if features else None

    def train(self, training_alerts):
        """Train isolation forest on normal network patterns"""
        features = self.extract_network_features(training_alerts)
        if features is None or len(features) < 10:
            return False

        features_scaled = self.scaler.fit_transform(features)
        self.isolation_forest.fit(features_scaled)
        self.is_trained = True
        return True

    def detect_anomaly(self, alerts_data):
        """Detect network anomalies"""
        if not self.is_trained:
            return False, 0.0

        features = self.extract_network_features(alerts_data)
        if features is None:
            return False, 0.0

        features_scaled = self.scaler.transform(features)
        anomaly_scores = self.isolation_forest.decision_function(features_scaled)
        predictions = self.isolation_forest.predict(features_scaled)

        is_anomaly = -1 in predictions
        anomaly_score = float(np.mean(anomaly_scores))

        return is_anomaly, anomaly_score


class DetectionAgent:
    def __init__(self):
        # Initialize AI models
        self.lstm_autoencoder = LSTMAutoencoder()
        self.network_analyzer = NetworkTrafficAnalyzer()

        # Data buffers
        self.device_data_buffer = deque(maxlen=1000)
        self.network_alerts_buffer = deque(maxlen=1000)
        self.training_data = deque(maxlen=5000)

        # Kafka setup
        self.kafka_consumer = KafkaConsumer(
            'device-telemetry', 'security-alerts',
            bootstrap_servers=['localhost:9092'],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='detection-agent'
        )

        self.kafka_producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        # MQTT setup for device data
        self.mqtt_client = mqtt.Client(client_id="detection_agent")
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_message = self._on_mqtt_message

        # Training parameters
        self.training_period = 3600  # Train every hour
        self.last_training_time = 0
        self.min_training_samples = 100

        # Detection state
        self.detection_active = False

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("Connected to MQTT broker")
            client.subscribe("healthcare/+/vitals")
        else:
            logger.error(f"Failed to connect to MQTT: {rc}")

    def _on_mqtt_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
            data['topic'] = msg.topic
            self.device_data_buffer.append(data)

            # Send to Kafka for other agents
            self.kafka_producer.send('device-telemetry', data)

        except Exception as e:
            logger.error(f"Error processing MQTT message: {e}")

    def start(self):
        """Start the detection agent"""
        logger.info("Starting Detection Agent...")

        # Connect to MQTT
        self.mqtt_client.connect("localhost", 1883, 60)
        self.mqtt_client.loop_start()

        # Start Kafka consumer thread
        kafka_thread = threading.Thread(target=self._kafka_consumer_loop)
        kafka_thread.daemon = True
        kafka_thread.start()

        # Start detection loop
        self._detection_loop()

    def _kafka_consumer_loop(self):
        """Consume messages from Kafka"""
        try:
            for message in self.kafka_consumer:
                if message.topic == 'security-alerts':
                    self.network_alerts_buffer.append(message.value)
                elif message.topic == 'device-telemetry':
                    # Already handled via MQTT, but could add redundancy here
                    pass
        except Exception as e:
            logger.error(f"Kafka consumer error: {e}")

    def _detection_loop(self):
        """Main detection loop"""
        while True:
            try:
                current_time = time.time()

                # Check if we need to train models
                if (current_time - self.last_training_time > self.training_period and
                        len(self.training_data) >= self.min_training_samples):
                    self._train_models()
                    self.last_training_time = current_time

                # Perform detection if models are trained
                if self.detection_active:
                    self._perform_detection()

                # Collect training data (assuming normal operation initially)
                if len(self.device_data_buffer) > 0:
                    recent_data = list(self.device_data_buffer)[-50:]  # Last 50 readings
                    self.training_data.extend(recent_data)

                time.sleep(10)  # Detection every 10 seconds

            except Exception as e:
                logger.error(f"Detection loop error: {e}")
                time.sleep(5)

    def _train_models(self):
        """Train both AI models"""
        logger.info("Training AI models...")

        try:
            # Train LSTM autoencoder
            training_list = list(self.training_data)
            if self.lstm_autoencoder.train(training_list):
                logger.info("LSTM autoencoder trained successfully")
            else:
                logger.warning("LSTM autoencoder training failed")

            # Train network analyzer
            alerts_list = list(self.network_alerts_buffer)
            if self.network_analyzer.train(alerts_list):
                logger.info("Network analyzer trained successfully")
            else:
                logger.warning("Network analyzer training failed")

            self.detection_active = True
            logger.info("AI models training completed")

        except Exception as e:
            logger.error(f"Training error: {e}")

    def _perform_detection(self):
        """Perform anomaly detection"""
        try:
            # Device-level anomaly detection
            if len(self.device_data_buffer) >= 10:
                recent_device_data = list(self.device_data_buffer)[-50:]
                device_anomaly, device_score = self.lstm_autoencoder.detect_anomaly(recent_device_data)

                if device_anomaly:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'device_anomaly',
                        'source': 'lstm_autoencoder',
                        'anomaly_score': device_score,
                        'device_data': recent_device_data[-1],  # Latest reading
                        'severity': 'high' if device_score > 0.5 else 'medium'
                    }
                    self._send_alert(alert)

            # Network-level anomaly detection
            if len(self.network_alerts_buffer) > 0:
                recent_alerts = list(self.network_alerts_buffer)[-20:]
                network_anomaly, network_score = self.network_analyzer.detect_anomaly(recent_alerts)

                if network_anomaly:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'network_anomaly',
                        'source': 'isolation_forest',
                        'anomaly_score': network_score,
                        'recent_alerts': len(recent_alerts),
                        'severity': 'high' if network_score < -0.5 else 'medium'
                    }
                    self._send_alert(alert)

        except Exception as e:
            logger.error(f"Detection error: {e}")

    def _send_alert(self, alert):
        """Send alert to response agent and dashboard"""
        try:
            logger.warning(f"ANOMALY DETECTED: {alert['type']} - Score: {alert['anomaly_score']}")

            # Send to Kafka for response agent
            self.kafka_producer.send('ai-alerts', alert)

            # Could also send to external systems, databases, etc.

        except Exception as e:
            logger.error(f"Alert sending error: {e}")


if __name__ == "__main__":
    agent = DetectionAgent()
    agent.start()
