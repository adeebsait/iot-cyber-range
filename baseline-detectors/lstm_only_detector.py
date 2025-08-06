import os
import json
import time
import logging
import threading
import numpy as np
import tensorflow as tf
from kafka import KafkaConsumer, KafkaProducer
from datetime import datetime
from collections import deque
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LSTMOnlyDetector:
    """Baseline detector using only LSTM autoencoder"""

    def __init__(self):
        self.kafka_bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

        # LSTM parameters
        self.sequence_length = 10
        self.n_features = 4
        self.model = self._build_model()
        self.scaler = StandardScaler()
        self.is_trained = False
        self.threshold = 0.05

        # Data buffers
        self.device_data = deque(maxlen=500)
        self.training_data = deque(maxlen=1000)

        # Setup Kafka
        self.consumer = KafkaConsumer(
            'device-telemetry',
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='lstm-only-detector',
            auto_offset_reset='earliest'
        )

        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        logger.info("LSTM-Only Detector initialized")

    def _build_model(self):
        """Build LSTM autoencoder"""
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(30, activation='relu', input_shape=(self.sequence_length, self.n_features),
                                 return_sequences=True),
            tf.keras.layers.LSTM(15, activation='relu', return_sequences=False),
            tf.keras.layers.RepeatVector(self.sequence_length),
            tf.keras.layers.LSTM(15, activation='relu', return_sequences=True),
            tf.keras.layers.LSTM(30, activation='relu', return_sequences=True),
            tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(self.n_features))
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def start(self):
        """Start the LSTM-only detector"""
        logger.info("Starting LSTM-Only Detector...")

        # Start data consumption
        consumer_thread = threading.Thread(target=self._consume_device_data)
        consumer_thread.daemon = True
        consumer_thread.start()

        # Detection loop
        self._detection_loop()

    def _consume_device_data(self):
        """Consume device telemetry data"""
        try:
            for message in self.consumer:
                data = message.value
                self.device_data.append(data)

                # Collect training data
                if len(self.training_data) < 1000:
                    self.training_data.append(data)

                logger.info(f"Device data received: {data.get('device_id', 'unknown')}")

        except Exception as e:
            logger.error(f"Device data consumption error: {e}")

    def _preprocess_data(self, data):
        """Preprocess device data for LSTM"""
        if len(data) < self.sequence_length:
            return None

        features = []
        for reading in data:
            features.append([
                reading.get('heart_rate', 75),
                reading.get('spo2', 98),
                reading.get('body_temp', 36.5),
                reading.get('timestamp', 0) % 86400
            ])

        sequences = []
        for i in range(len(features) - self.sequence_length + 1):
            sequences.append(features[i:i + self.sequence_length])

        return np.array(sequences)

    def _train_model(self):
        """Train the LSTM model"""
        logger.info(f"Training LSTM model with {len(self.training_data)} samples...")

        sequences = self._preprocess_data(list(self.training_data))
        if sequences is None or len(sequences) < 5:
            return False

        # Scale data
        n_samples, seq_len, n_feat = sequences.shape
        sequences_reshaped = sequences.reshape(-1, n_feat)
        sequences_scaled = self.scaler.fit_transform(sequences_reshaped)
        sequences_scaled = sequences_scaled.reshape(n_samples, seq_len, n_feat)

        # Train
        self.model.fit(sequences_scaled, sequences_scaled, epochs=50, batch_size=16, verbose=0)

        # Set threshold
        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))
        self.threshold = np.percentile(mse, 95)

        self.is_trained = True
        logger.info(f"LSTM training completed. Threshold: {self.threshold:.4f}")
        return True

    def _detect_anomaly(self, data):
        """Detect anomalies using LSTM"""
        if not self.is_trained:
            return False, 0.0

        sequences = self._preprocess_data(data)
        if sequences is None:
            return False, 0.0

        # Scale and predict
        n_samples, seq_len, n_feat = sequences.shape
        sequences_reshaped = sequences.reshape(-1, n_feat)
        sequences_scaled = self.scaler.transform(sequences_reshaped)
        sequences_scaled = sequences_scaled.reshape(n_samples, seq_len, n_feat)

        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))

        max_error = np.max(mse)
        is_anomaly = max_error > self.threshold

        return is_anomaly, float(max_error)

    def _detection_loop(self):
        """Main detection loop"""
        while True:
            try:
                # Train model if needed
                if not self.is_trained and len(self.training_data) >= 30:
                    self._train_model()

                # Perform detection
                if self.is_trained and len(self.device_data) >= 10:
                    recent_data = list(self.device_data)[-50:]
                    is_anomaly, anomaly_score = self._detect_anomaly(recent_data)

                    if is_anomaly:
                        self._generate_detection(anomaly_score, recent_data[-1])

                logger.info(f"LSTM-Only Status: Buffer: {len(self.device_data)}, "
                            f"Trained: {self.is_trained}, Training data: {len(self.training_data)}")

                time.sleep(15)

            except Exception as e:
                logger.error(f"Detection loop error: {e}")
                time.sleep(15)

    def _generate_detection(self, anomaly_score, latest_data):
        """Generate anomaly detection alert"""
        detection = {
            'timestamp': datetime.now().isoformat(),
            'detector_type': 'lstm_only',
            'method': 'deep_learning',
            'anomaly_score': anomaly_score,
            'threshold': self.threshold,
            'severity': 'high' if anomaly_score > self.threshold * 2 else 'medium',
            'device_id': latest_data.get('device_id', 'unknown'),
            'detection_latency': 3.0,  # LSTM is slower
            'confidence': min(0.95, anomaly_score / self.threshold),
            'details': f"LSTM anomaly detection: score {anomaly_score:.4f} > threshold {self.threshold:.4f}"
        }

        try:
            self.producer.send('baseline-alerts', detection)
            logger.warning(f"🧠 LSTM-ONLY DETECTION: Score: {anomaly_score:.4f}, Device: {detection['device_id']}")
        except Exception as e:
            logger.error(f"Detection sending error: {e}")


if __name__ == "__main__":
    detector = LSTMOnlyDetector()
    detector.start()
