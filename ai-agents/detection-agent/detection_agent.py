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

def to_native(obj):
    """
    Recursively convert numpy types and other non-serializable
    types into native Python types.
    """
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, dict):
        return {to_native(k): to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_native(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(to_native(x) for x in obj)
    return obj

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
            tf.keras.layers.LSTM(50, activation='relu', input_shape=(self.sequence_length, self.n_features), return_sequences=True),
            tf.keras.layers.LSTM(25, activation='relu', return_sequences=False),
            tf.keras.layers.RepeatVector(self.sequence_length),
            tf.keras.layers.LSTM(25, activation='relu', return_sequences=True),
            tf.keras.layers.LSTM(50, activation='relu', return_sequences=True),
            tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(self.n_features))
        ])
        model.compile(optimizer='adam', loss='mse')
        return model

    def preprocess_data(self, data):
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

    def train(self, training_data, epochs=50):
        logger.info(f"Training LSTM autoencoder with {len(training_data)} samples...")
        sequences = self.preprocess_data(training_data)
        if sequences is None or len(sequences) < 5:
            logger.warning("Insufficient data for training")
            return False
        n_samples, seq_len, n_feat = sequences.shape
        sequences_reshaped = sequences.reshape(-1, n_feat)
        sequences_scaled = self.scaler.fit_transform(sequences_reshaped)
        sequences_scaled = sequences_scaled.reshape(n_samples, seq_len, n_feat)
        self.model.fit(sequences_scaled, sequences_scaled, epochs=epochs, batch_size=16, verbose=0, validation_split=0.2)
        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))
        self.threshold = np.percentile(mse, 95)
        self.is_trained = True
        logger.info(f"LSTM training completed. Threshold: {self.threshold:.4f}")
        return True

    def detect_anomaly(self, data):
        if not self.is_trained:
            return False, 0.0, "Model not trained"
        sequences = self.preprocess_data(data)
        if sequences is None:
            return False, 0.0, "Insufficient data"
        n_samples, seq_len, n_feat = sequences.shape
        sequences_reshaped = sequences.reshape(-1, n_feat)
        sequences_scaled = self.scaler.transform(sequences_reshaped)
        sequences_scaled = sequences_scaled.reshape(n_samples, seq_len, n_feat)
        reconstructed = self.model.predict(sequences_scaled, verbose=0)
        mse = np.mean(np.power(sequences_scaled - reconstructed, 2), axis=(1, 2))
        max_error = float(np.max(mse))
        is_anomaly = max_error > self.threshold
        return bool(is_anomaly), max_error, f"Threshold: {self.threshold:.4f}"

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    def extract_network_features(self, alerts_data):
        if not alerts_data:
            return None
        features = []
        for alert in alerts_data:
            flow = alert.get('flow', {})
            alert_info = alert.get('alert', {})
            features.append([
                flow.get('pkts_toserver', 0),
                flow.get('pkts_toclient', 0),
                flow.get('bytes_toserver', 0),
                flow.get('bytes_toclient', 0),
                alert_info.get('signature_id', 0),
                alert.get('src_port', 0),
                alert.get('dest_port', 0),
                hash(alert.get('src_ip', '127.0.0.1')) % 1000
            ])
        return np.array(features) if features else None

    def train(self, training_alerts):
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
        if not self.is_trained:
            return False, 0.0, "Model not trained"
        features = self.extract_network_features(alerts_data)
        if features is None or len(features) == 0:
            return False, 0.0, "No network data"
        features_scaled = self.scaler.transform(features)
        scores = self.isolation_forest.decision_function(features_scaled)
        preds = self.isolation_forest.predict(features_scaled)
        is_anomaly = -1 in preds
        anomaly_score = float(np.mean(scores))
        return bool(is_anomaly), anomaly_score, f"Samples: {len(features)}"

class DetectionAgent:
    def __init__(self):
        self.lstm = LSTMAutoencoder()
        self.net = NetworkTrafficAnalyzer()
        self.device_buffer = deque(maxlen=500)
        self.network_buffer = deque(maxlen=200)
        self.training_data = deque(maxlen=2000)
        self.kafka_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS","kafka:9092")
        self.consumer = KafkaConsumer(
            'device-telemetry','security-alerts',
            bootstrap_servers=[self.kafka_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='detection-agent',
            auto_offset_reset='earliest',
            enable_auto_commit=True
        )
        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_servers],
            value_serializer=lambda v: json.dumps(to_native(v)).encode('utf-8')
        )
        self.training_period = 120
        self.min_samples = 30
        self.last_train = 0
        self.active = False
        self.fusion_threshold = 0.6
        self.high_conf_threshold = 0.8

    def start(self):
        threading.Thread(target=self._consume_loop,daemon=True).start()
        self._detection_loop()

    def _consume_loop(self):
        for msg in self.consumer:
            if msg.topic=='device-telemetry':
                self.device_buffer.append(msg.value)
                if len(self.training_data)<2000: self.training_data.append(msg.value)
            else:
                self.network_buffer.append(msg.value)

    def _detection_loop(self):
        while True:
            now=time.time()
            if not self.active and now-self.last_train>self.training_period and len(self.training_data)>=self.min_samples:
                self._train_models()
                self.last_train=now
            if self.active:
                self._perform_detection()
            time.sleep(15)

    def _train_models(self):
        device_trained=self.lstm.train(list(self.training_data))
        net_trained=self.net.train(list(self.network_buffer))
        self.active = device_trained or net_trained

    def _perform_detection(self):
        # Device
        d_anom,d_score,_=self.lstm.detect_anomaly(list(self.device_buffer)[-50:])
        # Network
        n_anom,n_score,_=self.net.detect_anomaly(list(self.network_buffer)[-20:])
        fused = self._fuse(d_anom,d_score,n_anom,n_score)
        if fused['is_threat']:
            self._send_alert(fused)

    def _fuse(self, da, ds, na, ns):
        dw=0.7 if da else 0.4
        nw=0.8 if na else 0.3
        total=dw+nw; dw/=total; nw/=total
        dsn=min(1,ds/0.2); nsn=min(1,abs(ns+0.5)/1)
        score=dw*dsn+nw*nsn
        if da and na:
            return {'is_threat':True,'fused_score':score,'confidence':0.95,'reason':'Both detect','device':da,'network':na}
        if score>self.fusion_threshold:
            return {'is_threat':True,'fused_score':score,'confidence':score,'reason':'High fusion score','device':da,'network':na}
        return {'is_threat':False,'fused_score':score,'confidence':score,'reason':'No threat','device':da,'network':na}

    def _send_alert(self, fused):
        alert={
            'timestamp':datetime.now().isoformat(),
            'type':'hybrid',
            'fused_score':fused['fused_score'],
            'confidence':fused['confidence'],
            'reason':fused['reason'],
            'device_detected':fused['device'],
            'network_detected':fused['network']
        }
        try:
            self.producer.send('ai-alerts', alert)
            self.producer.flush()
            logger.info("🔔 Alert sent to ai-alerts")
        except Exception as e:
            logger.error(f"Alert sending error: {e}")

if __name__=="__main__":
    DetectionAgent().start()
