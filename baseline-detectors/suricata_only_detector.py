import os
import json
import time
import logging
import threading
from kafka import KafkaConsumer, KafkaProducer
from datetime import datetime
from collections import deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SuricataOnlyDetector:
    """Baseline detector using only Suricata rules"""

    def __init__(self):
        self.kafka_bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

        # Setup Kafka
        self.consumer = KafkaConsumer(
            'security-alerts',
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='suricata-only-detector',
            auto_offset_reset='earliest'
        )

        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        # Detection parameters
        self.alert_threshold = 3  # Number of alerts to trigger detection
        self.time_window = 30  # Time window in seconds
        self.recent_alerts = deque(maxlen=100)

        logger.info("Suricata-Only Detector initialized")

    def start(self):
        """Start the baseline detector"""
        logger.info("Starting Suricata-Only Detector...")

        consumer_thread = threading.Thread(target=self._consume_alerts)
        consumer_thread.daemon = True
        consumer_thread.start()

        # Detection loop
        self._detection_loop()

    def _consume_alerts(self):
        """Consume Suricata alerts"""
        try:
            for message in self.consumer:
                alert = message.value
                timestamp = datetime.now()

                # Add timestamp to alert
                alert['received_at'] = timestamp.isoformat()
                self.recent_alerts.append(alert)

                logger.info(f"Suricata alert received: {alert.get('alert', {}).get('signature', 'Unknown')}")

        except Exception as e:
            logger.error(f"Alert consumption error: {e}")

    def _detection_loop(self):
        """Main detection logic"""
        while True:
            try:
                current_time = datetime.now()

                # Count recent alerts in time window
                recent_count = 0
                high_severity_count = 0

                for alert in self.recent_alerts:
                    alert_time = datetime.fromisoformat(alert['received_at'])
                    if (current_time - alert_time).total_seconds() <= self.time_window:
                        recent_count += 1
                        if alert.get('threat_level') == 'high':
                            high_severity_count += 1

                # Detection logic
                if recent_count >= self.alert_threshold or high_severity_count >= 1:
                    self._generate_detection(recent_count, high_severity_count)

                logger.info(f"Suricata-Only Status: {recent_count} alerts in {self.time_window}s window")
                time.sleep(10)

            except Exception as e:
                logger.error(f"Detection loop error: {e}")
                time.sleep(10)

    def _generate_detection(self, alert_count, high_severity_count):
        """Generate detection alert"""
        detection = {
            'timestamp': datetime.now().isoformat(),
            'detector_type': 'suricata_only',
            'method': 'rule_based',
            'alert_count': alert_count,
            'high_severity_count': high_severity_count,
            'severity': 'high' if high_severity_count > 0 else 'medium',
            'confidence': min(0.9, alert_count * 0.2),  # Simple confidence scoring
            'detection_latency': 1.0,  # Fast rule-based detection
            'details': f"Rule-based detection: {alert_count} alerts, {high_severity_count} high severity"
        }

        try:
            self.producer.send('baseline-alerts', detection)
            logger.warning(f"🔍 SURICATA-ONLY DETECTION: {alert_count} alerts, severity: {detection['severity']}")
        except Exception as e:
            logger.error(f"Detection sending error: {e}")


if __name__ == "__main__":
    detector = SuricataOnlyDetector()
    detector.start()
