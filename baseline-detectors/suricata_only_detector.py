import os
import json
import logging
from kafka import KafkaConsumer, KafkaProducer
from detection_agent import to_native  # import helper from detection_agent.py

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SuricataOnlyDetector:
    def __init__(self):
        self.kafka_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        self.consumer = KafkaConsumer(
            'security-alerts',
            bootstrap_servers=[self.kafka_servers],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='suricata-only-detector',
            auto_offset_reset='earliest'
        )
        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_servers],
            value_serializer=lambda v: json.dumps(to_native(v)).encode('utf-8')
        )

    def run(self):
        for msg in self.consumer:
            alert = msg.value
            # Transform Suricata eve.json alert to evaluation schema
            transformed = {
                'timestamp': alert.get('timestamp'),
                'detector_type': 'suricata_only',
                'method': 'suricata',
                'signature': alert.get('alert', {}).get('signature'),
                'severity': alert.get('alert', {}).get('severity'),
                'src_ip': alert.get('src_ip'),
                'dest_ip': alert.get('dest_ip'),
                'src_port': alert.get('src_port'),
                'dest_port': alert.get('dest_port'),
                'protocol': alert.get('proto'),
                'confidence': 1.0,
                'details': alert
            }
            try:
                self.producer.send('security-alerts', transformed)
                self.producer.flush()
                logger.info("🔔 Alert sent to security-alerts")
            except Exception as e:
                logger.error(f"Alert sending error: {e}")

if __name__ == "__main__":
    SuricataOnlyDetector().run()
