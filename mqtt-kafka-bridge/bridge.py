import json
import time
import logging
from kafka import KafkaProducer
import paho.mqtt.client as mqtt
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MQTTKafkaBridge:
    def __init__(self):
        # MQTT settings
        self.mqtt_broker = os.getenv("MQTT_BROKER", "mqtt-broker")
        self.mqtt_port = int(os.getenv("MQTT_PORT", "1883"))

        # Kafka settings
        self.kafka_bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

        # Initialize Kafka producer
        self.kafka_producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        # Initialize MQTT client
        self.mqtt_client = mqtt.Client(client_id="mqtt_kafka_bridge")
        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_message = self.on_mqtt_message

    def on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("Connected to MQTT broker")
            # Subscribe to all device vitals
            client.subscribe("healthcare/+/vitals")
            logger.info("Subscribed to healthcare/+/vitals")
        else:
            logger.error(f"Failed to connect to MQTT broker: {rc}")

    def on_mqtt_message(self, client, userdata, msg):
        try:
            # Parse the MQTT message
            topic = msg.topic
            payload = json.loads(msg.payload.decode())

            logger.info(f"Received MQTT message on {topic}: {payload}")

            # Send to Kafka device-telemetry topic
            self.kafka_producer.send('device-telemetry', payload)
            logger.info(f"Sent to Kafka device-telemetry: {payload}")

        except Exception as e:
            logger.error(f"Error processing MQTT message: {e}")

    def start(self):
        logger.info("Starting MQTT-Kafka bridge...")

        # Connect to MQTT
        self.mqtt_client.connect(self.mqtt_broker, self.mqtt_port, 60)
        self.mqtt_client.loop_forever()


if __name__ == "__main__":
    bridge = MQTTKafkaBridge()
    bridge.start()
