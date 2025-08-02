import os
import time
import json
import random
import paho.mqtt.client as mqtt

BROKER = os.getenv("MQTT_BROKER", "localhost")
PORT   = int(os.getenv("MQTT_PORT", "1883"))
DEV_ID = os.getenv("DEVICE_ID", "device001")
TOPIC  = f"healthcare/{DEV_ID}/vitals"

# explicitly name the client_id
client = mqtt.Client(client_id=DEV_ID)
client.connect(BROKER, PORT)

def generate_vitals():
    return {
        "device_id": DEV_ID,
        "timestamp": int(time.time()),
        "heart_rate": random.randint(60, 100),
        "spo2": round(random.uniform(95.0, 100.0), 1)
    }

if __name__ == "__main__":
    while True:
        vitals = generate_vitals()
        payload = json.dumps(vitals)
        client.publish(TOPIC, payload, qos=1)
        print(f"Published: {payload}")
        time.sleep(5)
