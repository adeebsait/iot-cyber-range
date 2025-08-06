import os
import time
import json
import random
import paho.mqtt.client as mqtt

BROKER = os.getenv("MQTT_BROKER", "localhost")
PORT = int(os.getenv("MQTT_PORT", "1883"))
DEV_ID = os.getenv("DEVICE_ID", "device001")
TOPIC = f"healthcare/{DEV_ID}/vitals"

# explicitly name the client_id
client = mqtt.Client(client_id=DEV_ID)


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Device {DEV_ID} connected to MQTT broker")
    else:
        print(f"Failed to connect, return code {rc}")


def on_publish(client, userdata, mid):
    print(f"Message {mid} published successfully")


client.on_connect = on_connect
client.on_publish = on_publish


def generate_vitals():
    return {
        "device_id": DEV_ID,
        "timestamp": int(time.time()),
        "heart_rate": random.randint(60, 100),
        "spo2": round(random.uniform(95.0, 100.0), 1),
        "body_temp": round(random.uniform(36.1, 37.2), 1),
        "blood_pressure_sys": random.randint(110, 140),
        "blood_pressure_dia": random.randint(70, 90)
    }


if __name__ == "__main__":
    client.connect(BROKER, PORT, 60)
    client.loop_start()

    try:
        while True:
            vitals = generate_vitals()
            payload = json.dumps(vitals)
            result = client.publish(TOPIC, payload, qos=1)
            print(f"Published: {payload}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("Shutting down device simulator...")
        client.loop_stop()
        client.disconnect()
