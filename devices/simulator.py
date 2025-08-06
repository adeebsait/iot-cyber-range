import os
import time
import json
import random
import paho.mqtt.client as mqtt

BROKER = os.getenv("MQTT_BROKER", "localhost")
PORT = int(os.getenv("MQTT_PORT", "1883"))
DEV_ID = os.getenv("DEVICE_ID", "device001")
TOPIC = f"healthcare/{DEV_ID}/vitals"

# Use API version 2
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEV_ID)


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"Device {DEV_ID} connected to MQTT broker")
    else:
        print(f"Failed to connect, return code {reason_code}")


def on_publish(client, userdata, mid, reason_code, properties):
    print(f"Message {mid} published successfully")


def on_disconnect(client, userdata, flags, reason_code, properties):
    print(f"Device {DEV_ID} disconnected with reason code {reason_code}")


client.on_connect = on_connect
client.on_publish = on_publish
client.on_disconnect = on_disconnect


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
