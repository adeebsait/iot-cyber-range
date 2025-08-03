import json
import time
from threading import Thread

import paho.mqtt.client as mqtt

SURICATA_LOG = "/var/log/suricata/eve.json"
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "healthcare/device01/vitals"

def tail_suricata():
    with open(SURICATA_LOG, "r") as f:
        # seek to end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                event = json.loads(line)
                print("SURICATA:", event)
            except json.JSONDecodeError:
                continue

def on_mqtt_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        print("MQTT:", data)
    except json.JSONDecodeError:
        pass

def mqtt_listener():
    client = mqtt.Client()
    client.on_message = on_mqtt_message
    client.connect(MQTT_BROKER, MQTT_PORT)
    client.subscribe(MQTT_TOPIC)
    client.loop_forever()

if __name__ == "__main__":
    Thread(target=tail_suricata, daemon=True).start()
    mqtt_listener()
