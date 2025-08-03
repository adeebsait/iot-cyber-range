#!/usr/bin/env python3
import json
import threading
import time
import os
import paho.mqtt.client as mqtt

# Environment-configurable parameters
MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
SURICATA_LOG = os.getenv("SURICATA_LOG", "/var/log/suricata/eve.json")
MQTT_TOPIC = "suricata/alerts"

def tail_suricata(callback):
    """Continuously tail the Suricata JSON log and fire callback on each new line."""
    with open(SURICATA_LOG, "r") as f:
        # Go to end of file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                record = json.loads(line)
                callback(record)
            except json.JSONDecodeError:
                continue

def mqtt_listener():
    client = mqtt.Client()
    client.connect(MQTT_BROKER, MQTT_PORT)
    client.loop_start()

    def publish(record):
        # Only forward alerts
        if record.get("event_type") == "alert":
            client.publish(MQTT_TOPIC, json.dumps(record), qos=1)

    # Start tailing Suricata in a background thread
    t = threading.Thread(target=tail_suricata, args=(publish,), daemon=True)
    t.start()

    # Keep main thread alive to maintain MQTT loop
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    mqtt_listener()
