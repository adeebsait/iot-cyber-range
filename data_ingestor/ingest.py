#!/usr/bin/env python3
import os
import time
import json
import threading
import paho.mqtt.client as mqtt

# Environment variables (set via docker-compose)
MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
SURICATA_LOG = os.getenv("SURICATA_LOG", "/var/log/suricata/eve.json")
TOPIC = os.getenv("MQTT_TOPIC", "suricata/events")

def tail_suricata(on_line):
    # wait for file to exist
    while not os.path.isfile(SURICATA_LOG):
        print(f"[ingest] waiting for {SURICATA_LOG} to appear...")
        time.sleep(1)

    # open and seek to end, then follow
    with open(SURICATA_LOG, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            on_line(line.rstrip())

def mqtt_publisher():
    client = mqtt.Client()
    # retry connect until broker is up
    while True:
        try:
            client.connect(MQTT_BROKER, MQTT_PORT)
            print(f"[ingest] connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}")
            break
        except Exception as e:
            print(f"[ingest] MQTT connection failed: {e!r}. retrying in 5s...")
            time.sleep(5)

    client.loop_start()

    def on_line(line):
        try:
            # parse JSON line from Suricata
            ev = json.loads(line)
        except Exception:
            return
        payload = json.dumps(ev)
        client.publish(TOPIC, payload)
        print(f"[ingest] published to {TOPIC}: {payload}")

    # start tailing in this thread
    tail_suricata(on_line)

if __name__ == "__main__":
    print("[ingest] starting data ingestor")
    mqtt_publisher()
