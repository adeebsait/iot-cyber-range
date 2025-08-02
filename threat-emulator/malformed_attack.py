from scapy.all import *
import os

BROKER = os.getenv("MQTT_BROKER", "mqtt-broker")
PORT   = int(os.getenv("MQTT_PORT", 1883))

# Build a raw TCP packet with invalid MQTT header bytes
ip = IP(dst=BROKER)
tcp = TCP(dport=PORT, flags='PA', sport=RandShort())
raw = Raw(load=b'\x30\xFF\x00\x10malformed_payload')  # invalid remaining length

pkt = ip/tcp/raw
send(pkt, count=5, inter=1)
print("Sent 5 malformed MQTT packets")
