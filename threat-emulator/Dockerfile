FROM python:3.10-slim

WORKDIR /app
RUN pip install scapy paho-mqtt

COPY malformed_attack.py dos_attack.py ./

CMD ["bash", "-c", "python malformed_attack.py && python dos_attack.py"]
