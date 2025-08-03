# data_ingestor/Dockerfile
FROM python:3.10-slim

# set working directory
WORKDIR /app

# copy your ingestor code
COPY ingest.py .

# install dependencies
RUN pip install --no-cache-dir paho-mqtt

# ensure the suricata log dir is present
VOLUME ["/var/log/suricata"]

# default env vars (overridden by compose)
ENV MQTT_BROKER=localhost \
    MQTT_PORT=1883 \
    SURICATA_LOG=/var/log/suricata/eve.json

# run the ingestor
CMD ["python", "ingest.py"]
