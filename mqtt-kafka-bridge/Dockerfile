FROM python:3.9-slim

WORKDIR /app

RUN pip install paho-mqtt kafka-python

COPY bridge.py .

CMD ["python", "bridge.py"]
