FROM python:3.10-slim
WORKDIR /app
COPY simulator.py .
RUN pip install paho-mqtt
CMD ["python", "simulator.py"]
