FROM python:3.9-slim
WORKDIR /app
RUN pip install paho-mqtt
COPY simulator.py .
CMD ["python", "simulator.py"]
