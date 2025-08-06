FROM python:3.9-slim

WORKDIR /app

# Install system dependencies including docker-compose
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    docker-compose \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "performance_evaluator.py"]
