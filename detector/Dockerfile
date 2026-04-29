FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .
COPY config.yaml .

RUN mkdir -p /var/log/hng-detector

EXPOSE 8080

CMD ["python", "-u", "main.py"]
