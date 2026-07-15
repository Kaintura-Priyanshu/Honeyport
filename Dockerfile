FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

# Run as a non-root user; the decoy ports in config.yaml are all
# unprivileged (>1024) by default so this works out of the box.
RUN useradd -m honeypot
USER honeypot

WORKDIR /app/src
ENTRYPOINT ["python3", "honeypot.py", "--config", "../config/config.yaml"]
