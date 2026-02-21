FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY relay_server.py .
COPY analytics.py .

# Data directory for analytics (JSONL logs)
RUN mkdir -p /data

# Non-root user for security
RUN useradd -r -s /bin/false relay && chown relay:relay /data
USER relay

EXPOSE 8765 8766

CMD ["python", "relay_server.py"]
