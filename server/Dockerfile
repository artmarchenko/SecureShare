FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY relay_server.py .

# Non-root user for security
RUN useradd -r -s /bin/false relay
USER relay

EXPOSE 8765

CMD ["python", "relay_server.py"]
