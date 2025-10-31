FROM python:3.12-slim
WORKDIR /app

# Install build dependencies for netifaces
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY . .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8443
CMD ["python3", "app.py"]
