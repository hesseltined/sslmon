#!/bin/bash
# SSLMon v3.9 Deployment Script
# Author: Doug Hesseltine
# Copyright: Technologist.services 2025

set -e  # Exit on error

echo "========================================="
echo "SSLMon v3.9 Deployment Script"
echo "========================================="
echo ""

# Move uploaded files to production locations
echo "[1/6] Moving uploaded files to /opt/sslmon/..."
sudo cp /tmp/cert_checker.py /opt/sslmon/cert_checker.py
sudo cp /tmp/app.py /opt/sslmon/app.py
sudo cp /tmp/dashboard.html /opt/sslmon/templates/dashboard.html
sudo cp /tmp/domains.html /opt/sslmon/templates/domains.html
sudo chown root:root /opt/sslmon/cert_checker.py /opt/sslmon/app.py
sudo chown root:root /opt/sslmon/templates/dashboard.html /opt/sslmon/templates/domains.html
echo "   Files moved successfully."
echo ""

# Verify files are in place
echo "[2/6] Verifying file deployment..."
if [ ! -f /opt/sslmon/cert_checker.py ]; then
    echo "   ERROR: cert_checker.py not found!"
    exit 1
fi
if [ ! -f /opt/sslmon/app.py ]; then
    echo "   ERROR: app.py not found!"
    exit 1
fi
echo "   All files verified."
echo ""

# Check if Docker container is running
echo "[3/6] Checking current container status..."
if sudo docker ps | grep -q sslmon; then
    echo "   Container is running. Stopping..."
    sudo docker stop sslmon
    sudo docker rm sslmon
    echo "   Container stopped and removed."
else
    echo "   No running container found."
fi
echo ""

# Rebuild Docker image
echo "[4/6] Building Docker image sslmon:3.9..."
sudo docker build -t sslmon:3.9 /opt/sslmon/
echo "   Image built successfully."
echo ""

# Start new container
echo "[5/6] Starting new container..."
sudo docker run -d \
  --name sslmon \
  -p 8443:8443 \
  -v /opt/sslmon-data:/data \
  --restart unless-stopped \
  sslmon:3.9

echo "   Container started."
echo ""

# Wait for container to be ready
echo "[6/6] Waiting for application to start..."
sleep 5

# Check container status
if sudo docker ps | grep -q sslmon; then
    echo "   Container is running!"
    echo ""
    echo "========================================="
    echo "Deployment completed successfully!"
    echo "========================================="
    echo ""
    echo "Next steps:"
    echo "1. Check logs: sudo docker logs -f sslmon"
    echo "2. Test web UI: https://sslmon.technologist.services/"
    echo "3. Verify certificate checks are working"
    echo ""
else
    echo "   ERROR: Container failed to start!"
    echo "   Check logs with: sudo docker logs sslmon"
    exit 1
fi
