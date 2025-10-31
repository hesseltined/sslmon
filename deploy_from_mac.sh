#!/bin/bash
# SSLMon Deployment Script - Run from Mac
# Author: Doug Hesseltine
# Copyright: Technologist.services 2025

set -e

SERVER="sslmon@10.250.0.158"
REMOTE_DIR="/opt/sslmon"

echo "========================================="
echo "SSLMon Deployment (from Mac)"
echo "========================================="
echo ""

echo "[1/3] Syncing files to server..."
rsync -avz --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  ./*.py \
  ./*.txt \
  ./Dockerfile \
  ${SERVER}:${REMOTE_DIR}/

rsync -avz --exclude='__pycache__' ./templates/ ${SERVER}:${REMOTE_DIR}/templates/
rsync -avz ./static/ ${SERVER}:${REMOTE_DIR}/static/

echo "   Files synced!"
echo ""

echo "[2/3] Rebuilding Docker container on server..."
ssh ${SERVER} "cd ${REMOTE_DIR} && docker stop sslmon || true && docker rm sslmon || true && docker build -t sslmon:3.9 . && docker run -d --name sslmon -p 8443:8443 -v /opt/sslmon-data:/data --restart unless-stopped sslmon:3.9"

echo "   Container rebuilt!"
echo ""

echo "[3/3] Checking status..."
sleep 3
ssh ${SERVER} "docker ps | grep sslmon"

echo ""
echo "========================================="
echo "Deployment completed!"
echo "========================================="
echo "Test at: https://sslmon.technologist.services/"
