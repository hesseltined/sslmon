# SSLMon - SSL Certificate Monitoring System

**Version:** 3.9  
**Author:** Doug Hesseltine  
**Copyright:** Technologist.services 2025

## Overview

SSLMon is a self-contained SSL certificate monitoring solution designed to run within client environments as a Docker container. It provides automatic certificate expiration monitoring, email alerting, and a web-based dashboard for tracking SSL certificates across internal networks.

## Features

- ✅ Automatic SSL certificate monitoring with configurable check intervals
- ✅ Real-time certificate expiration tracking with visual progress bars
- ✅ CA issuer identification and self-signed certificate detection
- ✅ Web-based dashboard with Bootstrap 5 UI
- ✅ Manual "Check Now" button for immediate certificate checks
- ✅ Email notifications with configurable thresholds (planned)
- ✅ HTTPS-enabled web interface
- ✅ Docker containerized for easy deployment
- ✅ Persistent data storage via Docker volumes

## Quick Start

### Prerequisites
- Docker installed
- SSL certificate and key for HTTPS (or use self-signed)

### Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/sslmon.git
   cd sslmon
   ```

2. **Create data directory and certificates:**
   ```bash
   sudo mkdir -p /opt/sslmon-data
   sudo openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
     -keyout /opt/sslmon-data/server.key \
     -out /opt/sslmon-data/server.crt \
     -subj '/CN=sslmon.local'
   sudo chmod 600 /opt/sslmon-data/server.key
   ```

3. **Build and run:**
   ```bash
   docker build -t sslmon:3.9 .
   docker run -d \
     --name sslmon \
     -p 8443:8443 \
     -v /opt/sslmon-data:/data \
     --restart unless-stopped \
     sslmon:3.9
   ```

4. **Access the dashboard:**
   ```
   https://your-server:8443/
   ```

## Architecture

### Tech Stack
- **Backend:** Python 3.12 + Flask
- **Frontend:** Bootstrap 5 + Chart.js
- **Data:** JSON files (SQLite planned for history)
- **Runtime:** Docker container
- **Security:** HTTPS with custom or self-signed certificates

### Directory Structure
```
/opt/sslmon/
├── app.py                 # Main Flask application
├── cert_checker.py        # Certificate checking module
├── db.py                  # Database module (planned)
├── mailer.py             # Email notification module
├── Dockerfile
├── requirements.txt
├── templates/            # HTML templates
└── static/              # CSS and JavaScript

/opt/sslmon-data/        # Persistent data (Docker volume)
├── results.json         # Certificate status
├── config.json          # Configuration
├── sslmon.log          # Application logs
├── server.crt          # HTTPS certificate
└── server.key          # HTTPS private key
```

## Usage

### Adding Domains
1. Navigate to the dashboard
2. Enter domain name in the "Add" form
3. Certificate is checked immediately upon addition

### Manual Checks
- Click the **"Check Now"** button in the navigation bar to trigger immediate certificate checks for all monitored domains

### Monitoring
- Green: >60 days remaining
- Yellow: 30-60 days remaining
- Red: <30 days remaining
- Gray: Error or pending check

## Development

### Local Development
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Testing Certificate Checker
```bash
python cert_checker.py google.com technologist.services
```

## Configuration

Configuration will be managed through a web interface (planned). Currently:
- Default admin credentials: `admin/changeme`
- SMTP settings stored in `/opt/sslmon-data/config.json`

## Roadmap

### High Priority
- [ ] Web-based configuration UI for SMTP and admin password
- [ ] Authentication system (login/logout)
- [ ] Email notification integration with configurable thresholds

### Medium Priority
- [ ] Delete domain functionality
- [ ] Historical certificate tracking with SQLite
- [ ] Multi-user support

### Low Priority
- [ ] IP range scanning for automatic certificate discovery
- [ ] API endpoints for external integrations

## Version History

See [docs/SSLMon.html](docs/SSLMon.html) for detailed changelog.

**v3.9 (2025-10-31)**
- Added cert_checker module with comprehensive SSL/TLS checking
- Integrated certificate checking into Flask application
- Enhanced dashboard with issuer, self-signed detection, and error display
- Added "Check Now" button for manual checks
- Improved error handling and logging

## License

Copyright 2025 Technologist.services - All Rights Reserved

## Author

Doug Hesseltine  
[Technologist.services](https://technologist.services)
