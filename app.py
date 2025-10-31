#!/usr/bin/env python3
import os
import json
import logging
import threading
import time
import shutil
import subprocess
import ssl
import hashlib
import secrets
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for, session, flash

# Import certificate checker module
import cert_checker
import mailer
import network_scanner

# --------------------------------------------------------------------
# Flask setup
# --------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

LOG_PATH = "/data/sslmon.log"
RESULTS_PATH = "/data/results.json"
AUTH_PATH = "/data/auth.json"
MAIL_CONFIG_PATH = "/data/mail_config.json"
MAIL_KEY_PATH = "/data/fernet.key"

os.makedirs("/data", exist_ok=True)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Initialize mailer
mail = mailer.Mailer(MAIL_KEY_PATH, MAIL_CONFIG_PATH)

# Global storage for scan state (needed for SSE which can't use session)
scan_state = {}

# --------------------------------------------------------------------
# Authentication functions
# --------------------------------------------------------------------
def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_auth_config():
    """Load authentication configuration."""
    if os.path.exists(AUTH_PATH):
        with open(AUTH_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_auth_config(config):
    """Save authentication configuration."""
    with open(AUTH_PATH, 'w') as f:
        json.dump(config, f, indent=2)

def is_setup_complete():
    """Check if initial setup (admin password) is complete."""
    config = load_auth_config()
    return 'admin_password_hash' in config

def verify_password(password):
    """Verify admin password."""
    config = load_auth_config()
    if 'admin_password_hash' not in config:
        return False
    return hash_password(password) == config['admin_password_hash']

def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --------------------------------------------------------------------
# Utility functions
# --------------------------------------------------------------------
def get_ca_renewal_link(issuer):
    """Get renewal link for known Certificate Authorities."""
    if not issuer:
        return None
    
    issuer_lower = issuer.lower()
    
    # Let's Encrypt specific codes (known intermediates)
    # WE1 = Let's Encrypt E5, R3, R4, R10, R11, E1, E2, E3, E4, E5, E6, E7, E8, E9
    letsencrypt_codes = ['we1', 'r3', 'r4', 'r10', 'r11', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e9']
    if issuer_lower in letsencrypt_codes or 'let' in issuer_lower or 'letsencrypt' in issuer_lower:
        return 'https://letsencrypt.org/'
    
    # Map common CAs to their renewal/management URLs
    ca_links = {
        'digicert': 'https://www.digicert.com/account/login',
        'godaddy': 'https://account.godaddy.com/products/',
        'geotrust': 'https://products.geotrust.com/',
        'thawte': 'https://www.thawte.com/ssl/',
        'comodo': 'https://secure.comodo.com/',
        'sectigo': 'https://secure.sectigo.com/',
        'globalsign': 'https://www.globalsign.com/en/',
        'entrust': 'https://www.entrust.com/',
        'rapidssl': 'https://www.rapidssl.com/',
        'ssl.com': 'https://www.ssl.com/my-account/',
        'namecheap': 'https://ap.www.namecheap.com/ProductList/SSL',
        'zerossl': 'https://app.zerossl.com/',
        'cloudflare': 'https://dash.cloudflare.com/',
        'amazon': 'https://console.aws.amazon.com/acm/',
        'google': 'https://console.cloud.google.com/security/ccm/'
    }
    
    for ca_name, url in ca_links.items():
        if ca_name in issuer_lower:
            return url
    
    return None


def perform_checks():
    """
    Perform SSL certificate checks on all monitored domains.
    Updates results.json with certificate details, expiry info, and error states.
    """
    logging.info("Starting SSL certificate checks...")
    data = []
    
    try:
        if os.path.exists(RESULTS_PATH):
            with open(RESULTS_PATH, "r") as f:
                data = json.load(f)
    except Exception as e:
        logging.exception("Error reading %s: %s", RESULTS_PATH, e)
        return

    if not data:
        logging.info("No domains to check.")
        return

    # Check each domain's certificate
    checked_count = 0
    error_count = 0
    
    for record in data:
        domain = record.get("domain")
        if not domain:
            continue
            
        logging.info(f"Checking certificate for {domain}...")
        
        try:
            # Call cert_checker module
            result = cert_checker.check_certificate(domain)
            
            # Update record with certificate details
            if result.get("ok"):
                record["expires"] = result.get("expires")
                record["issued"] = result.get("issued")
                record["days_remaining"] = result.get("days_remaining")
                record["issuer"] = result.get("issuer")
                record["subject"] = result.get("subject")
                record["is_self_signed"] = result.get("is_self_signed")
                record["tls_version"] = result.get("tls_version")
                record["error"] = None
                record["error_type"] = None
                checked_count += 1
                logging.info(f"  {domain}: OK - expires {result.get('expires')}, {result.get('days_remaining')} days remaining")
            else:
                # Certificate check failed - store error info
                record["error"] = result.get("error")
                record["error_type"] = result.get("error_type")
                record["expires"] = None
                record["days_remaining"] = -1
                error_count += 1
                logging.warning(f"  {domain}: ERROR - {result.get('error_type')}: {result.get('error')}")
                
            # Update last checked timestamp
            record["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            
        except Exception as e:
            logging.exception(f"Unexpected error checking {domain}: {e}")
            record["error"] = f"Internal error: {str(e)}"
            record["error_type"] = "internal"
            record["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            error_count += 1

    # Save updated results
    try:
        with open(RESULTS_PATH, "w") as f:
            json.dump(data, f, indent=2)
        logging.info(f"Certificate checks complete: {checked_count} successful, {error_count} errors")
    except Exception as e:
        logging.exception("Error writing %s: %s", RESULTS_PATH, e)
    
    # Send email notifications if configured
    try:
        send_notifications(data)
    except Exception as e:
        logging.exception(f"Error sending notifications: {e}")


def send_notifications(data):
    """Send email notifications based on thresholds and settings."""
    cfg = mail.cfg
    if not cfg or not cfg.get('smtp_host'):
        return  # Email not configured
    
    warning_threshold = cfg.get('alert_threshold_warning', 30)
    critical_threshold = cfg.get('alert_threshold_critical', 14)
    
    for record in data:
        domain = record.get('domain')
        days = record.get('days_remaining')
        expires = record.get('expires')
        issuer = record.get('issuer')
        error = record.get('error')
        
        # Skip if there's an error or no valid data
        if error or days is None or days < 0:
            continue
        
        # Check if alert should be sent
        is_critical = days <= critical_threshold
        is_warning = days <= warning_threshold
        
        if is_critical or is_warning:
            # Check if we should send based on frequency settings
            if should_send_alert(record, is_critical):
                try:
                    renewal_link = get_ca_renewal_link(issuer)
                    result = mail.send_alert(domain, days, expires, issuer, is_critical, renewal_link)
                    if result:
                        record['last_alert_sent'] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        record['last_alert_level'] = 'critical' if is_critical else 'warning'
                        logging.info(f"Sent {'critical' if is_critical else 'warning'} alert for {domain}")
                    else:
                        logging.warning(f"Failed to send alert for {domain}")
                except Exception as e:
                    logging.exception(f"Error sending alert for {domain}: {e}")


def should_send_alert(record, is_critical):
    """Determine if an alert should be sent based on frequency settings."""
    cfg = mail.cfg
    frequency = cfg.get('alert_frequency', 'once')
    
    last_sent = record.get('last_alert_sent')
    last_level = record.get('last_alert_level')
    
    # Always send if never sent before
    if not last_sent:
        return True
    
    # Always send critical if previous was warning
    if is_critical and last_level == 'warning':
        return True
    
    # Check frequency settings
    if frequency == 'once':
        return False  # Already sent
    
    try:
        last_sent_dt = datetime.strptime(last_sent, "%Y-%m-%d %H:%M:%S")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        hours_since = (now - last_sent_dt).total_seconds() / 3600
        
        if frequency == 'daily' and hours_since >= 24:
            return True
        elif frequency == 'every_check' and hours_since >= 24:
            return True
        elif frequency == 'weekly' and hours_since >= 168:
            return True
    except Exception as e:
        logging.exception(f"Error checking alert frequency: {e}")
        return True  # Send if we can't determine
    
    return False


def check_monthly_report():
    """Check if monthly report should be sent (on 1st of month)."""
    cfg = mail.cfg
    if not cfg or not cfg.get('monthly_report'):
        return
    
    # Check if it's the 1st of the month
    now = datetime.now(timezone.utc)
    if now.day != 1:
        return
    
    # Check if we already sent this month
    last_report_file = "/data/last_monthly_report.txt"
    current_month = now.strftime("%Y-%m")
    
    try:
        if os.path.exists(last_report_file):
            with open(last_report_file, 'r') as f:
                last_report_month = f.read().strip()
                if last_report_month == current_month:
                    return  # Already sent this month
    except Exception as e:
        logging.exception(f"Error checking last report date: {e}")
    
    # Send monthly report
    try:
        if os.path.exists(RESULTS_PATH):
            with open(RESULTS_PATH, 'r') as f:
                data = json.load(f)
            
            result = mail.send_monthly_report(data)
            if result:
                # Record that we sent the report
                with open(last_report_file, 'w') as f:
                    f.write(current_month)
                logging.info("Monthly report sent successfully")
            else:
                logging.warning("Failed to send monthly report")
    except Exception as e:
        logging.exception(f"Error sending monthly report: {e}")


def scheduler_loop():
    """Simple background loop to re‑run perform_checks every 24 hours."""
    while True:
        time.sleep(24 * 3600)
        logging.info("Scheduled daily SSL check triggered.")
        perform_checks()
        check_monthly_report()


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# Authentication routes
# --------------------------------------------------------------------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Initial setup page for setting admin password."""
    if is_setup_complete():
        return redirect(url_for('login'))
    
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        
        if not password:
            return render_template("setup.html", error="Password is required")
        
        if len(password) < 8:
            return render_template("setup.html", error="Password must be at least 8 characters")
        
        if password != confirm:
            return render_template("setup.html", error="Passwords do not match")
        
        config = {'admin_password_hash': hash_password(password)}
        save_auth_config(config)
        logging.info("Initial admin password configured")
        return redirect(url_for('login'))
    
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if not is_setup_complete():
        return redirect(url_for('setup'))
    
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        
        if verify_password(password):
            session['logged_in'] = True
            logging.info("Admin logged in")
            return redirect(url_for('dashboard'))
        else:
            return render_template("login.html", error="Invalid password")
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout and clear session."""
    session.clear()
    logging.info("Admin logged out")
    return redirect(url_for('login'))


@app.route("/admin/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change admin password."""
    if request.method == "POST":
        current = request.form.get("current_password", "").strip()
        new = request.form.get("new_password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()
        
        # Verify current password
        if not verify_password(current):
            return render_template("change_password.html", error="Current password is incorrect")
        
        # Validate new password
        if len(new) < 8:
            return render_template("change_password.html", error="New password must be at least 8 characters")
        
        if new != confirm:
            return render_template("change_password.html", error="New passwords do not match")
        
        # Update password
        config = load_auth_config()
        config['admin_password_hash'] = hash_password(new)
        save_auth_config(config)
        logging.info("Admin password changed")
        
        return render_template("change_password.html", success="Password updated successfully")
    
    return render_template("change_password.html")


@app.route("/admin/factory-reset", methods=["GET", "POST"])
@login_required
def factory_reset():
    """Factory reset - clear all data and reset to defaults."""
    if request.method == "POST":
        confirm_text = request.form.get("confirm_text", "").strip()
        password = request.form.get("password", "").strip()
        
        # Verify password
        if not verify_password(password):
            return render_template("factory_reset.html", error="Incorrect password")
        
        # Verify confirmation text
        if confirm_text != "RESET":
            return render_template("factory_reset.html", error="You must type RESET to confirm")
        
        try:
            # Delete all data files
            files_to_delete = [
                RESULTS_PATH,
                MAIL_CONFIG_PATH,
                MAIL_KEY_PATH,
                "/data/last_monthly_report.txt",
                LOG_PATH
            ]
            
            for file_path in files_to_delete:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logging.info(f"Deleted {file_path}")
            
            # Reset auth to default (admin/changeme)
            default_config = {'admin_password_hash': hash_password('changeme')}
            save_auth_config(default_config)
            
            logging.info("FACTORY RESET COMPLETED")
            
            # Log out the user
            session.clear()
            
            return redirect(url_for('login'))
            
        except Exception as e:
            logging.exception(f"Error during factory reset: {e}")
            return render_template("factory_reset.html", error=f"Error during reset: {str(e)}")
    
    return render_template("factory_reset.html")


@app.route("/")
@login_required
def dashboard():
    data = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH, "r") as f:
            data = json.load(f)
    
    # Normalize data to use consistent field names
    for row in data:
        # Ensure new field names exist, falling back to old ones
        if "days_remaining" not in row and "days_left" in row:
            row["days_remaining"] = row["days_left"]
        if "expires" not in row and "expiry" in row:
            row["expires"] = row["expiry"]
        if "checked_at" not in row and "last_checked" in row:
            row["checked_at"] = row["last_checked"]
        
        # Ensure all required fields exist with defaults
        row.setdefault("domain", "Unknown")
        row.setdefault("issuer", None)
        row.setdefault("subject", None)
        row.setdefault("is_self_signed", False)
        row.setdefault("expires", None)
        row.setdefault("days_remaining", -1)
        row.setdefault("error", None)
        row.setdefault("error_type", None)
        row.setdefault("checked_at", "Never")
    
    return render_template("dashboard.html", data=data, get_ca_renewal_link=get_ca_renewal_link)


@app.route("/api/results")
@login_required
def api_results():
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            data = json.load(f)
        return jsonify(data)
    return jsonify([])


@app.route("/health")
@login_required
def health():
    data = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            data = json.load(f)
    return jsonify({
        "status": "ok",
        "last_check": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "monitored": len(data)
    })


@app.route("/admin/logs")
@login_required
def admin_logs():
    if not os.path.exists(LOG_PATH):
        return "No log file yet."
    with open(LOG_PATH) as f:
        lines = f.read()[-4000:]
    return f"<pre>{lines}</pre>"


# --------------------------------------------------------------------
# Overview page with charts
# --------------------------------------------------------------------
@app.route("/overview", endpoint="overview_page")
@login_required
def overview():
    domains = []
    try:
        if os.path.exists(RESULTS_PATH):
            with open(RESULTS_PATH, "r") as f:
                data = json.load(f)
            for row in data:
                domains.append({
                    "domain": row.get("domain"),
                    "days_left": row.get("days_remaining", -1)
                })
    except Exception as e:
        logging.exception("Error loading results for overview: %s", e)

    total, used, free = shutil.disk_usage("/data")
    disk = {
        "total_gb": round(total / (1024**3), 2),
        "used_gb": round(used / (1024**3), 2),
        "free_gb": round(free / (1024**3), 2),
        "percent": round(used / total * 100, 1)
    }

    return render_template("overview.html",
                           domains=domains,
                           disk=disk)


@app.route("/api/overviewdata")
@login_required
def overview_data():
    total, used, free = shutil.disk_usage("/data")
    disk = {
        "total_gb": round(total / (1024**3), 2),
        "used_gb": round(used / (1024**3), 2),
        "free_gb": round(free / (1024**3), 2),
        "percent": round(used / total * 100, 1)
    }
    results = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            results = json.load(f)
    return jsonify({"domains": results, "disk": disk})


# --------------------------------------------------------------------
# Admin page
# --------------------------------------------------------------------
@app.route("/admin")
@login_required
def admin_page():
    # If you already have an admin.html later, this will render it.
    log_preview = ""
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r") as f:
                log_preview = f.read()[-5000:]
        except Exception as e:
            log_preview = f"Error reading logs: {e}"

    total, used, free = shutil.disk_usage("/data")
    disk = {
        "total_gb": round(total / (1024**3), 2),
        "used_gb": round(used / (1024**3), 2),
        "free_gb": round(free / (1024**3), 2),
        "percent": round(used / total * 100, 1)
    }

    return render_template("admin.html",
                           log_preview=log_preview,
                           disk=disk)


# ---------------------------------------------------------------------
# SMTP Configuration
# ---------------------------------------------------------------------
@app.route("/admin/smtp", methods=["GET", "POST"])
@login_required
def smtp_config():
    """Configure SMTP settings for email notifications."""
    if request.method == "POST":
        smtp_host = request.form.get("smtp_host", "").strip()
        smtp_port = request.form.get("smtp_port", "587").strip()
        smtp_user = request.form.get("smtp_user", "").strip()
        smtp_pass = request.form.get("smtp_pass", "").strip()
        to_emails = request.form.get("to_emails", "").strip()
        alert_threshold_warning = request.form.get("alert_threshold_warning", "30").strip()
        alert_threshold_critical = request.form.get("alert_threshold_critical", "14").strip()
        alert_frequency = request.form.get("alert_frequency", "once").strip()
        monthly_report = request.form.get("monthly_report") == "on"
        
        # Validation
        if not smtp_host or not smtp_user or not to_emails:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   error="SMTP host, user, and recipient emails are required")
        
        try:
            smtp_port = int(smtp_port)
            alert_threshold_warning = int(alert_threshold_warning)
            alert_threshold_critical = int(alert_threshold_critical)
        except ValueError:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   error="Port and threshold values must be numbers")
        
        # Save configuration
        cfg = {
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_user": smtp_user,
            "alert_threshold_warning": alert_threshold_warning,
            "alert_threshold_critical": alert_threshold_critical,
            "alert_frequency": alert_frequency,
            "monthly_report": monthly_report
        }
        
        try:
            # If password is empty, keep the existing one
            if not smtp_pass and mail.cfg.get('smtp_pass'):
                cfg['smtp_pass'] = mail.cfg['smtp_pass']  # Preserve encrypted password
                cfg['to_emails'] = [e.strip() for e in to_emails.split(",") if e.strip()]
                # Save directly without re-encrypting
                with open(MAIL_CONFIG_PATH, 'w') as f:
                    json.dump(cfg, f, indent=2)
                mail._load()  # Reload config
            else:
                # New password provided, use normal save
                mail.save_config(cfg, smtp_pass, to_emails)
            
            logging.info("SMTP configuration updated")
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   success="SMTP configuration saved successfully")
        except Exception as e:
            logging.exception(f"Error saving SMTP config: {e}")
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   error=f"Error saving configuration: {str(e)}")
    
    # GET - show form
    return render_template("smtp_config.html", config=mail.get_config_safe())


@app.route("/admin/smtp/test", methods=["POST"])
@login_required
def smtp_test():
    """Send a test email to verify SMTP configuration."""
    try:
        result = mail.send_test()
        if result is True:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   success="Test email sent successfully! Check your inbox.")
        else:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   error=f"Failed to send test email: {result}")
    except Exception as e:
        logging.exception(f"Error sending test email: {e}")
        return render_template("smtp_config.html",
                               config=mail.get_config_safe(),
                               error=f"Error: {str(e)}")


@app.route("/admin/smtp/test-warning", methods=["POST"])
@login_required
def smtp_test_warning():
    """Send a test warning alert."""
    try:
        from datetime import timedelta
        # Simulate a certificate expiring in 25 days (warning threshold)
        test_expires = (datetime.now(timezone.utc) + timedelta(days=25)).strftime("%Y-%m-%d")
        renewal_link = get_ca_renewal_link("Let's Encrypt")
        
        result = mail.send_alert(
            domain="test-warning.example.com",
            days_remaining=25,
            expires=test_expires,
            issuer="Let's Encrypt Authority X3",
            critical=False,
            renewal_link=renewal_link
        )
        
        if result:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   success="Test WARNING alert sent! Check your inbox.")
        else:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   error="Failed to send test warning alert")
    except Exception as e:
        logging.exception(f"Error sending test warning: {e}")
        return render_template("smtp_config.html",
                               config=mail.get_config_safe(),
                               error=f"Error: {str(e)}")


@app.route("/admin/smtp/test-critical", methods=["POST"])
@login_required
def smtp_test_critical():
    """Send a test critical alert."""
    try:
        from datetime import timedelta
        # Simulate a certificate expiring in 7 days (critical threshold)
        test_expires = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d")
        renewal_link = get_ca_renewal_link("DigiCert")
        
        result = mail.send_alert(
            domain="test-critical.example.com",
            days_remaining=7,
            expires=test_expires,
            issuer="DigiCert SHA2 Secure Server CA",
            critical=True,
            renewal_link=renewal_link
        )
        
        if result:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   success="Test CRITICAL alert sent! Check your inbox.")
        else:
            return render_template("smtp_config.html",
                                   config=mail.get_config_safe(),
                                   error="Failed to send test critical alert")
    except Exception as e:
        logging.exception(f"Error sending test critical: {e}")
        return render_template("smtp_config.html",
                               config=mail.get_config_safe(),
                               error=f"Error: {str(e)}")


# ---------------------------------------------------------------------
# Check Now - Manual certificate check trigger
# ---------------------------------------------------------------------
@app.route("/check_now", methods=["POST"])
@login_required
def check_now():
    """Manually trigger certificate checks for all domains."""
    logging.info("Manual certificate check triggered via Check Now button")
    try:
        perform_checks()
    except Exception as e:
        logging.exception(f"Error during manual check: {e}")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------
# Domains page (handles existing Add button link)
# ---------------------------------------------------------------------
@app.route("/domains", methods=["GET", "POST"])
@login_required
def domains_page():
    """
    Handles the Add button form linked to /domains.
    GET -> renders form
    POST -> adds new domain to results.json
    """
    if request.method == "GET":
        # Show simple add-domain form
        data = []
        if os.path.exists(RESULTS_PATH):
            with open(RESULTS_PATH, "r") as f:
                data = json.load(f)
        
        # Normalize data
        for row in data:
            if "days_remaining" not in row and "days_left" in row:
                row["days_remaining"] = row["days_left"]
            if "checked_at" not in row and "last_checked" in row:
                row["checked_at"] = row["last_checked"]
            row.setdefault("issuer", None)
            row.setdefault("is_self_signed", False)
            row.setdefault("days_remaining", None)
            row.setdefault("error", None)
            row.setdefault("error_type", None)
            row.setdefault("checked_at", "Never")
        
        return render_template("domains.html", data=data)

    # POST -> process new domain
    domain = request.form.get("domain", "").strip().lower()
    if not domain:
        return render_template("domains.html", error="Please enter a domain name.")

    records = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH, "r") as f:
            records = json.load(f)

    if any(r.get("domain") == domain for r in records):
        return render_template("domains.html",
                               data=records,
                               error=f"Domain {domain} already exists.")

    records.append({
        "domain": domain,
        "expires": None,
        "issued": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "is_self_signed": None,
        "tls_version": None,
        "error": None,
        "error_type": None,
        "checked_at": None
    })

    with open(RESULTS_PATH, "w") as f:
        json.dump(records, f, indent=2)

    logging.info("Added domain: %s, triggering immediate check", domain)
    
    # Trigger immediate check for the new domain
    try:
        result = cert_checker.check_certificate(domain)
        # Find and update the newly added record
        for rec in records:
            if rec.get("domain") == domain:
                if result.get("ok"):
                    rec["expires"] = result.get("expires")
                    rec["issued"] = result.get("issued")
                    rec["days_remaining"] = result.get("days_remaining")
                    rec["issuer"] = result.get("issuer")
                    rec["subject"] = result.get("subject")
                    rec["is_self_signed"] = result.get("is_self_signed")
                    rec["tls_version"] = result.get("tls_version")
                    logging.info(f"  {domain}: OK - expires {result.get('expires')}")
                else:
                    rec["error"] = result.get("error")
                    rec["error_type"] = result.get("error_type")
                    logging.warning(f"  {domain}: ERROR - {result.get('error_type')}")
                rec["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                break
        
        # Save updated results
        with open(RESULTS_PATH, "w") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        logging.exception(f"Error checking new domain {domain}: {e}")
    
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------
# Parse pasted certificate
# ---------------------------------------------------------------------
@app.route("/domains/paste-cert", methods=["POST"])
@login_required
def paste_certificate():
    """Parse a pasted PEM certificate and add to monitoring."""
    cert_text = request.form.get("cert_text", "").strip()
    
    if not cert_text:
        return render_template("domains.html", error="Please paste a certificate")
    
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        # Parse the PEM certificate
        cert = x509.load_pem_x509_certificate(cert_text.encode(), default_backend())
        
        # Extract information
        subject = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        
        # Calculate days remaining
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days
        
        # Check if self-signed
        is_self_signed = cert.issuer == cert.subject
        
        # Load existing records
        records = []
        if os.path.exists(RESULTS_PATH):
            with open(RESULTS_PATH, "r") as f:
                records = json.load(f)
        
        # Check if domain already exists
        if any(r.get("domain") == subject for r in records):
            return render_template("domains.html", error=f"Domain {subject} already exists")
        
        # Add new record
        records.append({
            "domain": subject,
            "expires": not_after.strftime("%Y-%m-%d"),
            "issued": not_before.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "issuer": issuer_cn,
            "subject": subject,
            "is_self_signed": is_self_signed,
            "tls_version": None,
            "error": None,
            "error_type": None,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        })
        
        # Save
        with open(RESULTS_PATH, "w") as f:
            json.dump(records, f, indent=2)
        
        logging.info(f"Added certificate for {subject} from pasted PEM")
        
        # Reload data for display
        data = records
        for row in data:
            if "days_remaining" not in row and "days_left" in row:
                row["days_remaining"] = row["days_left"]
            if "checked_at" not in row and "last_checked" in row:
                row["checked_at"] = row["last_checked"]
            row.setdefault("issuer", None)
            row.setdefault("is_self_signed", False)
            row.setdefault("days_remaining", None)
            row.setdefault("error", None)
            row.setdefault("error_type", None)
            row.setdefault("checked_at", "Never")
        
        return render_template("domains.html", data=data, success=f"Added certificate for {subject}")
        
    except Exception as e:
        logging.exception(f"Error parsing certificate: {e}")
        return render_template("domains.html", error=f"Error parsing certificate: {str(e)}")


# ---------------------------------------------------------------------
# Delete domain
# ---------------------------------------------------------------------
@app.route("/domains/delete", methods=["POST"])
@login_required
def delete_domain():
    """Delete a domain from the monitoring list."""
    domain = request.form.get("domain", "").strip().lower()
    if not domain:
        return redirect(url_for("domains_page"))
    
    records = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH, "r") as f:
            records = json.load(f)
    
    # Filter out the domain to delete
    original_count = len(records)
    records = [r for r in records if r.get("domain") != domain]
    
    if len(records) < original_count:
        with open(RESULTS_PATH, "w") as f:
            json.dump(records, f, indent=2)
        logging.info(f"Deleted domain: {domain}")
    
    return redirect(url_for("domains_page"))


# ---------------------------------------------------------------------
# Network Discovery
# ---------------------------------------------------------------------
@app.route("/network-discovery", methods=["GET"])
@login_required
def network_discovery():
    """Network discovery page."""
    return render_template("network_discovery.html")


@app.route("/network-discovery/auto", methods=["POST"])
@login_required
def network_discovery_auto():
    """Auto-detect and scan local networks - start async scan."""
    try:
        networks = network_scanner.get_local_networks()
        
        if not networks:
            return render_template("network_discovery.html", 
                                   error="No local networks detected")
        
        # Calculate IPs
        all_ips = []
        for network in networks:
            ips = network_scanner.parse_ip_range(network)
            all_ips.extend(ips)
        
        # Limit scan size
        if len(all_ips) > 254:
            all_ips = all_ips[:254]
        
        # Generate scan ID and store in global state (session doesn't work with SSE)
        scan_id = secrets.token_hex(8)
        scan_state[scan_id] = {
            'type': 'ip',
            'targets': all_ips,
            'user': session.get('user_id', 'admin')
        }
        
        # Redirect to progress page
        return render_template("network_discovery.html",
                               scanning=True,
                               scan_count=len(all_ips),
                               scan_id=scan_id)
    
    except Exception as e:
        logging.exception(f"Error in auto-discovery: {e}")
        return render_template("network_discovery.html", error=f"Error: {str(e)}")


@app.route("/network-discovery/manual", methods=["POST"])
@login_required
def network_discovery_manual():
    """Manually scan specified IP range - start async scan."""
    ip_range = request.form.get("ip_range", "").strip()
    
    if not ip_range:
        return render_template("network_discovery.html", error="Please enter an IP range")
    
    try:
        ips = network_scanner.parse_ip_range(ip_range)
        
        # Limit scan size
        if len(ips) > 254:
            ips = ips[:254]
        
        # Generate scan ID and store in global state
        scan_id = secrets.token_hex(8)
        scan_state[scan_id] = {
            'type': 'ip',
            'targets': ips,
            'user': session.get('user_id', 'admin')
        }
        
        # Redirect to progress page
        return render_template("network_discovery.html",
                               scanning=True,
                               scan_count=len(ips),
                               scan_id=scan_id)
    
    except Exception as e:
        logging.exception(f"Error in manual scan: {e}")
        return render_template("network_discovery.html", error=f"Error: {str(e)}")


@app.route("/network-discovery/dns", methods=["POST"])
@login_required
def network_discovery_dns():
    """Query DNS zone for hosts - start async scan."""
    dns_server = request.form.get("dns_server", "").strip()
    domain_zone = request.form.get("domain_zone", "").strip()
    
    if not dns_server or not domain_zone:
        return render_template("network_discovery.html", 
                               error="DNS server and domain zone are required")
    
    try:
        logging.info(f"Querying DNS {dns_server} for zone {domain_zone}")
        hostnames = network_scanner.query_dns_zone(dns_server, domain_zone)
        
        if not hostnames:
            return render_template("network_discovery.html",
                                   error="No hosts found in DNS zone (zone transfer may be restricted)")
        
        # Generate scan ID and store in global state
        scan_id = secrets.token_hex(8)
        scan_state[scan_id] = {
            'type': 'dns',
            'targets': hostnames,
            'user': session.get('user_id', 'admin')
        }
        
        # Redirect to progress page
        return render_template("network_discovery.html",
                               scanning=True,
                               scan_count=len(hostnames),
                               scan_id=scan_id)
    
    except Exception as e:
        logging.exception(f"Error in DNS query: {e}")
        return render_template("network_discovery.html", error=f"Error: {str(e)}")


@app.route("/network-discovery/scan-progress/<scan_id>")
@login_required
def network_discovery_scan_progress(scan_id):
    """SSE endpoint for real-time scan progress."""
    from flask import Response
    import json
    
    def generate():
        """Stream scan progress events."""
        # Get scan info from global state
        scan_info = scan_state.get(scan_id)
        
        if not scan_info:
            yield f"data: {json.dumps({'error': 'Scan not found or expired'})}

"
            return
        
        scan_type = scan_info['type']
        targets = scan_info['targets']
        
        if not targets:
            yield f"data: {json.dumps({'error': 'No targets to scan'})}

"
            return
        
        total = len(targets)
        discovered = []
        
        # Scan all targets
        for idx, target in enumerate(targets):
            result = network_scanner.scan_host(target)
            if result.get('has_ssl'):
                discovered.append(result)
            
            progress = {
                'current': idx + 1,
                'total': total,
                'percent': int((idx + 1) / total * 100),
                'discovered_count': len(discovered)
            }
            yield f"data: {json.dumps(progress)}

"
            
            # Rate limiting for DNS scans
            if scan_type == 'dns':
                time.sleep(0.2)
        
        # Store results and cleanup
        scan_state[scan_id]['discovered'] = discovered
        session['discovered_hosts'] = discovered
        
        # Send completion event
        yield f"data: {json.dumps({'complete': True, 'discovered': discovered})}

"
        
        # Cleanup old scan data after some time
        def cleanup():
            time.sleep(300)  # Keep for 5 minutes
            scan_state.pop(scan_id, None)
        
        threading.Thread(target=cleanup, daemon=True).start()
    
    return Response(generate(), mimetype='text/event-stream')


@app.route("/network-discovery/add-selected", methods=["POST"])
@login_required
def network_discovery_add_selected():
    """Add selected discovered hosts to monitoring."""
    discovered = session.get('discovered_hosts', [])
    
    if not discovered:
        return redirect(url_for('network_discovery'))
    
    # Check if "Add All" was clicked
    add_all = request.form.get('add_all')
    
    if add_all:
        selected = [h['domain'] for h in discovered]
    else:
        selected = request.form.getlist('selected_hosts')
    
    if not selected:
        return render_template("network_discovery.html",
                               discovered=discovered,
                               error="No hosts selected")
    
    # Load existing records
    records = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH, "r") as f:
            records = json.load(f)
    
    existing_domains = {r.get('domain') for r in records}
    added_count = 0
    skipped_count = 0
    
    # Add selected hosts
    for host in discovered:
        domain = host['domain']
        
        if domain not in selected:
            continue
        
        if domain in existing_domains:
            skipped_count += 1
            continue
        
        # Add to records
        records.append({
            "domain": domain,
            "expires": host.get('expires'),
            "issued": host.get('issued'),
            "days_remaining": host.get('days_remaining'),
            "issuer": host.get('issuer'),
            "subject": host.get('subject'),
            "is_self_signed": host.get('is_self_signed'),
            "tls_version": host.get('tls_version'),
            "error": None,
            "error_type": None,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        })
        added_count += 1
    
    # Save
    with open(RESULTS_PATH, "w") as f:
        json.dump(records, f, indent=2)
    
    logging.info(f"Network discovery: added {added_count} hosts, skipped {skipped_count} duplicates")
    
    return redirect(url_for('dashboard'))


# --------------------------------------------------------------------
# Main entrypoint  –  HTTPS server
# --------------------------------------------------------------------
if __name__ == "__main__":
    # Launch background scheduler
    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()

    perform_checks()

    cert_path = "/data/server.crt"
    key_path = "/data/server.key"

    # Require existing cert/key (mounted from host)
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print("\n❌  TLS certificate/key not found in /data/.")
        print("Please create them on host:\n"
              "  sudo openssl req -x509 -nodes -days 730 "
              "-newkey rsa:2048 "
              "-keyout /opt/sslmon-data/server.key "
              "-out /opt/sslmon-data/server.crt "
              "-subj '/CN=sslmon.local'\n")
        raise SystemExit(1)

    print(f"✅  Starting HTTPS server on port 8443 "
          f"using cert {cert_path}")
    app.run(host="0.0.0.0", port=8443,
            ssl_context=(cert_path, key_path))
