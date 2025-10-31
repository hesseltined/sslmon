#!/usr/bin/env python3
import os
import json
import logging
import threading
import time
import shutil
import subprocess
import ssl
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for

# Import certificate checker module
import cert_checker

# --------------------------------------------------------------------
# Flask setup
# --------------------------------------------------------------------
app = Flask(__name__)

LOG_PATH = "/data/sslmon.log"
RESULTS_PATH = "/data/results.json"

os.makedirs("/data", exist_ok=True)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# --------------------------------------------------------------------
# Utility functions
# --------------------------------------------------------------------
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


def scheduler_loop():
    """Simple background loop to re‑run perform_checks every 24 hours."""
    while True:
        time.sleep(24 * 3600)
        logging.info("Scheduled daily SSL check triggered.")
        perform_checks()


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------
@app.route("/")
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
    
    return render_template("dashboard.html", data=data)


@app.route("/api/results")
def api_results():
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            data = json.load(f)
        return jsonify(data)
    return jsonify([])


@app.route("/health")
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
# Check Now - Manual certificate check trigger
# ---------------------------------------------------------------------
@app.route("/check_now", methods=["POST"])
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
# Delete domain
# ---------------------------------------------------------------------
@app.route("/domains/delete", methods=["POST"])
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
