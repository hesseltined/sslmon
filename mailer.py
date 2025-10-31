import os, json, smtplib
from email.mime.text import MIMEText
from cryptography.fernet import Fernet

class Mailer:
    def __init__(self, key_path, cfg_path):
        self.key_path = key_path
        self.cfg_path = cfg_path
        if not os.path.exists(key_path):
            with open(key_path,"wb") as f: f.write(Fernet.generate_key())
        self.key = open(key_path,"rb").read()
        if not os.path.exists(cfg_path):
            with open(cfg_path,"w") as f: json.dump({}, f)
        self._load()

    def _load(self):
        try:
            with open(self.cfg_path) as f:
                self.cfg = json.load(f)
        except Exception:
            self.cfg = {}

    def encrypt(self, text):
        return Fernet(self.key).encrypt(text.encode()).decode()

    def decrypt(self, enc):
        try:
            return Fernet(self.key).decrypt(enc.encode()).decode()
        except Exception:
            return ""

    def save_config(self, cfg, pw, to_emails):
        enc_pw = self.encrypt(pw)
        cfg["smtp_pass"] = enc_pw
        cfg["to_emails"] = [e.strip() for e in to_emails.split(",") if e.strip()]
        with open(self.cfg_path,"w") as f: json.dump(cfg,f)
        self._load()

    def get_config_safe(self):
        out = self.cfg.copy()
        if "smtp_pass" in out: out["smtp_pass"]="********"
        return out

    def _connect(self):
        if not self.cfg: return None
        pw = self.decrypt(self.cfg.get("smtp_pass",""))
        s = smtplib.SMTP(self.cfg["smtp_host"], self.cfg.get("smtp_port",587))
        s.starttls()
        s.login(self.cfg["smtp_user"], pw)
        return s

    def _send(self, subject, body):
        s = self._connect()
        if not s: 
            return False
        msg = MIMEText(body)
        msg["From"] = self.cfg["smtp_user"]
        msg["To"] = ",".join(self.cfg["to_emails"])
        msg["Subject"] = subject
        try:
            s.send_message(msg)
            s.quit()
            return True
        except Exception as e:
            print(f"[Mailer] Send error: {e}")
            return str(e)

    def send_alert(self, domain, days_remaining, expires, issuer=None, critical=False):
        """Send alert for a specific domain approaching expiration."""
        if not self.cfg:
            return False
        level = "CRITICAL" if critical else "WARNING"
        subj = f"[SSLMon {level}] SSL Certificate Expiring: {domain}"
        
        body = f"""SSL Certificate Expiration Alert

Domain: {domain}
Issuer: {issuer or 'Unknown'}
Expires: {expires}
Days Remaining: {days_remaining}

Alert Level: {level}
Threshold: {'Critical (14 days)' if critical else 'Warning (30 days)'}

Action Required:
Please renew the SSL certificate for {domain} before it expires.

---
This is an automated message from SSLMon
"""
        return self._send(subj, body)

    def send_monthly_report(self, domains_data):
        """Send monthly status report for all certificates."""
        if not self.cfg:
            return False
        
        total = len(domains_data)
        expiring_soon = len([d for d in domains_data if d.get('days_remaining', 999) <= 30])
        critical = len([d for d in domains_data if d.get('days_remaining', 999) <= 14])
        errors = len([d for d in domains_data if d.get('error')])
        
        subj = f"[SSLMon] Monthly Certificate Status Report - {total} Domains Monitored"
        
        body = f"""SSLMon Monthly Certificate Status Report

Summary:
- Total Domains Monitored: {total}
- Expiring Soon (30 days): {expiring_soon}
- Critical (14 days): {critical}
- Check Errors: {errors}

Detailed Status:
"""
        
        # Sort by days remaining
        sorted_domains = sorted(domains_data, key=lambda x: x.get('days_remaining', 999))
        
        for domain in sorted_domains:
            name = domain.get('domain', 'Unknown')
            days = domain.get('days_remaining', -1)
            expires = domain.get('expires', 'Unknown')
            issuer = domain.get('issuer', 'Unknown')
            error = domain.get('error')
            
            if error:
                body += f"\n[ERROR] {name}\n  Status: {error}\n"
            elif days >= 0:
                status = "CRITICAL" if days <= 14 else ("WARNING" if days <= 30 else "OK")
                body += f"\n[{status}] {name}\n"
                body += f"  Expires: {expires} ({days} days)\n"
                body += f"  Issuer: {issuer}\n"
            else:
                body += f"\n[EXPIRED] {name}\n  Expired: {expires}\n"
        
        body += "\n\n---\nThis is an automated monthly report from SSLMon\n"
        
        return self._send(subj, body)

    def send_test(self):
        if not self.cfg:
            return "No configuration"
        result = self._send("SSLMon Test Email", "This is a test from your SSLMon instance.\n\nIf you received this, your SMTP configuration is working correctly!")
        return result
