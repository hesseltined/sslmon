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

    def send_alert(self, domain, info, critical=False):
        if not self.cfg: return
        level = "ACTION REQUIRED" if critical else "Warning"
        subj = f"{level}: SSL certificate expiring for {domain}"
        body = f"Domain: {domain}\nExpires: {info['expires']}\nDays Left: {info['days_left']}"
        self._send(subj, body)

    def send_test(self):
        if not self.cfg:
            return "No configuration"
        result = self._send("SSLMon test email", "This is a test from your SSLMon instance.")
        return result
