import smtplib
import os
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

SENDER = os.getenv("EMAIL_SENDER")
APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
RECEIVER = os.getenv("EMAIL_RECEIVER")

last_sent = {}  # एकाच IP साठी परत परत email न पाठवण्यासाठी, 5 मिनिटांचा gap
COOLDOWN_SECONDS = 500

def send_alert_email(ip, mac_addresses, mitre_info):
    if ip in last_sent and (time.time() - last_sent[ip] < COOLDOWN_SECONDS):
        return False

    subject = f"Critical ARP Spoofing Detected — {ip}"
    body = f"""
Security Alert: Possible ARP Spoofing Detected

IP Address: {ip}
MAC Addresses observed: {mac_addresses}
Detected at: {time.strftime('%Y-%m-%d %H:%M:%S')}

MITRE ATT&CK Technique: {mitre_info['technique']} - {mitre_info['name']}
Tactic: {mitre_info['tactic']}

Recommended Mitigation: {mitre_info['mitigation']}

This is an automated alert from the Advanced Packet Sniffer & ARP Spoofing Detector.
Please investigate and confirm before taking action.
"""

    msg = MIMEMultipart()
    msg["From"] = SENDER
    msg["To"] = RECEIVER
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER, APP_PASSWORD)
        server.sendmail(SENDER, RECEIVER, msg.as_string())
        server.quit()
        last_sent[ip] = time.time()
        return True
    except Exception as e:
        print(f"Email send error: {e}")
        return False
