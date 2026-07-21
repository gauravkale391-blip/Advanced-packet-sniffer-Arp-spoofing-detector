import sqlite3
import time

DB_FILE = "network_monitor.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            destination TEXT,
            protocol TEXT,
            length INTEGER,
            timestamp REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS arp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac TEXT,
            op TEXT,
            timestamp REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac_addresses TEXT,
            mac_count INTEGER,
            timestamp REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            ip TEXT PRIMARY KEY,
            malicious_count INTEGER,
            harmless_count INTEGER,
            country TEXT,
            checked_at REAL
        )
    """)

    conn.commit()
    conn.close()


def insert_packet(data):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO packets (source, destination, protocol, length, timestamp) VALUES (?, ?, ?, ?, ?)",
        (data["source"], data["destination"], data["protocol"], data["length"], data["timestamp"])
    )
    conn.commit()
    conn.close()


def insert_arp_event(data):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO arp_events (ip, mac, op, timestamp) VALUES (?, ?, ?, ?)",
        (data["ip"], data["mac"], data["op"], data["timestamp"])
    )
    conn.commit()
    conn.close()


def get_recent_packets(limit=200):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT source, destination, protocol, length, timestamp FROM packets ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    packets = []
    for row in rows:
        packets.append({
            "source": row[0],
            "destination": row[1],
            "protocol": row[2],
            "length": row[3],
            "timestamp": row[4]
        })
    return packets


def get_recent_arp_events(limit=500):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT ip, mac, op, timestamp FROM arp_events ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    arp_events = []
    for row in rows:
        arp_events.append({
            "ip": row[0],
            "mac": row[1],
            "op": row[2],
            "timestamp": row[3]
        })
    return arp_events
def get_cached_threat_intel(ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT malicious_count, harmless_count, country, checked_at FROM threat_intel_cache WHERE ip = ?",
        (ip,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "malicious_count": row[0],
            "harmless_count": row[1],
            "country": row[2],
            "checked_at": row[3]
        }
    return None


def save_threat_intel(ip, malicious_count, harmless_count, country):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO threat_intel_cache (ip, malicious_count, harmless_count, country, checked_at) VALUES (?, ?, ?, ?, ?)",
        (ip, malicious_count, harmless_count, country, time.time())
    )
    conn.commit()
    conn.close()
