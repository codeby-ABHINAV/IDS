import sqlite3
import os

DB_PATH = "database/nids.db"
os.makedirs("database", exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Alerts table
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    alert_type TEXT,
    src_ip TEXT,
    details TEXT,
    severity TEXT,
    status TEXT
)
""")

# Users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
)
""")

# Active users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS active_users (
    username TEXT PRIMARY KEY,
    role TEXT,
    login_time TEXT
)
""")

# Default users
cursor.execute("""
INSERT OR IGNORE INTO users (username, password, role)
VALUES
('admin', 'admin123', 'admin'),
('analyst', 'analyst123', 'analyst')
""")

conn.commit()
conn.close()

print("[+] Database initialized with users")
