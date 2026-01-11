# alerts/alert_manager.py
import sqlite3
from datetime import datetime
from colorama import Fore, Style

DB_PATH = "database/nids.db"

def raise_alert(alert_type, src_ip, details, severity="High"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print alert
    print(
        f"{Fore.RED}[ALERT]{Style.RESET_ALL} "
        f"{timestamp} | {alert_type} | "
        f"Source: {src_ip} | {details}"
    )

    # Store alert in database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts
        (timestamp, alert_type, src_ip, details, severity, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, alert_type, src_ip, details, severity, "New"))

    conn.commit()
    conn.close()
