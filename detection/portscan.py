# detection/portscan.py
import time
from collections import defaultdict

# Store ports scanned by each IP
scan_tracker = defaultdict(list)

PORT_THRESHOLD = 10
TIME_WINDOW = 60  # seconds

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()

    # Add current port with timestamp
    scan_tracker[src_ip].append((dst_port, current_time))

    # Keep only recent entries
    scan_tracker[src_ip] = [
        (port, t) for port, t in scan_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    # Unique ports count
    unique_ports = set(port for port, _ in scan_tracker[src_ip])

    if len(unique_ports) >= PORT_THRESHOLD:
        return True

    return False
