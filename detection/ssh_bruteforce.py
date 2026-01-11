# detection/ssh_bruteforce.py
import time
from collections import defaultdict

attempt_tracker = defaultdict(list)

ATTEMPT_THRESHOLD = 5
TIME_WINDOW = 60  # seconds

def detect_ssh_bruteforce(src_ip):
    current_time = time.time()

    attempt_tracker[src_ip].append(current_time)

    # Keep only recent attempts
    attempt_tracker[src_ip] = [
        t for t in attempt_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    if len(attempt_tracker[src_ip]) >= ATTEMPT_THRESHOLD:
        return True

    return False
