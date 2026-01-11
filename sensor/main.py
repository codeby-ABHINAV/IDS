# sensor/main.py
from sensor.sniffer import start_sniff
from sensor.parser import parse_packet
from detection.portscan import detect_port_scan
from detection.ssh_bruteforce import detect_ssh_bruteforce
from alerts.alert_manager import raise_alert

def handle_packet(packet):
    parsed = parse_packet(packet)
    if not parsed:
        return

    src_ip = parsed.get("src_ip")
    dst_port = parsed.get("dst_port")
    protocol = parsed.get("protocol_name")

    if protocol == "TCP" and dst_port:
        # Port scan detection
        if detect_port_scan(src_ip, dst_port):
            raise_alert(
                "Port Scan Detected",
                src_ip,
                "Multiple ports scanned"
            )

        # SSH brute-force detection
        if dst_port == 22:
            if detect_ssh_bruteforce(src_ip):
                raise_alert(
                    "SSH Brute Force Detected",
                    src_ip,
                    "Multiple SSH login attempts"
                )

if __name__ == "__main__":
    print("[*] Starting Open-NIDS Sensor...")
    start_sniff(handle_packet)
