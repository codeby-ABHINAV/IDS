# sensor/parser.py
from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_packet(packet):
    data = {}

    if IP in packet:
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst
        data["protocol"] = packet[IP].proto

        if TCP in packet:
            data["protocol_name"] = "TCP"
            data["src_port"] = packet[TCP].sport
            data["dst_port"] = packet[TCP].dport
            data["flags"] = packet[TCP].flags

        elif UDP in packet:
            data["protocol_name"] = "UDP"
            data["src_port"] = packet[UDP].sport
            data["dst_port"] = packet[UDP].dport

        elif ICMP in packet:
            data["protocol_name"] = "ICMP"

        return data

    return None
