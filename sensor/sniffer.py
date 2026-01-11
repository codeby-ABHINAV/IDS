# sensor/sniffer.py
from scapy.all import sniff

def start_sniff(packet_handler):
    """
    Starts packet sniffing and sends each packet
    to the handler function
    """
    sniff(prn=packet_handler, store=False)
