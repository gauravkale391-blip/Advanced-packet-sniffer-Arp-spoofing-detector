from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP
import time
from database import init_db, insert_packet, insert_arp_event

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def process_packet(packet):
    if packet.haslayer(ARP):
        arp_data = {
            "ip": packet[ARP].psrc,
            "mac": packet[ARP].hwsrc,
            "op": "reply" if packet[ARP].op == 2 else "request",
            "timestamp": time.time()
        }
        insert_arp_event(arp_data)
        print("ARP captured:", arp_data)

    if packet.haslayer(IP):
        protocol = PROTOCOLS.get(packet[IP].proto, str(packet[IP].proto))
        data = {
            "source": packet[IP].src,
            "destination": packet[IP].dst,
            "protocol": protocol,
            "length": len(packet),
            "timestamp": time.time()
        }
        insert_packet(data)
        print("captured:", data)


def start_sniffing():
    init_db()
    sniff(prn=process_packet, store=False, iface="wlan0")


if __name__ == "__main__":
    print("Sniffer starting...")
    start_sniffing()
