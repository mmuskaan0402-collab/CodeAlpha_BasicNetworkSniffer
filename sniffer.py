from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from datetime import datetime
from colorama import Fore, Style, init
import csv
import os

init(autoreset=True)

CSV_FILE = "captured_packets.csv"
PCAP_FILE = "captured_packets.pcap"

packet_number = 1
captured_packets = []


# -----------------------------
# Create CSV File
# -----------------------------
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Packet No",
            "Timestamp",
            "Source MAC",
            "Destination MAC",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Service",
            "TCP Flags",
            "Length",
            "Payload"
        ])


# -----------------------------
# Port Number → Service Name
# -----------------------------
def get_service(port):

    services = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
    }

    return services.get(port, "Unknown")


# -----------------------------
# Process Packet
# -----------------------------
def process_packet(packet):

    global packet_number

    captured_packets.append(packet)

    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    src_mac = "-"
    dst_mac = "-"

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    src_ip = "-"
    dst_ip = "-"

    protocol = "Unknown"

    src_port = "-"
    dst_port = "-"

    tcp_flags = "-"

    service = "-"

    payload = "None"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if packet.haslayer(TCP):

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        service = get_service(dst_port)

        tcp_flags = packet.sprintf("%TCP.flags%")

    elif packet.haslayer(UDP):

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        service = get_service(dst_port)

    elif packet.haslayer(ICMP):

        protocol = "ICMP"

    if packet.haslayer(Raw):
        payload = repr(packet[Raw].load)

    length = len(packet)

    print(Fore.CYAN + "=" * 75)
    print(Fore.YELLOW + f"Packet #{packet_number}")
    print(Fore.CYAN + "=" * 75)

    print(f"Timestamp         : {timestamp}")

    print(f"Source MAC        : {src_mac}")
    print(f"Destination MAC   : {dst_mac}")

    print(f"Source IP         : {src_ip}")
    print(f"Destination IP    : {dst_ip}")

    print(f"Protocol          : {protocol}")

    if protocol in ["TCP", "UDP"]:

        print(f"Source Port       : {src_port}")

        print(f"Destination Port  : {dst_port}")

        print(f"Service           : {service}")

    if protocol == "TCP":
        print(f"TCP Flags         : {tcp_flags}")

    print(f"Packet Length     : {length} bytes")

    print("\nPayload:")

    print(payload)

    print()

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            packet_number,
            timestamp,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            service,
            tcp_flags,
            length,
            payload
        ])

    packet_number += 1


# -----------------------------
# Main Program
# -----------------------------
print(Fore.GREEN + "=" * 75)
print(Fore.GREEN + "          CODEALPHA BASIC NETWORK SNIFFER")
print(Fore.GREEN + "=" * 75)

print("\nCapturing 20 packets...\n")

try:

    sniff(prn=process_packet, count=20)

except KeyboardInterrupt:

    print("\nCapture Stopped.")

finally:

    if captured_packets:
        wrpcap(PCAP_FILE, captured_packets)

    print(Fore.GREEN + "\nCapture Completed Successfully!")

    print(Fore.GREEN + f"CSV File  : {CSV_FILE}")

    print(Fore.GREEN + f"PCAP File : {PCAP_FILE}")

    print(Fore.GREEN + f"Total Packets Captured : {len(captured_packets)}")