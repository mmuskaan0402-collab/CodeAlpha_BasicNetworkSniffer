# CodeAlpha Basic Network Sniffer

## Overview

This project is a Python-based Network Packet Sniffer developed as part of the CodeAlpha Cyber Security Internship.

The application captures live network packets using the Scapy library and displays important packet information such as source and destination IP addresses, MAC addresses, protocols, ports, packet size, TCP flags, timestamps, and payloads.

Captured packets are also saved into CSV and PCAP files for future analysis.

---

## Features

- Capture live network traffic
- Display Source & Destination IP
- Display Source & Destination MAC Address
- Detect TCP, UDP and ICMP protocols
- Display Source & Destination Ports
- Display TCP Flags
- Display Packet Length
- Display Payload
- Timestamp every packet
- Save packet details to CSV
- Save captured packets as PCAP
- Clean formatted console output

---

## Technologies Used

- Python 3
- Scapy
- Colorama

---

## Installation

Clone the repository

```bash
git clone https://github.com/YourUsername/CodeAlpha_BasicNetworkSniffer.git
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the project

```bash
python sniffer.py
```

---

## Output

The application displays

- Timestamp
- Source MAC Address
- Destination MAC Address
- Source IP
- Destination IP
- Protocol
- Source Port
- Destination Port
- TCP Flags
- Packet Length
- Payload

---

## Files Generated

- captured_packets.csv
- captured_packets.pcap

---

## Learning Outcomes

- Packet Sniffing
- Network Protocol Analysis
- TCP/IP
- Ethernet
- Scapy
- Network Traffic Analysis

---

## Author

Developed by **Your Name**

CodeAlpha Cyber Security Internship