# Prodigy_cs_05
# Network Packet Analyzer
A Python-based Network Packet Analyzer (Packet Sniffer) that captures and analyzes live network traffic. It extracts important information such as source IP, destination IP, protocol type, HTTP details, and payload data.
# Features
- Capture live network packets
- Display Source & Destination IP addresses
- Identify protocols (TCP, UDP, ICMP)
- Analyze HTTP requests (GET, POST, URLs)
- Display packet payload (limited for readability)
- Packet counter for tracking captured packets
- Ethical usage warning included
# Technologies Used
- Python 3
- Scapy
# Requirements
Make sure you have the following installed:
- Python 3.x
- Scapy
- Npcap (Required for Windows users)
# Installation
1. Install Dependencies
```
pip install scapy
```
2. Install Npcap (Windows Only)
Download and install from:
```
https://npcap.com/
```
Enable WinPcap API-compatible Mode during installation
# Usage
Run the program using:
```
python prodigy_cs_05.py -i <interface> -c <count>
```
# Sample Output
```
-------- Packet #1 --------
Source IP : 192.168.1.5
Destination IP : 142.250.183.14
Protocol : TCP
Type : HTTP Request
Payload : b'GET / HTTP/1.1...'
```
# Ethical Usage
This project is developed strictly for educational purposes.
- Unauthorized packet capturing may violate privacy laws and regulations.
- Always use this tool on networks you own or have permission to monitor.
# Author
- Created by : Suryawanshi Shravani Dnyanoba
- Task 5 :  Network Packet Analyzer - Completed
