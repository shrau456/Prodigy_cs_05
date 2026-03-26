import scapy.all as scapy
from scapy.layers import http
import argparse
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

packet_count = 0

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to capture packets from")
    parser.add_argument("-c", "--count", dest="count", type=int, default=0,
                        help="Number of packets to capture (0 for unlimited)")
    return parser.parse_args()

def get_protocol_name(proto_num):
    if proto_num == 6:
        return "TCP"
    elif proto_num == 17:
        return "UDP"
    elif proto_num == 1:
        return "ICMP"
    else:
        return str(proto_num)

def process_packet(packet):
    global packet_count
    packet_count += 1

    print(f"\n-------- Packet #{packet_count} --------")

    if not packet.haslayer(scapy.IP):
        print("[!] Non-IP Packet Captured")
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    protocol = get_protocol_name(packet[scapy.IP].proto)

    print(f"Source IP      : {src_ip}")
    print(f"Destination IP : {dst_ip}")
    print(f"Protocol       : {protocol}")

    if packet.haslayer(http.HTTPRequest):
        try:
            host = packet[http.HTTPRequest].Host.decode(errors='ignore')
            path = packet[http.HTTPRequest].Path.decode(errors='ignore')
            method = packet[http.HTTPRequest].Method.decode(errors='ignore')

            print("Type           : HTTP Request")
            print(f"HTTP Method    : {method}")
            print(f"URL            : http://{host}{path}")
        except:
            print("[!] Error decoding HTTP data")

    elif packet.haslayer(scapy.TCP):
        print("Type           : TCP Packet")

    elif packet.haslayer(scapy.UDP):
        print("Type           : UDP Packet")

    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        print(f"Payload        : {payload[:100]}")

def sniff_packets(interface, count):
    try:
        print(f"\n[+] Starting packet capture on interface: {interface}")
        print("[!] Press Ctrl+C to stop")
        print("[!] Educational use only. Capture authorized traffic only.\n")

        scapy.sniff(
            iface=interface,
            store=False,
            prn=process_packet,
            count=count
        )

    except KeyboardInterrupt:
        print("\n[!] Packet capture stopped by user.")
        sys.exit(0)

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        sys.exit(1)

def main():
    print("\n" + "-"*80)
    print("NETWORK PACKET ANALYZER")
    print("-"*80)
    print("WARNING: This tool is for educational purposes only.")
    print("Unauthorized packet capture may violate privacy laws.")
    print("Use only on networks you own or have permission to monitor.")
    print("-"*80 + "\n")

    args = get_arguments()

    if not args.interface:
        logging.error("Please specify an interface using -i or --interface")
        print("\nExample: python prodigy_cs_05.py -i Wi-Fi -c 10")
        sys.exit(1)

    sniff_packets(args.interface, args.count)

if __name__ == "__main__":
    main()