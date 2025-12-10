#!/usr/bin/env python3
"""
Sample PCAP generator for testing
Creates synthetic network traffic for demonstration purposes
"""
from scapy.all import *
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def generate_http_traffic():
    """Generate sample HTTP traffic"""
    packets = []
    
    # HTTP GET Request
    ip = IP(src="192.168.1.100", dst="93.184.216.34")
    tcp = TCP(sport=random.randint(49152, 65535), dport=80, flags="PA")
    http_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    packets.append(ip/tcp/Raw(load=http_request))
    
    # HTTP Response
    ip_resp = IP(src="93.184.216.34", dst="192.168.1.100")
    tcp_resp = TCP(sport=80, dport=tcp.sport, flags="PA")
    http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 50\r\n\r\n<html><body>Hello World!</body></html>"
    packets.append(ip_resp/tcp_resp/Raw(load=http_response))
    
    return packets

def generate_dns_traffic():
    """Generate sample DNS traffic"""
    packets = []
    
    # DNS Query
    ip = IP(src="192.168.1.100", dst="8.8.8.8")
    udp = UDP(sport=random.randint(49152, 65535), dport=53)
    dns = DNS(rd=1, qd=DNSQR(qname="example.com"))
    packets.append(ip/udp/dns)
    
    # DNS Response
    ip_resp = IP(src="8.8.8.8", dst="192.168.1.100")
    udp_resp = UDP(sport=53, dport=udp.sport)
    dns_resp = DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    packets.append(ip_resp/udp_resp/dns_resp)
    
    return packets

def generate_tcp_handshake():
    """Generate TCP three-way handshake"""
    packets = []
    
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200"
    src_port = random.randint(49152, 65535)
    dst_port = 443
    
    # SYN
    syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
    packets.append(syn)
    
    # SYN-ACK
    synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
    packets.append(synack)
    
    # ACK
    ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
    packets.append(ack)
    
    return packets

def generate_icmp_traffic():
    """Generate ICMP ping traffic"""
    packets = []
    
    # Ping request
    ip = IP(src="192.168.1.100", dst="8.8.8.8")
    icmp = ICMP(type=8, code=0, id=random.randint(1, 65535), seq=1)
    packets.append(ip/icmp/Raw(load=b"ping data"))
    
    # Ping reply
    ip_resp = IP(src="8.8.8.8", dst="192.168.1.100")
    icmp_resp = ICMP(type=0, code=0, id=icmp.id, seq=1)
    packets.append(ip_resp/icmp_resp/Raw(load=b"ping data"))
    
    return packets

def generate_arp_traffic():
    """Generate ARP traffic"""
    packets = []
    
    # ARP Request
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="192.168.1.1")
    packets.append(arp_req)
    
    # ARP Reply
    arp_reply = Ether()/ARP(op=2, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1", 
                            hwdst=arp_req.src, pdst=arp_req.psrc)
    packets.append(arp_reply)
    
    return packets

def generate_port_scan():
    """Generate port scan traffic (for anomaly detection testing)"""
    packets = []
    
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200"
    src_port = random.randint(49152, 65535)
    
    # Scan multiple ports
    for port in range(20, 35):  # Scan ports 20-34
        syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=port, flags="S")
        packets.append(syn)
    
    return packets

def generate_sample_pcap(filename="samples/sample_traffic.pcap"):
    """Generate a comprehensive sample PCAP file"""
    print(f"Generating sample PCAP file: {filename}")
    
    # Create samples directory if it doesn't exist
    import os
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    all_packets = []
    
    # Add various types of traffic
    print("  - Adding ARP traffic...")
    all_packets.extend(generate_arp_traffic())
    
    print("  - Adding TCP handshake...")
    all_packets.extend(generate_tcp_handshake())
    
    print("  - Adding DNS traffic...")
    all_packets.extend(generate_dns_traffic())
    
    print("  - Adding HTTP traffic...")
    all_packets.extend(generate_http_traffic())
    
    print("  - Adding ICMP traffic...")
    all_packets.extend(generate_icmp_traffic())
    
    print("  - Adding port scan (for anomaly detection)...")
    all_packets.extend(generate_port_scan())
    
    # Write to file
    wrpcap(filename, all_packets)
    
    print(f"✓ Generated {len(all_packets)} packets")
    print(f"✓ Saved to: {filename}")
    
    return filename

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample PCAP files for testing')
    parser.add_argument('-o', '--output', default='samples/sample_traffic.pcap',
                       help='Output PCAP file (default: samples/sample_traffic.pcap)')
    
    args = parser.parse_args()
    
    generate_sample_pcap(args.output)
    
    print("\nYou can now analyze this file with:")
    print(f"  python pcap_analyzer.py -f {args.output}")
    print("or")
    print(f"  python pcap_analyzer.py  # Then open {args.output} from GUI")

if __name__ == '__main__':
    main()
