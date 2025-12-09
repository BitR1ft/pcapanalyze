"""
Filtering and search utilities for packet analysis
"""
import re
from typing import List, Dict, Any, Callable

class PacketFilter:
    """Filter packets based on various criteria"""
    
    def __init__(self):
        self.filters = []
    
    def add_protocol_filter(self, protocol: str):
        """Filter by protocol (TCP, UDP, ICMP, etc.)"""
        protocol_upper = protocol.upper()
        def protocol_match(pkt):
            return hasattr(pkt, protocol_upper) or protocol_upper in pkt.sprintf('%IP.proto%')
        self.filters.append(protocol_match)
    
    def add_ip_filter(self, ip_address: str, src=True, dst=True):
        """Filter by IP address (source and/or destination)"""
        def ip_match(pkt):
            if hasattr(pkt, 'IP'):
                if src and hasattr(pkt['IP'], 'src') and pkt['IP'].src == ip_address:
                    return True
                if dst and hasattr(pkt['IP'], 'dst') and pkt['IP'].dst == ip_address:
                    return True
            return False
        self.filters.append(ip_match)
    
    def add_port_filter(self, port: int, src=True, dst=True):
        """Filter by port number (source and/or destination)"""
        def port_match(pkt):
            if hasattr(pkt, 'TCP'):
                if src and hasattr(pkt['TCP'], 'sport') and pkt['TCP'].sport == port:
                    return True
                if dst and hasattr(pkt['TCP'], 'dport') and pkt['TCP'].dport == port:
                    return True
            if hasattr(pkt, 'UDP'):
                if src and hasattr(pkt['UDP'], 'sport') and pkt['UDP'].sport == port:
                    return True
                if dst and hasattr(pkt['UDP'], 'dport') and pkt['UDP'].dport == port:
                    return True
            return False
        self.filters.append(port_match)
    
    def add_keyword_filter(self, keyword: str, case_sensitive=False):
        """Filter by keyword in packet payload"""
        def keyword_match(pkt):
            if hasattr(pkt, 'Raw'):
                payload = bytes(pkt['Raw']).decode('utf-8', errors='ignore')
                if case_sensitive:
                    return keyword in payload
                else:
                    return keyword.lower() in payload.lower()
            return False
        self.filters.append(keyword_match)
    
    def add_length_filter(self, min_length=0, max_length=float('inf')):
        """Filter by packet length"""
        self.filters.append(lambda pkt: min_length <= len(pkt) <= max_length)
    
    def add_custom_filter(self, filter_func: Callable):
        """Add a custom filter function"""
        self.filters.append(filter_func)
    
    def apply(self, packets: List) -> List:
        """Apply all filters to a list of packets"""
        if not self.filters:
            return packets
        
        filtered_packets = []
        for pkt in packets:
            if all(f(pkt) for f in self.filters):
                filtered_packets.append(pkt)
        
        return filtered_packets
    
    def clear(self):
        """Clear all filters"""
        self.filters = []

class PacketSearcher:
    """Search functionality for packets"""
    
    @staticmethod
    def search_by_regex(packets: List, pattern: str, field='payload') -> List:
        """Search packets using regular expression"""
        regex = re.compile(pattern, re.IGNORECASE)
        results = []
        
        for pkt in packets:
            if field == 'payload':
                if hasattr(pkt, 'Raw'):
                    payload = bytes(pkt['Raw']).decode('utf-8', errors='ignore')
                    if regex.search(payload):
                        results.append(pkt)
            elif field == 'summary':
                if regex.search(pkt.summary()):
                    results.append(pkt)
        
        return results
    
    @staticmethod
    def search_by_ip(packets: List, ip_address: str) -> List:
        """Search for packets containing specific IP address"""
        results = []
        for pkt in packets:
            if hasattr(pkt, 'IP'):
                if (hasattr(pkt['IP'], 'src') and pkt['IP'].src == ip_address) or \
                   (hasattr(pkt['IP'], 'dst') and pkt['IP'].dst == ip_address):
                    results.append(pkt)
        return results
    
    @staticmethod
    def search_by_mac(packets: List, mac_address: str) -> List:
        """Search for packets containing specific MAC address"""
        results = []
        mac_normalized = mac_address.lower()
        for pkt in packets:
            if hasattr(pkt, 'Ether'):
                if (hasattr(pkt['Ether'], 'src') and pkt['Ether'].src.lower() == mac_normalized) or \
                   (hasattr(pkt['Ether'], 'dst') and pkt['Ether'].dst.lower() == mac_normalized):
                    results.append(pkt)
        return results
    
    @staticmethod
    def search_by_protocol(packets: List, protocol: str) -> List:
        """Search for packets of specific protocol"""
        results = []
        protocol_upper = protocol.upper()
        for pkt in packets:
            if hasattr(pkt, protocol_upper):
                results.append(pkt)
        return results
