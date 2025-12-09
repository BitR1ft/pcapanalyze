"""
Connection tracking module
Tracks TCP/UDP flows and analyzes connection patterns
"""
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from utils.logger import logger

class ConnectionTracker:
    """Track and analyze network connections"""
    
    def __init__(self):
        self.tcp_connections = {}
        self.udp_flows = {}
        self.connection_list = []
    
    def analyze_connections(self, packets: List) -> List[Dict[str, Any]]:
        """Analyze all connections in packet list"""
        logger.info("Analyzing network connections...")
        
        self.tcp_connections = {}
        self.udp_flows = {}
        self.connection_list = []
        
        for i, pkt in enumerate(packets):
            if hasattr(pkt, 'IP'):
                if hasattr(pkt, 'TCP'):
                    self._process_tcp_packet(pkt, i)
                elif hasattr(pkt, 'UDP'):
                    self._process_udp_packet(pkt, i)
        
        # Compile connection summaries
        self._compile_connections()
        
        logger.info(f"Found {len(self.connection_list)} connections")
        return self.connection_list
    
    def _get_tcp_key(self, pkt) -> Tuple:
        """Generate unique key for TCP connection"""
        src_ip = pkt['IP'].src
        dst_ip = pkt['IP'].dst
        src_port = pkt['TCP'].sport
        dst_port = pkt['TCP'].dport
        
        # Normalize key (smaller IP:port first)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        else:
            return (dst_ip, dst_port, src_ip, src_port)
    
    def _process_tcp_packet(self, pkt, index: int):
        """Process a TCP packet"""
        key = self._get_tcp_key(pkt)
        
        if key not in self.tcp_connections:
            self.tcp_connections[key] = {
                'src_ip': key[0],
                'src_port': key[1],
                'dst_ip': key[2],
                'dst_port': key[3],
                'protocol': 'TCP',
                'packets': [],
                'start_time': float(pkt.time) if hasattr(pkt, 'time') else 0,
                'end_time': float(pkt.time) if hasattr(pkt, 'time') else 0,
                'bytes_sent': 0,
                'bytes_recv': 0,
                'syn_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'retransmissions': 0,
                'out_of_order': 0,
                'state': 'unknown',
                'events': []
            }
        
        conn = self.tcp_connections[key]
        conn['packets'].append(index)
        conn['end_time'] = float(pkt.time) if hasattr(pkt, 'time') else conn['end_time']
        
        # Analyze TCP flags
        tcp = pkt['TCP']
        flags = tcp.flags
        
        # Track connection state
        if flags & 0x02:  # SYN
            conn['syn_count'] += 1
            conn['events'].append({'time': pkt.time, 'event': 'SYN', 'packet': index})
            if conn['state'] == 'unknown':
                conn['state'] = 'syn_sent'
        
        if flags & 0x10:  # ACK
            if conn['state'] == 'syn_sent':
                conn['state'] = 'established'
                conn['events'].append({'time': pkt.time, 'event': 'ESTABLISHED', 'packet': index})
        
        if flags & 0x01:  # FIN
            conn['fin_count'] += 1
            conn['state'] = 'closing'
            conn['events'].append({'time': pkt.time, 'event': 'FIN', 'packet': index})
        
        if flags & 0x04:  # RST
            conn['rst_count'] += 1
            conn['state'] = 'reset'
            conn['events'].append({'time': pkt.time, 'event': 'RST', 'packet': index})
        
        # Track bytes
        pkt_len = len(pkt)
        if pkt['IP'].src == key[0]:
            conn['bytes_sent'] += pkt_len
        else:
            conn['bytes_recv'] += pkt_len
    
    def _get_udp_key(self, pkt) -> Tuple:
        """Generate unique key for UDP flow"""
        src_ip = pkt['IP'].src
        dst_ip = pkt['IP'].dst
        src_port = pkt['UDP'].sport
        dst_port = pkt['UDP'].dport
        
        # Normalize key
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        else:
            return (dst_ip, dst_port, src_ip, src_port)
    
    def _process_udp_packet(self, pkt, index: int):
        """Process a UDP packet"""
        key = self._get_udp_key(pkt)
        
        if key not in self.udp_flows:
            self.udp_flows[key] = {
                'src_ip': key[0],
                'src_port': key[1],
                'dst_ip': key[2],
                'dst_port': key[3],
                'protocol': 'UDP',
                'packets': [],
                'start_time': float(pkt.time) if hasattr(pkt, 'time') else 0,
                'end_time': float(pkt.time) if hasattr(pkt, 'time') else 0,
                'bytes_sent': 0,
                'bytes_recv': 0
            }
        
        flow = self.udp_flows[key]
        flow['packets'].append(index)
        flow['end_time'] = float(pkt.time) if hasattr(pkt, 'time') else flow['end_time']
        
        # Track bytes
        pkt_len = len(pkt)
        if pkt['IP'].src == key[0]:
            flow['bytes_sent'] += pkt_len
        else:
            flow['bytes_recv'] += pkt_len
    
    def _compile_connections(self):
        """Compile all connections into a single list"""
        self.connection_list = []
        
        # Add TCP connections
        for key, conn in self.tcp_connections.items():
            summary = {
                'src_ip': conn['src_ip'],
                'src_port': conn['src_port'],
                'dst_ip': conn['dst_ip'],
                'dst_port': conn['dst_port'],
                'protocol': 'TCP',
                'packets': len(conn['packets']),
                'duration': conn['end_time'] - conn['start_time'],
                'bytes_total': conn['bytes_sent'] + conn['bytes_recv'],
                'bytes_sent': conn['bytes_sent'],
                'bytes_recv': conn['bytes_recv'],
                'state': conn['state'],
                'events': len(conn['events']),
                'anomalies': conn['retransmissions'] + conn['out_of_order']
            }
            self.connection_list.append(summary)
        
        # Add UDP flows
        for key, flow in self.udp_flows.items():
            summary = {
                'src_ip': flow['src_ip'],
                'src_port': flow['src_port'],
                'dst_ip': flow['dst_ip'],
                'dst_port': flow['dst_port'],
                'protocol': 'UDP',
                'packets': len(flow['packets']),
                'duration': flow['end_time'] - flow['start_time'],
                'bytes_total': flow['bytes_sent'] + flow['bytes_recv'],
                'bytes_sent': flow['bytes_sent'],
                'bytes_recv': flow['bytes_recv'],
                'state': 'stateless',
                'events': 0,
                'anomalies': 0
            }
            self.connection_list.append(summary)
        
        # Sort by total bytes
        self.connection_list.sort(key=lambda x: x['bytes_total'], reverse=True)
    
    def get_connection_details(self, src_ip: str, src_port: int, 
                              dst_ip: str, dst_port: int, 
                              protocol: str) -> Dict[str, Any]:
        """Get detailed information about a specific connection"""
        if protocol == 'TCP':
            key = self._normalize_key(src_ip, src_port, dst_ip, dst_port)
            return self.tcp_connections.get(key, {})
        elif protocol == 'UDP':
            key = self._normalize_key(src_ip, src_port, dst_ip, dst_port)
            return self.udp_flows.get(key, {})
        return {}
    
    def _normalize_key(self, src_ip: str, src_port: int, 
                       dst_ip: str, dst_port: int) -> Tuple:
        """Normalize connection key"""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        else:
            return (dst_ip, dst_port, src_ip, src_port)
    
    def get_top_connections(self, n: int = 10) -> List[Dict[str, Any]]:
        """Get top N connections by traffic volume"""
        return self.connection_list[:n]
    
    def get_connections_by_port(self, port: int) -> List[Dict[str, Any]]:
        """Get all connections involving a specific port"""
        return [conn for conn in self.connection_list 
                if conn['src_port'] == port or conn['dst_port'] == port]
    
    def get_connections_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Get all connections involving a specific IP"""
        return [conn for conn in self.connection_list 
                if conn['src_ip'] == ip or conn['dst_ip'] == ip]
