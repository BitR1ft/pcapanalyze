"""
Anomaly detection module
Detects suspicious activities and patterns in network traffic
"""
from typing import List, Dict, Any
from collections import defaultdict, Counter
from utils.logger import logger

class AnomalyDetector:
    """Detect anomalies in network traffic"""
    
    def __init__(self):
        self.anomalies = []
        self.thresholds = {
            'port_scan_threshold': 10,  # Number of different ports in short time
            'syn_flood_threshold': 100,  # SYN packets without ACK
            'unusual_packet_size': 10000,  # Unusually large packets
            'high_retransmission_rate': 0.1,  # 10% retransmission rate
            'dns_tunnel_query_length': 50,  # Suspiciously long DNS queries
        }
    
    def detect_anomalies(self, packets: List, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect various anomalies in traffic"""
        logger.info("Running anomaly detection...")
        
        self.anomalies = []
        
        # Port scan detection
        self.anomalies.extend(self._detect_port_scans(packets))
        
        # SYN flood detection
        self.anomalies.extend(self._detect_syn_flood(packets))
        
        # Unusual packet sizes
        self.anomalies.extend(self._detect_unusual_packet_sizes(packets))
        
        # DNS tunneling detection
        self.anomalies.extend(self._detect_dns_tunneling(packets))
        
        # High retransmission rate
        self.anomalies.extend(self._detect_retransmissions(connections))
        
        # Suspicious ports
        self.anomalies.extend(self._detect_suspicious_ports(connections))
        
        # Unencrypted credentials
        self.anomalies.extend(self._detect_unencrypted_credentials(packets))
        
        logger.info(f"Detected {len(self.anomalies)} anomalies")
        return self.anomalies
    
    def _detect_port_scans(self, packets: List) -> List[Dict[str, Any]]:
        """Detect port scanning activity"""
        anomalies = []
        
        # Track connections per source IP
        src_connections = defaultdict(lambda: {'dst_ips': set(), 'dst_ports': set(), 'count': 0})
        
        for pkt in packets:
            if hasattr(pkt, 'IP') and hasattr(pkt, 'TCP'):
                src_ip = pkt['IP'].src
                dst_ip = pkt['IP'].dst
                dst_port = pkt['TCP'].dport
                
                src_connections[src_ip]['dst_ips'].add(dst_ip)
                src_connections[src_ip]['dst_ports'].add(dst_port)
                src_connections[src_ip]['count'] += 1
        
        # Identify potential port scans
        for src_ip, data in src_connections.items():
            # Many ports to same IP
            if len(data['dst_ports']) > self.thresholds['port_scan_threshold']:
                anomalies.append({
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f"Possible port scan detected: {src_ip} connected to {len(data['dst_ports'])} different ports",
                    'details': {
                        'unique_ports': len(data['dst_ports']),
                        'unique_ips': len(data['dst_ips']),
                        'total_attempts': data['count']
                    }
                })
        
        return anomalies
    
    def _detect_syn_flood(self, packets: List) -> List[Dict[str, Any]]:
        """Detect SYN flood attacks"""
        anomalies = []
        
        syn_count = defaultdict(int)
        syn_ack_count = defaultdict(int)
        
        for pkt in packets:
            if hasattr(pkt, 'IP') and hasattr(pkt, 'TCP'):
                dst_ip = pkt['IP'].dst
                flags = pkt['TCP'].flags
                
                if flags & 0x02:  # SYN flag
                    if not (flags & 0x10):  # Not ACK
                        syn_count[dst_ip] += 1
                    else:  # SYN-ACK
                        syn_ack_count[dst_ip] += 1
        
        # Check for imbalance
        for dst_ip, syn_cnt in syn_count.items():
            if syn_cnt > self.thresholds['syn_flood_threshold']:
                syn_ack_cnt = syn_ack_count.get(dst_ip, 0)
                if syn_ack_cnt < syn_cnt * 0.5:  # Less than 50% SYN-ACK responses
                    anomalies.append({
                        'type': 'SYN Flood',
                        'severity': 'CRITICAL',
                        'target_ip': dst_ip,
                        'description': f"Possible SYN flood attack against {dst_ip}",
                        'details': {
                            'syn_packets': syn_cnt,
                            'syn_ack_packets': syn_ack_cnt,
                            'ratio': syn_ack_cnt / syn_cnt if syn_cnt > 0 else 0
                        }
                    })
        
        return anomalies
    
    def _detect_unusual_packet_sizes(self, packets: List) -> List[Dict[str, Any]]:
        """Detect unusually large or small packets"""
        anomalies = []
        
        for i, pkt in enumerate(packets):
            pkt_len = len(pkt)
            
            # Very large packets
            if pkt_len > self.thresholds['unusual_packet_size']:
                anomalies.append({
                    'type': 'Unusual Packet Size',
                    'severity': 'MEDIUM',
                    'packet_number': i + 1,
                    'description': f"Unusually large packet detected ({pkt_len} bytes)",
                    'details': {
                        'size': pkt_len,
                        'src': pkt['IP'].src if hasattr(pkt, 'IP') else 'N/A',
                        'dst': pkt['IP'].dst if hasattr(pkt, 'IP') else 'N/A'
                    }
                })
        
        return anomalies
    
    def _detect_dns_tunneling(self, packets: List) -> List[Dict[str, Any]]:
        """Detect potential DNS tunneling"""
        anomalies = []
        
        for i, pkt in enumerate(packets):
            if hasattr(pkt, 'DNS') and hasattr(pkt['DNS'], 'qd'):
                dns = pkt['DNS']
                if dns.qd:
                    query = dns.qd
                    qname = query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname)
                    
                    # Check for suspiciously long queries
                    if len(qname) > self.thresholds['dns_tunnel_query_length']:
                        anomalies.append({
                            'type': 'DNS Tunneling',
                            'severity': 'HIGH',
                            'packet_number': i + 1,
                            'description': f"Possible DNS tunneling detected (query length: {len(qname)})",
                            'details': {
                                'query': qname,
                                'query_length': len(qname),
                                'src': pkt['IP'].src if hasattr(pkt, 'IP') else 'N/A'
                            }
                        })
        
        return anomalies
    
    def _detect_retransmissions(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect high retransmission rates"""
        anomalies = []
        
        for conn in connections:
            if conn['protocol'] == 'TCP' and conn.get('anomalies', 0) > 0:
                retrans_rate = conn['anomalies'] / conn['packets'] if conn['packets'] > 0 else 0
                
                if retrans_rate > self.thresholds['high_retransmission_rate']:
                    anomalies.append({
                        'type': 'High Retransmission Rate',
                        'severity': 'MEDIUM',
                        'connection': f"{conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}",
                        'description': f"High retransmission rate detected ({retrans_rate*100:.1f}%)",
                        'details': {
                            'retransmissions': conn['anomalies'],
                            'total_packets': conn['packets'],
                            'rate': retrans_rate
                        }
                    })
        
        return anomalies
    
    def _detect_suspicious_ports(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect connections to suspicious or uncommon ports"""
        anomalies = []
        
        # Common malware/suspicious ports
        suspicious_ports = {
            1337: 'WASTE/Backdoor',
            31337: 'Back Orifice',
            12345: 'NetBus',
            54321: 'Back Orifice 2000',
            6667: 'IRC (potential C&C)',
            6666: 'IRC variant',
            4444: 'Common backdoor port'
        }
        
        for conn in connections:
            dst_port = conn['dst_port']
            src_port = conn['src_port']
            
            if dst_port in suspicious_ports or src_port in suspicious_ports:
                port = dst_port if dst_port in suspicious_ports else src_port
                anomalies.append({
                    'type': 'Suspicious Port',
                    'severity': 'HIGH',
                    'connection': f"{conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}",
                    'description': f"Connection to suspicious port {port} ({suspicious_ports[port]})",
                    'details': {
                        'port': port,
                        'service': suspicious_ports[port],
                        'bytes_transferred': conn['bytes_total']
                    }
                })
        
        return anomalies
    
    def _detect_unencrypted_credentials(self, packets: List) -> List[Dict[str, Any]]:
        """Detect potential unencrypted credentials in traffic"""
        anomalies = []
        
        # Keywords that might indicate credentials
        keywords = [b'password=', b'passwd=', b'pwd=', b'username=', b'user=', b'login=']
        
        for i, pkt in enumerate(packets):
            if hasattr(pkt, 'Raw'):
                payload = bytes(pkt['Raw'])
                
                for keyword in keywords:
                    if keyword in payload.lower():
                        # Check if it's not HTTPS (port 443)
                        is_https = False
                        if hasattr(pkt, 'TCP'):
                            if pkt['TCP'].dport == 443 or pkt['TCP'].sport == 443:
                                is_https = True
                        
                        if not is_https:
                            anomalies.append({
                                'type': 'Unencrypted Credentials',
                                'severity': 'CRITICAL',
                                'packet_number': i + 1,
                                'description': 'Possible unencrypted credentials detected',
                                'details': {
                                    'keyword': keyword.decode(),
                                    'src': pkt['IP'].src if hasattr(pkt, 'IP') else 'N/A',
                                    'dst': pkt['IP'].dst if hasattr(pkt, 'IP') else 'N/A'
                                }
                            })
                            break
        
        return anomalies
    
    def get_anomalies(self) -> List[Dict[str, Any]]:
        """Get detected anomalies"""
        return self.anomalies
    
    def get_anomalies_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get anomalies filtered by severity"""
        return [a for a in self.anomalies if a['severity'] == severity]
    
    def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get summary of detected anomalies"""
        severity_counts = Counter(a['severity'] for a in self.anomalies)
        type_counts = Counter(a['type'] for a in self.anomalies)
        
        return {
            'total': len(self.anomalies),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts)
        }
