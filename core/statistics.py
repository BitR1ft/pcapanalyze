"""
Statistics generation module
Provides comprehensive statistics and summaries of network traffic
"""
from typing import List, Dict, Any
from collections import defaultdict, Counter
from utils.logger import logger

class StatisticsGenerator:
    """Generate statistics from packet analysis"""
    
    def __init__(self):
        self.stats = {}
    
    def generate_statistics(self, packets: List, connections: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        logger.info("Generating statistics...")
        
        self.stats = {
            'general': self._general_stats(packets),
            'protocols': self._protocol_stats(packets),
            'top_talkers': self._top_talkers(connections),
            'top_services': self._top_services(connections),
            'bandwidth': self._bandwidth_stats(connections),
            'packet_sizes': self._packet_size_stats(packets),
            'time_distribution': self._time_distribution(packets)
        }
        
        logger.info("Statistics generated successfully")
        return self.stats
    
    def _general_stats(self, packets: List) -> Dict[str, Any]:
        """Generate general statistics"""
        if not packets:
            return {}
        
        total_bytes = sum(len(pkt) for pkt in packets)
        
        # Calculate duration
        if len(packets) > 1:
            start_time = float(packets[0].time) if hasattr(packets[0], 'time') else 0
            end_time = float(packets[-1].time) if hasattr(packets[-1], 'time') else 0
            duration = end_time - start_time
        else:
            duration = 0
        
        return {
            'total_packets': len(packets),
            'total_bytes': total_bytes,
            'duration_seconds': duration,
            'average_packet_size': total_bytes / len(packets) if packets else 0,
            'packets_per_second': len(packets) / duration if duration > 0 else 0,
            'bytes_per_second': total_bytes / duration if duration > 0 else 0
        }
    
    def _protocol_stats(self, packets: List) -> Dict[str, Any]:
        """Generate protocol distribution statistics"""
        protocol_counts = Counter()
        protocol_bytes = defaultdict(int)
        
        for pkt in packets:
            pkt_len = len(pkt)
            
            # Layer 2
            if hasattr(pkt, 'Ether'):
                protocol_counts['Ethernet'] += 1
                protocol_bytes['Ethernet'] += pkt_len
            
            # Layer 3
            if hasattr(pkt, 'IP'):
                protocol_counts['IP'] += 1
                protocol_bytes['IP'] += pkt_len
                
                # Get IP protocol
                if hasattr(pkt, 'TCP'):
                    protocol_counts['TCP'] += 1
                    protocol_bytes['TCP'] += pkt_len
                elif hasattr(pkt, 'UDP'):
                    protocol_counts['UDP'] += 1
                    protocol_bytes['UDP'] += pkt_len
                elif hasattr(pkt, 'ICMP'):
                    protocol_counts['ICMP'] += 1
                    protocol_bytes['ICMP'] += pkt_len
            
            elif hasattr(pkt, 'IPv6'):
                protocol_counts['IPv6'] += 1
                protocol_bytes['IPv6'] += pkt_len
            
            elif hasattr(pkt, 'ARP'):
                protocol_counts['ARP'] += 1
                protocol_bytes['ARP'] += pkt_len
            
            # Application layer
            if hasattr(pkt, 'DNS'):
                protocol_counts['DNS'] += 1
                protocol_bytes['DNS'] += pkt_len
            
            if hasattr(pkt, 'HTTP'):
                protocol_counts['HTTP'] += 1
                protocol_bytes['HTTP'] += pkt_len
            elif hasattr(pkt, 'Raw'):
                # Heuristic detection for HTTP
                payload = bytes(pkt['Raw']).decode('utf-8', errors='ignore')
                if payload.startswith('HTTP/') or any(m in payload[:50] for m in ['GET ', 'POST ']):
                    protocol_counts['HTTP'] += 1
                    protocol_bytes['HTTP'] += pkt_len
        
        # Calculate percentages
        total_packets = len(packets)
        total_bytes = sum(len(pkt) for pkt in packets)
        
        protocol_distribution = {}
        for proto in protocol_counts:
            protocol_distribution[proto] = {
                'packets': protocol_counts[proto],
                'bytes': protocol_bytes[proto],
                'packet_percentage': (protocol_counts[proto] / total_packets * 100) if total_packets > 0 else 0,
                'byte_percentage': (protocol_bytes[proto] / total_bytes * 100) if total_bytes > 0 else 0
            }
        
        return protocol_distribution
    
    def _top_talkers(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Identify top IP addresses by traffic volume"""
        ip_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0, 'connections': 0})
        
        for conn in connections:
            src_ip = conn['src_ip']
            dst_ip = conn['dst_ip']
            
            ip_stats[src_ip]['bytes_sent'] += conn['bytes_sent']
            ip_stats[src_ip]['bytes_recv'] += conn['bytes_recv']
            ip_stats[src_ip]['connections'] += 1
            
            ip_stats[dst_ip]['bytes_sent'] += conn['bytes_recv']
            ip_stats[dst_ip]['bytes_recv'] += conn['bytes_sent']
            ip_stats[dst_ip]['connections'] += 1
        
        # Convert to list and sort
        top_talkers = []
        for ip, stats in ip_stats.items():
            top_talkers.append({
                'ip': ip,
                'total_bytes': stats['bytes_sent'] + stats['bytes_recv'],
                'bytes_sent': stats['bytes_sent'],
                'bytes_recv': stats['bytes_recv'],
                'connections': stats['connections']
            })
        
        top_talkers.sort(key=lambda x: x['total_bytes'], reverse=True)
        return top_talkers[:20]  # Top 20
    
    def _top_services(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Identify most used services/ports"""
        port_stats = defaultdict(lambda: {'connections': 0, 'bytes': 0})
        
        for conn in connections:
            src_port = conn['src_port']
            dst_port = conn['dst_port']
            total_bytes = conn['bytes_total']
            
            # Typically server ports are < 1024 or well-known
            server_port = dst_port if dst_port < 1024 or dst_port in [3306, 5432, 6379, 8080, 8443] else src_port
            
            port_stats[server_port]['connections'] += 1
            port_stats[server_port]['bytes'] += total_bytes
        
        # Convert to list and add port names
        top_services = []
        for port, stats in port_stats.items():
            top_services.append({
                'port': port,
                'service': self._get_service_name(port),
                'connections': stats['connections'],
                'bytes': stats['bytes']
            })
        
        top_services.sort(key=lambda x: x['bytes'], reverse=True)
        return top_services[:20]  # Top 20
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return services.get(port, f'Port-{port}')
    
    def _bandwidth_stats(self, connections: List[Dict]) -> Dict[str, Any]:
        """Calculate bandwidth statistics"""
        if not connections:
            return {}
        
        total_bytes = sum(conn['bytes_total'] for conn in connections)
        total_duration = sum(conn['duration'] for conn in connections)
        
        tcp_bytes = sum(conn['bytes_total'] for conn in connections if conn['protocol'] == 'TCP')
        udp_bytes = sum(conn['bytes_total'] for conn in connections if conn['protocol'] == 'UDP')
        
        return {
            'total_bytes': total_bytes,
            'tcp_bytes': tcp_bytes,
            'udp_bytes': udp_bytes,
            'tcp_percentage': (tcp_bytes / total_bytes * 100) if total_bytes > 0 else 0,
            'udp_percentage': (udp_bytes / total_bytes * 100) if total_bytes > 0 else 0,
            'average_bandwidth': total_bytes / total_duration if total_duration > 0 else 0
        }
    
    def _packet_size_stats(self, packets: List) -> Dict[str, Any]:
        """Analyze packet size distribution"""
        if not packets:
            return {}
        
        sizes = [len(pkt) for pkt in packets]
        sizes.sort()
        
        # Calculate distribution
        size_ranges = {
            '0-64': 0,
            '65-128': 0,
            '129-256': 0,
            '257-512': 0,
            '513-1024': 0,
            '1025-1518': 0,
            '>1518': 0
        }
        
        for size in sizes:
            if size <= 64:
                size_ranges['0-64'] += 1
            elif size <= 128:
                size_ranges['65-128'] += 1
            elif size <= 256:
                size_ranges['129-256'] += 1
            elif size <= 512:
                size_ranges['257-512'] += 1
            elif size <= 1024:
                size_ranges['513-1024'] += 1
            elif size <= 1518:
                size_ranges['1025-1518'] += 1
            else:
                size_ranges['>1518'] += 1
        
        n = len(sizes)
        return {
            'min': min(sizes),
            'max': max(sizes),
            'average': sum(sizes) / n,
            'median': sizes[n // 2],
            'distribution': size_ranges
        }
    
    def _time_distribution(self, packets: List) -> Dict[str, Any]:
        """Analyze packet distribution over time"""
        if not packets or len(packets) < 2:
            return {}
        
        start_time = float(packets[0].time) if hasattr(packets[0], 'time') else 0
        end_time = float(packets[-1].time) if hasattr(packets[-1], 'time') else 0
        duration = end_time - start_time
        
        if duration <= 0:
            return {}
        
        # Divide into time buckets (e.g., 10 buckets)
        num_buckets = min(10, int(duration) + 1)
        bucket_size = duration / num_buckets
        buckets = [0] * num_buckets
        
        for pkt in packets:
            if hasattr(pkt, 'time'):
                pkt_time = float(pkt.time) - start_time
                bucket_idx = int(pkt_time / bucket_size)
                if bucket_idx >= num_buckets:
                    bucket_idx = num_buckets - 1
                buckets[bucket_idx] += 1
        
        return {
            'buckets': buckets,
            'bucket_size_seconds': bucket_size,
            'num_buckets': num_buckets
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generated statistics"""
        return self.stats
