"""
Traffic visualization module
Creates charts and graphs for network traffic analysis
"""
import matplotlib.pyplot as plt
from typing import List, Dict, Any
import os
from datetime import datetime
from utils.logger import logger

class TrafficVisualizer:
    """Create visualizations for network traffic"""
    
    def __init__(self, output_dir: str = "visualizations"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def create_protocol_distribution_pie(self, stats: Dict[str, Any], filename: str = None) -> str:
        """Create pie chart of protocol distribution"""
        try:
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend locally
            if 'protocols' not in stats or not stats['protocols']:
                return None
            
            protocols = stats['protocols']
            
            # Prepare data
            labels = []
            sizes = []
            for proto, data in protocols.items():
                if isinstance(data, dict) and 'packet_percentage' in data:
                    if data['packet_percentage'] > 0.5:  # Only show protocols > 0.5%
                        labels.append(proto)
                        sizes.append(data['packet_percentage'])
            
            if not labels:
                return None
            
            # Create pie chart
            plt.figure(figsize=(10, 8))
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            plt.title('Protocol Distribution by Packet Count')
            plt.axis('equal')
            
            # Save
            if filename is None:
                filename = os.path.join(self.output_dir, 'protocol_distribution.png')
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Created protocol distribution chart: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error creating protocol distribution chart: {e}")
            return None
    
    def create_traffic_timeline(self, packets: List, filename: str = None) -> str:
        """Create timeline chart of traffic over time"""
        try:
            if not packets or len(packets) < 2:
                return None
            
            # Get timestamps and packet sizes
            times = []
            sizes = []
            
            start_time = float(packets[0].time) if hasattr(packets[0], 'time') else 0
            
            for pkt in packets:
                if hasattr(pkt, 'time'):
                    times.append(float(pkt.time) - start_time)
                    sizes.append(len(pkt))
            
            if not times:
                return None
            
            # Create timeline
            plt.figure(figsize=(12, 6))
            plt.plot(times, sizes, linewidth=0.5, alpha=0.7)
            plt.xlabel('Time (seconds)')
            plt.ylabel('Packet Size (bytes)')
            plt.title('Traffic Timeline')
            plt.grid(True, alpha=0.3)
            
            # Save
            if filename is None:
                filename = os.path.join(self.output_dir, 'traffic_timeline.png')
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Created traffic timeline: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error creating traffic timeline: {e}")
            return None
    
    def create_top_talkers_bar(self, stats: Dict[str, Any], filename: str = None, top_n: int = 10) -> str:
        """Create bar chart of top talkers"""
        try:
            if 'top_talkers' not in stats or not stats['top_talkers']:
                return None
            
            top_talkers = stats['top_talkers'][:top_n]
            
            # Prepare data
            ips = [t['ip'] for t in top_talkers]
            bytes_data = [t['total_bytes'] / (1024 * 1024) for t in top_talkers]  # Convert to MB
            
            # Create bar chart
            plt.figure(figsize=(12, 6))
            plt.barh(range(len(ips)), bytes_data)
            plt.yticks(range(len(ips)), ips)
            plt.xlabel('Traffic (MB)')
            plt.title(f'Top {len(ips)} Talkers by Traffic Volume')
            plt.grid(True, alpha=0.3, axis='x')
            
            # Save
            if filename is None:
                filename = os.path.join(self.output_dir, 'top_talkers.png')
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Created top talkers chart: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error creating top talkers chart: {e}")
            return None
    
    def create_packet_size_distribution(self, stats: Dict[str, Any], filename: str = None) -> str:
        """Create histogram of packet size distribution"""
        try:
            if 'packet_sizes' not in stats or 'distribution' not in stats['packet_sizes']:
                return None
            
            distribution = stats['packet_sizes']['distribution']
            
            # Prepare data
            labels = list(distribution.keys())
            values = list(distribution.values())
            
            # Create bar chart
            plt.figure(figsize=(12, 6))
            plt.bar(range(len(labels)), values)
            plt.xticks(range(len(labels)), labels, rotation=45)
            plt.xlabel('Packet Size Range (bytes)')
            plt.ylabel('Number of Packets')
            plt.title('Packet Size Distribution')
            plt.grid(True, alpha=0.3, axis='y')
            
            # Save
            if filename is None:
                filename = os.path.join(self.output_dir, 'packet_size_distribution.png')
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Created packet size distribution chart: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error creating packet size distribution: {e}")
            return None
    
    def create_connection_graph(self, connections: List[Dict], filename: str = None, max_connections: int = 50) -> str:
        """Create network graph showing connections"""
        try:
            import matplotlib.patches as mpatches
            
            if not connections:
                return None
            
            # Use top connections by traffic
            top_connections = sorted(connections, key=lambda x: x['bytes_total'], reverse=True)[:max_connections]
            
            # Get unique IPs
            all_ips = set()
            for conn in top_connections:
                all_ips.add(conn['src_ip'])
                all_ips.add(conn['dst_ip'])
            
            # Create simple visualization
            plt.figure(figsize=(14, 10))
            ax = plt.gca()
            
            # Plot connections as lines
            for i, conn in enumerate(top_connections):
                # This is a simplified representation
                # A proper network graph would use networkx library
                color = 'blue' if conn['protocol'] == 'TCP' else 'green'
                alpha = min(0.8, conn['bytes_total'] / max(c['bytes_total'] for c in top_connections))
                
            plt.title(f'Network Connections (Top {len(top_connections)})')
            
            # Add legend
            tcp_patch = mpatches.Patch(color='blue', label='TCP')
            udp_patch = mpatches.Patch(color='green', label='UDP')
            plt.legend(handles=[tcp_patch, udp_patch])
            
            plt.text(0.5, 0.5, f'{len(top_connections)} connections\n{len(all_ips)} unique IPs',
                    ha='center', va='center', fontsize=14, transform=ax.transAxes)
            plt.axis('off')
            
            # Save
            if filename is None:
                filename = os.path.join(self.output_dir, 'connection_graph.png')
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Created connection graph: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error creating connection graph: {e}")
            return None
    
    def create_time_series_packets(self, stats: Dict[str, Any], filename: str = None) -> str:
        """Create time series chart of packet distribution"""
        try:
            if 'time_distribution' not in stats or 'buckets' not in stats['time_distribution']:
                return None
            
            time_dist = stats['time_distribution']
            buckets = time_dist['buckets']
            bucket_size = time_dist['bucket_size_seconds']
            
            # Create time labels
            time_labels = [f"{i*bucket_size:.1f}" for i in range(len(buckets))]
            
            # Create line chart
            plt.figure(figsize=(12, 6))
            plt.plot(time_labels, buckets, marker='o', linewidth=2)
            plt.xlabel('Time (seconds)')
            plt.ylabel('Number of Packets')
            plt.title('Packet Distribution Over Time')
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            
            # Save
            if filename is None:
                filename = os.path.join(self.output_dir, 'time_series.png')
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Created time series chart: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error creating time series chart: {e}")
            return None
    
    def create_all_visualizations(self, packets: List, connections: List[Dict], stats: Dict[str, Any]) -> Dict[str, str]:
        """Create all visualizations and return their filenames"""
        logger.info("Creating all visualizations...")
        
        visualizations = {}
        
        # Protocol distribution
        protocol_chart = self.create_protocol_distribution_pie(stats)
        if protocol_chart:
            visualizations['protocol_distribution'] = protocol_chart
        
        # Traffic timeline
        timeline_chart = self.create_traffic_timeline(packets)
        if timeline_chart:
            visualizations['traffic_timeline'] = timeline_chart
        
        # Top talkers
        talkers_chart = self.create_top_talkers_bar(stats)
        if talkers_chart:
            visualizations['top_talkers'] = talkers_chart
        
        # Packet size distribution
        size_chart = self.create_packet_size_distribution(stats)
        if size_chart:
            visualizations['packet_sizes'] = size_chart
        
        # Connection graph
        conn_chart = self.create_connection_graph(connections)
        if conn_chart:
            visualizations['connections'] = conn_chart
        
        # Time series
        time_chart = self.create_time_series_packets(stats)
        if time_chart:
            visualizations['time_series'] = time_chart
        
        logger.info(f"Created {len(visualizations)} visualizations")
        return visualizations
