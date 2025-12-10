"""
PCAP/PCAPNG file parser
Handles reading and parsing of packet capture files
"""
from scapy.all import rdpcap, PcapReader, sniff, IP, TCP, UDP, Ether
from scapy.utils import PcapWriter
import os
from typing import List, Dict, Any
from utils.logger import logger

class PCAPParser:
    """Parser for PCAP and PCAPNG files"""
    
    def __init__(self, filename: str = None):
        self.filename = filename
        self.packets = []
        self.file_info = {}
        self.is_loaded = False
    
    def load_file(self, filename: str = None) -> bool:
        """Load a PCAP/PCAPNG file"""
        if filename:
            self.filename = filename
        
        if not self.filename or not os.path.exists(self.filename):
            logger.error(f"File not found: {self.filename}")
            return False
        
        try:
            logger.info(f"Loading file: {self.filename}")
            
            # Get file information
            self.file_info = {
                'filename': os.path.basename(self.filename),
                'filepath': self.filename,
                'size': os.path.getsize(self.filename),
                'format': self._detect_format()
            }
            
            # Read packets
            self.packets = rdpcap(self.filename)
            self.file_info['packet_count'] = len(self.packets)
            
            # Calculate capture duration
            if len(self.packets) > 0:
                first_time = float(self.packets[0].time)
                last_time = float(self.packets[-1].time)
                self.file_info['duration'] = last_time - first_time
                self.file_info['start_time'] = first_time
                self.file_info['end_time'] = last_time
            
            self.is_loaded = True
            logger.info(f"Successfully loaded {len(self.packets)} packets")
            return True
            
        except Exception as e:
            logger.error(f"Error loading file: {e}")
            return False
    
    def _detect_format(self) -> str:
        """Detect if file is PCAP or PCAPNG"""
        try:
            with open(self.filename, 'rb') as f:
                magic = f.read(4)
                # PCAP magic numbers
                if magic in [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1']:
                    return 'PCAP'
                # PCAPNG magic number
                elif magic == b'\x0a\x0d\x0d\x0a':
                    return 'PCAPNG'
                else:
                    return 'Unknown'
        except:
            return 'Unknown'
    
    def get_packets(self) -> List:
        """Get all loaded packets"""
        return self.packets
    
    def get_packet(self, index: int):
        """Get a specific packet by index"""
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def get_file_info(self) -> Dict[str, Any]:
        """Get file metadata"""
        return self.file_info
    
    def get_packet_summary(self, index: int) -> Dict[str, Any]:
        """Get a summary of a specific packet"""
        pkt = self.get_packet(index)
        if not pkt:
            return {}
        
        summary = {
            'number': index + 1,
            'time': float(pkt.time) if hasattr(pkt, 'time') else 0,
            'length': len(pkt),
            'summary': pkt.summary()
        }
        
        # Add protocol-specific information
        if pkt.haslayer(Ether):
            summary['src_mac'] = pkt[Ether].src
            summary['dst_mac'] = pkt[Ether].dst
        
        if pkt.haslayer(IP):
            summary['src_ip'] = pkt[IP].src
            summary['dst_ip'] = pkt[IP].dst
            summary['protocol'] = pkt[IP].proto
        
        if pkt.haslayer(TCP):
            summary['src_port'] = pkt[TCP].sport
            summary['dst_port'] = pkt[TCP].dport
            summary['transport'] = 'TCP'
        elif pkt.haslayer(UDP):
            summary['src_port'] = pkt[UDP].sport
            summary['dst_port'] = pkt[UDP].dport
            summary['transport'] = 'UDP'
        
        return summary
    
    def save_packets(self, packets: List, filename: str) -> bool:
        """Save packets to a new PCAP file"""
        try:
            from scapy.all import wrpcap
            wrpcap(filename, packets)
            logger.info(f"Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving packets: {e}")
            return False
    
    def lazy_load(self, filename: str = None):
        """Generator for lazy loading of large PCAP files"""
        if filename:
            self.filename = filename
        
        try:
            with PcapReader(self.filename) as pcap_reader:
                for pkt in pcap_reader:
                    yield pkt
        except Exception as e:
            logger.error(f"Error in lazy loading: {e}")
            return
