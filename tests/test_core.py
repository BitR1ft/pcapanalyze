"""
Unit tests for PCAP Analyzer
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parser import PCAPParser
from core.dissector import PacketDissector
from core.connection_tracker import ConnectionTracker
from core.statistics import StatisticsGenerator
from utils.filters import PacketFilter, PacketSearcher

class TestPCAPParser:
    """Test PCAP parser functionality"""
    
    def test_parser_init(self):
        """Test parser initialization"""
        parser = PCAPParser()
        assert parser.packets == []
        assert parser.is_loaded == False
    
    def test_format_detection(self):
        """Test file format detection"""
        parser = PCAPParser()
        # Would need actual PCAP file to test
        assert parser._detect_format is not None

class TestPacketDissector:
    """Test packet dissection"""
    
    def test_dissector_methods(self):
        """Test dissector has required methods"""
        assert hasattr(PacketDissector, 'dissect_packet')
        assert hasattr(PacketDissector, 'get_ip_info')
        assert hasattr(PacketDissector, 'get_tcp_info')
        assert hasattr(PacketDissector, 'get_udp_info')

class TestConnectionTracker:
    """Test connection tracking"""
    
    def test_tracker_init(self):
        """Test tracker initialization"""
        tracker = ConnectionTracker()
        assert tracker.tcp_connections == {}
        assert tracker.udp_flows == {}

class TestFilters:
    """Test filtering functionality"""
    
    def test_filter_init(self):
        """Test filter initialization"""
        pkt_filter = PacketFilter()
        assert pkt_filter.filters == []
    
    def test_filter_methods(self):
        """Test filter has required methods"""
        pkt_filter = PacketFilter()
        assert hasattr(pkt_filter, 'add_protocol_filter')
        assert hasattr(pkt_filter, 'add_ip_filter')
        assert hasattr(pkt_filter, 'add_port_filter')
        assert hasattr(pkt_filter, 'apply')
        assert hasattr(pkt_filter, 'clear')

class TestStatistics:
    """Test statistics generation"""
    
    def test_stats_init(self):
        """Test statistics generator initialization"""
        stats_gen = StatisticsGenerator()
        assert stats_gen.stats == {}

if __name__ == '__main__':
    pytest.main([__file__])
