# Developer Guide

## PCAP Analyzer - Developer Documentation

### Architecture Overview

The PCAP Analyzer follows a modular architecture with clear separation of concerns:

```
pcapanalyze/
├── core/              # Core analysis functionality
├── gui/               # PyQt5 GUI interface
├── analysis/          # Advanced analysis features
├── utils/             # Utility functions
└── tests/             # Unit tests
```

### Core Modules

#### parser.py
Handles PCAP/PCAPNG file parsing using Scapy.

**Key Classes:**
- `PCAPParser`: Main parser class

**Methods:**
- `load_file(filename)`: Load and parse PCAP file
- `get_packets()`: Retrieve all packets
- `get_packet_summary(index)`: Get packet summary
- `lazy_load(filename)`: Generator for large files

#### dissector.py
Provides layer-by-layer packet dissection.

**Key Classes:**
- `PacketDissector`: Static methods for packet analysis

**Methods:**
- `dissect_packet(packet)`: Full packet dissection
- `get_ip_info(packet)`: Extract IP layer
- `get_tcp_info(packet)`: Extract TCP layer
- `get_http_info(packet)`: Extract HTTP data

#### connection_tracker.py
Tracks TCP/UDP flows and connection states.

**Key Classes:**
- `ConnectionTracker`: Connection flow analysis

**Methods:**
- `analyze_connections(packets)`: Analyze all connections
- `get_top_connections(n)`: Get top N connections
- `get_connection_details()`: Detailed connection info

#### file_extractor.py
Extracts embedded files from network traffic.

**Key Classes:**
- `FileExtractor`: File extraction from protocols

**Methods:**
- `extract_files(packets)`: Extract all files
- `_extract_http_files()`: HTTP file extraction
- `_extract_ftp_files()`: FTP file extraction

#### statistics.py
Generates comprehensive statistics.

**Key Classes:**
- `StatisticsGenerator`: Statistical analysis

**Methods:**
- `generate_statistics(packets, connections)`: Full stats
- `_protocol_stats()`: Protocol distribution
- `_top_talkers()`: Top IP addresses

### Analysis Modules

#### anomaly_detector.py
Detects suspicious network activities.

**Key Features:**
- Port scan detection
- SYN flood detection
- DNS tunneling detection
- Credential leakage detection

#### protocol_decoders.py
Advanced protocol-specific decoders.

**Supported Protocols:**
- HTTP
- TLS/SSL
- FTP
- SMTP
- DHCP
- SIP

#### visualizer.py
Creates traffic visualizations using Matplotlib.

**Visualization Types:**
- Protocol distribution pie charts
- Traffic timelines
- Top talkers bar charts
- Packet size distributions
- Connection graphs

### Utility Modules

#### filters.py
Packet filtering and searching.

**Key Classes:**
- `PacketFilter`: Multi-criteria filtering
- `PacketSearcher`: Advanced search functions

#### exporters.py
Export functionality for various formats.

**Export Formats:**
- CSV
- JSON
- Filtered PCAP
- HTML reports
- Text reports

#### logger.py
Centralized logging system.

**Features:**
- File and console logging
- Log rotation
- Timestamped logs

### GUI Architecture

The GUI is built with PyQt5 and follows the MVC pattern:

**Main Components:**
- `PCAPAnalyzerGUI`: Main window class
- `AnalysisThread`: Background processing
- Tab-based interface:
  - Packets tab (three-pane layout)
  - Connections tab
  - Statistics tab
  - Anomalies tab
  - Extracted files tab

### Adding New Features

#### Adding a New Protocol Decoder

1. Add decoder method to `analysis/protocol_decoders.py`:

```python
@staticmethod
def decode_my_protocol(packet) -> Dict[str, Any]:
    """Decode MY_PROTOCOL"""
    if not hasattr(packet, 'Raw'):
        return {}
    
    # Parsing logic here
    protocol_data = {}
    
    return protocol_data
```

2. Use in dissection or display

#### Adding a New Anomaly Detection Rule

1. Add detection method to `analysis/anomaly_detector.py`:

```python
def _detect_my_anomaly(self, packets: List) -> List[Dict[str, Any]]:
    """Detect MY_ANOMALY"""
    anomalies = []
    
    # Detection logic here
    
    return anomalies
```

2. Call in `detect_anomalies()` method

#### Adding a New Visualization

1. Add visualization method to `analysis/visualizer.py`:

```python
def create_my_chart(self, data, filename=None) -> str:
    """Create MY_CHART"""
    try:
        # Matplotlib code here
        plt.figure(figsize=(12, 6))
        # ... plotting logic ...
        
        if filename is None:
            filename = os.path.join(self.output_dir, 'my_chart.png')
        plt.savefig(filename, dpi=150, bbox_inches='tight')
        plt.close()
        
        return filename
    except Exception as e:
        logger.error(f"Error creating chart: {e}")
        return None
```

### Testing

Run tests with pytest:

```bash
pytest tests/
```

Create new test file:

```python
# tests/test_myfeature.py
import pytest
from core.mymodule import MyClass

class TestMyFeature:
    def test_something(self):
        obj = MyClass()
        assert obj.method() == expected_value
```

### Performance Optimization

#### For Large Files

1. Use lazy loading:
```python
parser = PCAPParser()
for packet in parser.lazy_load('large.pcap'):
    # Process packet
    pass
```

2. Use filtering early:
```python
filter = PacketFilter()
filter.add_protocol_filter('TCP')
filtered = filter.apply(packets)
```

3. Enable multi-threading (future enhancement)

### Code Style

- Follow PEP 8
- Use type hints where possible
- Document all public methods
- Keep functions focused and small
- Use descriptive variable names

### Dependencies

Core dependencies:
- `scapy`: Packet parsing
- `PyQt5`: GUI framework
- `matplotlib`: Visualizations
- `pandas`: Data manipulation

Optional:
- `dpkt`: Alternative parser
- `plotly`: Interactive charts

### Building Standalone Executable

Use PyInstaller:

```bash
pyinstaller --onefile --windowed pcap_analyzer.py
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit pull request

### License

MIT License - see LICENSE file

---

**Maintainer**: Final Year Project Team  
**Version**: 1.0.0
