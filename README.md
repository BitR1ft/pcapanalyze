# PCAP/PCAPNG File Analyzer

A comprehensive network traffic analysis tool with a graphical user interface for analyzing PCAP and PCAPNG files.

## Features

### Core Features
- **File Parsing**: Support for both PCAP and PCAPNG file formats
- **Packet Dissection**: Layer-by-layer analysis (Link, Network, Transport, Application)
- **Connection Tracking**: TCP/UDP flow analysis with detailed statistics
- **File Extraction**: Extract embedded files from HTTP, FTP, SMTP traffic
- **Search & Filtering**: Filter packets by protocol, IP, port, or keywords
- **Statistics**: Protocol distribution, top talkers, bandwidth analysis
- **Export**: CSV, JSON, and filtered PCAP export

### Advanced Features
- **Visualization**: Traffic timelines, flow graphs, protocol distribution charts
- **Anomaly Detection**: Port scans, unusual patterns, suspicious activities
- **Protocol Decoders**: HTTP, DNS, TLS, FTP, SMTP, and more
- **Batch Processing**: Analyze multiple files simultaneously
- **Report Generation**: Automated PDF/HTML reports
- **Theme Support**: Dark and light mode
- **Performance**: Multi-threaded processing for large files
- **Plugin System**: Custom analysis scripts

## Requirements

- Python 3.8 or higher
- PyQt5
- Scapy
- Matplotlib
- Pandas
- dpkt (optional, for additional parsing)

## Installation

```bash
# Clone the repository
git clone https://github.com/BitR1ft/pcapanalyze.git
cd pcapanalyze

# Install dependencies
pip install -r requirements.txt
```

## Usage

### GUI Mode
```bash
python pcap_analyzer.py
```

### Command Line Mode
```bash
# Analyze a PCAP file
python pcap_analyzer.py -f capture.pcap

# Export statistics to CSV
python pcap_analyzer.py -f capture.pcap --export-stats stats.csv

# Extract files
python pcap_analyzer.py -f capture.pcap --extract-files output_dir/
```

## Project Structure

```
pcapanalyze/
├── pcap_analyzer.py          # Main application entry point
├── core/                      # Core analysis modules
│   ├── parser.py             # PCAP/PCAPNG file parser
│   ├── dissector.py          # Packet dissection
│   ├── connection_tracker.py # Flow analysis
│   ├── file_extractor.py     # File extraction
│   └── statistics.py         # Statistics generation
├── gui/                       # GUI modules
│   ├── main_window.py        # Main GUI window
│   ├── packet_view.py        # Packet list and details
│   ├── connection_view.py    # Connection viewer
│   ├── stats_view.py         # Statistics and charts
│   └── file_view.py          # Extracted files viewer
├── analysis/                  # Advanced analysis
│   ├── anomaly_detector.py   # Anomaly detection
│   ├── protocol_decoders.py  # Protocol-specific decoders
│   └── visualizer.py         # Traffic visualization
├── utils/                     # Utilities
│   ├── filters.py            # Filtering and search
│   ├── exporters.py          # Export functionality
│   └── logger.py             # Logging utilities
├── tests/                     # Test suite
├── samples/                   # Sample PCAP files
└── docs/                      # Documentation
```

## Screenshots

[Screenshots will be added here]

## Development

### Running Tests
```bash
pytest tests/
```

### Building Standalone Executable
```bash
pyinstaller --onefile --windowed pcap_analyzer.py
```

## License

MIT License

## Contributors

Final Year Computer Networks Project

## Acknowledgments

- Scapy for packet parsing
- PyQt5 for GUI framework
- Wireshark sample captures for testing
