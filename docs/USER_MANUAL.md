# User Manual

## PCAP/PCAPNG File Analyzer - User Guide

### Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [GUI Interface](#gui-interface)
5. [Command Line Usage](#command-line-usage)
6. [Features](#features)
7. [Troubleshooting](#troubleshooting)

### Introduction

The PCAP/PCAPNG File Analyzer is a comprehensive network traffic analysis tool designed for network engineers, security analysts, and students. It provides detailed insights into network packet captures, including:

- Packet-level analysis
- Connection tracking
- File extraction
- Anomaly detection
- Traffic visualization
- Statistical analysis

### Installation

#### Requirements
- Python 3.8 or higher
- pip package manager

#### Install Dependencies

```bash
pip install -r requirements.txt
```

#### Verify Installation

```bash
python pcap_analyzer.py --help
```

### Getting Started

#### Launch GUI Mode

```bash
python pcap_analyzer.py
```

Or simply:

```bash
python pcap_analyzer.py --gui
```

#### Analyze a File from Command Line

```bash
python pcap_analyzer.py -f capture.pcap
```

### GUI Interface

The GUI provides an intuitive, Wireshark-like interface with multiple tabs:

#### Packets Tab
- **Packet List**: Shows all packets with key information
- **Packet Details**: Layer-by-layer breakdown of selected packet
- **Hex View**: Raw hexadecimal view of packet data

#### Connections Tab
- Lists all TCP/UDP connections
- Shows connection state, duration, and traffic volume
- Identifies anomalies

#### Statistics Tab
- Protocol distribution
- Top talkers
- Traffic summaries
- Bandwidth usage

#### Anomalies Tab
- Port scan detection
- SYN flood detection
- Suspicious activities
- Unencrypted credentials

#### Extracted Files Tab
- Files extracted from HTTP, FTP, SMTP traffic
- File metadata and location

### Command Line Usage

#### Basic Analysis
```bash
python pcap_analyzer.py -f capture.pcap
```

#### Extract Files
```bash
python pcap_analyzer.py -f capture.pcap --extract-files --extract-dir output/
```

#### Detect Anomalies
```bash
python pcap_analyzer.py -f capture.pcap --detect-anomalies
```

#### Create Visualizations
```bash
python pcap_analyzer.py -f capture.pcap --visualize
```

#### Export Data
```bash
# Export statistics
python pcap_analyzer.py -f capture.pcap --export-stats stats.csv

# Export connections
python pcap_analyzer.py -f capture.pcap --export-connections connections.csv

# Export packet list
python pcap_analyzer.py -f capture.pcap --export-packets packets.csv
```

#### Generate Reports
```bash
# HTML report
python pcap_analyzer.py -f capture.pcap --report report.html

# Text report
python pcap_analyzer.py -f capture.pcap --report report.txt
```

### Features

#### Packet Analysis
- Layer-by-layer dissection
- Support for Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, and more
- Hex and ASCII payload view

#### Connection Tracking
- TCP connection state tracking (SYN, ACK, FIN, RST)
- UDP flow grouping
- Retransmission detection
- Connection duration and bandwidth

#### File Extraction
- HTTP file downloads
- FTP transfers
- SMTP attachments
- Automatic file type detection

#### Anomaly Detection
- Port scanning
- SYN flood attacks
- DNS tunneling
- Unusual packet sizes
- Suspicious ports
- Unencrypted credentials

#### Protocol Decoders
- HTTP (requests and responses)
- DNS (queries and answers)
- TLS (handshake analysis)
- FTP (commands and responses)
- SMTP (email traffic)

#### Visualization
- Protocol distribution pie charts
- Traffic timeline
- Top talkers bar charts
- Packet size distribution
- Connection graphs

#### Export and Reporting
- CSV export (packets, connections, statistics)
- HTML reports
- Text reports
- Filtered PCAP files

### Filtering

The GUI includes a filter bar for quick packet filtering:

- Filter by protocol: `TCP`, `UDP`, `HTTP`
- Filter by IP: `192.168.1.1`
- Filter by port: `port 80`
- Combined filters: `TCP 192.168.1.1`

### Troubleshooting

#### GUI Won't Launch
```bash
# Install PyQt5
pip install PyQt5
```

#### Cannot Load PCAP File
- Ensure file is valid PCAP or PCAPNG format
- Check file permissions
- Try with a smaller file first

#### Missing Dependencies
```bash
# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall
```

#### Performance Issues
- Use lazy loading for large files
- Filter packets to reduce dataset
- Close unnecessary tabs

### Keyboard Shortcuts

- `Ctrl+O`: Open PCAP file
- `Ctrl+Q`: Quit application
- `Ctrl+F`: Focus filter bar (when implemented)

### Tips

1. **Start Small**: Test with small PCAP files first
2. **Use Filters**: Filter packets to focus on relevant traffic
3. **Export Data**: Export to CSV for further analysis in Excel
4. **Save Reports**: Generate HTML reports for documentation
5. **Check Anomalies**: Always review the Anomalies tab for security insights

### Support

For issues, feature requests, or contributions, please visit the project repository.

---

**Version**: 1.0.0  
**Last Updated**: 2024
