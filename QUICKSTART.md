# Quick Start Guide

## PCAP Analyzer - Get Started in 5 Minutes

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Generate Sample Traffic (Optional)

```bash
python tests/generate_sample_pcap.py
```

This creates a sample PCAP file at `samples/sample_traffic.pcap` with various traffic types for testing.

### Step 3: Launch the Application

#### Option A: GUI Mode (Recommended)
```bash
python pcap_analyzer.py
```

Then click "Open PCAP File" and select `samples/sample_traffic.pcap` or any PCAP file.

#### Option B: Command Line Mode
```bash
python pcap_analyzer.py -f samples/sample_traffic.pcap
```

### What You'll See

The GUI has 5 tabs:

1. **Packets**: View all packets with detailed information
   - Packet list (top pane)
   - Packet details (middle pane)
   - Hex dump (bottom pane)

2. **Connections**: See all TCP/UDP flows
   - Connection states
   - Bytes transferred
   - Duration

3. **Statistics**: Traffic analysis
   - Protocol distribution
   - Top talkers
   - Bandwidth usage

4. **Anomalies**: Security insights
   - Port scans
   - Suspicious activities
   - Potential threats

5. **Extracted Files**: Files from traffic
   - HTTP downloads
   - FTP transfers
   - Email attachments

### Quick Tips

**Filtering**
- Type in the filter box: `TCP`, `192.168.1.1`, `port 80`
- Click "Apply Filter"

**Exporting**
- Menu → File → Export → Choose format
- Exports to CSV, JSON, or filtered PCAP

**Visualizations**
- Menu → Analysis → Create Visualizations
- Generates charts in `visualizations/` folder

**Reports**
- Menu → Analysis → Generate Report
- Creates HTML or text report

### Advanced Usage

**Extract Files from Traffic**
```bash
python pcap_analyzer.py -f capture.pcap --extract-files
```

**Detect Anomalies**
```bash
python pcap_analyzer.py -f capture.pcap --detect-anomalies
```

**Create Comprehensive Report**
```bash
python pcap_analyzer.py -f capture.pcap --detect-anomalies --visualize --report report.html
```

**Export Everything**
```bash
python pcap_analyzer.py -f capture.pcap \
  --export-stats stats.csv \
  --export-connections connections.csv \
  --export-packets packets.csv \
  --report analysis.html
```

### Common Issues

**GUI won't start?**
```bash
pip install PyQt5
```

**Can't load PCAP file?**
- Make sure it's a valid PCAP/PCAPNG file
- Try with the sample file first
- Check file permissions

**Performance slow?**
- Use filtering to reduce data
- Try command-line mode for large files
- Filter before analysis

### Getting Help

- Check `docs/USER_MANUAL.md` for detailed documentation
- See `docs/DEVELOPER_GUIDE.md` for development info
- Run `python pcap_analyzer.py --help` for CLI options

### Sample Commands

```bash
# Quick analysis with summary
python pcap_analyzer.py -f capture.pcap

# Full analysis with all features
python pcap_analyzer.py -f capture.pcap \
  --extract-files \
  --detect-anomalies \
  --visualize \
  --report full_report.html

# Just extract files
python pcap_analyzer.py -f capture.pcap \
  --extract-files \
  --extract-dir my_extracted_files/

# Export for spreadsheet analysis
python pcap_analyzer.py -f capture.pcap \
  --export-stats stats.csv \
  --export-connections connections.csv
```

### Next Steps

1. Try the sample file: `samples/sample_traffic.pcap`
2. Load your own PCAP files
3. Explore the different tabs
4. Try filtering and exporting
5. Generate reports and visualizations

---

**Ready to analyze network traffic!** 🚀
