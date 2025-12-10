# CTF Challenge Solving Guide

This guide demonstrates how to use PCAP Analyzer for solving Capture The Flag (CTF) challenges involving network traffic analysis.

## Overview

PCAP Analyzer now includes specialized features designed specifically for CTF challenges:

- **Text & Payloads Tab**: Extract and search all text content from packets
- **CTF Utilities Tab**: Find flags, extract credentials, URLs, and emails
- **Decoder/Encoder Tab**: Decode Base64, Hex, URL encoding, ROT13, and XOR

## Quick Start for CTF Challenges

### 1. Load Your PCAP File

```bash
# Command line
python pcap_analyzer.py -f capture.pcap

# Or launch GUI
python pcap_analyzer.py
# Then: File > Open PCAP File
```

### 2. Automatic Flag Detection

Navigate to the **CTF Utilities** tab and click **Find Flags**.

The tool automatically searches for common flag patterns:
- `flag{...}`
- `FLAG{...}`
- `CTF{...}`
- MD5 hashes (32 hex characters)
- SHA1 hashes (40 hex characters)
- Base64-encoded data (20+ characters)

### 3. Extract Credentials

Click **Show Credentials** to find:
- HTTP Basic Authentication (automatically decoded)
- Passwords in GET/POST requests
- API keys and tokens
- Username fields

### 4. Search for Specific Text

Go to the **Text & Payloads** tab:

1. Enter your search term in the search box
2. Click **Search Text** for plain text search
3. Click **Search Regex** for pattern matching

Example regex patterns:
- `\b[A-Z0-9]{32}\b` - Find 32-character uppercase strings (MD5)
- `https?://.*` - Find all URLs
- `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` - Find IP addresses

### 5. Decode Hidden Data

Use the **Decoder/Encoder** tab:

1. Copy suspicious text from packets
2. Paste into the input field
3. Try different decoding methods:
   - **Smart Decode**: Tries all methods automatically
   - **Decode Base64**: For Base64-encoded data
   - **Decode Hex**: For hexadecimal data
   - **ROT13**: For simple rotation cipher
   - **Try All XOR Keys**: For single-byte XOR encryption

## Common CTF Scenarios

### Scenario 1: Flag in HTTP Traffic

**Problem**: Flag hidden in HTTP request or response

**Solution**:
1. Go to **Connections** tab to see HTTP connections
2. Go to **Text & Payloads** tab
3. Search for "flag" or use regex: `flag\{[^}]+\}`
4. Check HTTP headers and body content

### Scenario 2: Base64-Encoded Flag

**Problem**: Flag is Base64-encoded

**Solution**:
1. Go to **CTF Utilities** > **Find Flags**
2. Or go to **Text & Payloads** and search for Base64 patterns
3. Copy suspicious Base64 string
4. Go to **Decoder/Encoder** tab
5. Click **Decode Base64**

### Scenario 3: Flag in DNS Queries

**Problem**: Flag exfiltrated via DNS queries

**Solution**:
1. Go to **Statistics** tab and look for DNS statistics
2. Go to **Text & Payloads** tab
3. Search for DNS-related text
4. Look for unusual domain names containing the flag

### Scenario 4: XOR-Encrypted Data

**Problem**: Data encrypted with single-byte XOR

**Solution**:
1. Extract hex data from packets (Text & Payloads tab)
2. Go to **Decoder/Encoder** tab
3. Paste hex data
4. Click **Try All XOR Keys**
5. Review results sorted by printable character ratio

### Scenario 5: Hidden in Image or File

**Problem**: Flag embedded in transferred file

**Solution**:
1. Go to **Extracted Files** tab
2. Check all extracted files
3. Files are automatically saved to `extracted_files/` directory
4. Examine files with hex editor or appropriate viewer

### Scenario 6: Credential Stealing

**Problem**: Find stolen credentials in traffic

**Solution**:
1. Go to **CTF Utilities** tab
2. Click **Show Credentials**
3. Review all found credentials with automatic Base64 decoding

## Advanced Features

### Network Stream Reconstruction

For reassembling TCP conversations:

```python
from utils.ctf_utils import CTFUtils

# Reconstruct TCP stream between two endpoints
stream = CTFUtils.reconstruct_tcp_stream(
    packets, 
    src_ip='192.168.1.100', 
    src_port=12345,
    dst_ip='10.0.0.1', 
    dst_port=80
)
```

### Custom Regex Search

Search for custom patterns in **Text & Payloads** tab:

```
# Find email addresses
\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b

# Find IPv4 addresses
\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b

# Find MD5 hashes
\b[a-f0-9]{32}\b

# Find SHA256 hashes
\b[a-f0-9]{64}\b

# Find custom flag format
mycorp\{[a-zA-Z0-9_]+\}
```

### Multi-Stage Decoding

Sometimes data is encoded multiple times:

1. Extract encoded data from packets
2. Use **Smart Decode** first
3. If result looks like another encoding, decode again
4. Example: Base64 → URL decode → Hex decode

### Entropy Analysis

High entropy often indicates encryption or compression:

```python
from utils.ctf_utils import CTFUtils

entropy = CTFUtils.analyze_entropy(data)
# Entropy close to 8.0 = likely encrypted/compressed
# Entropy around 4-5 = normal text
```

## Tips and Tricks

### 1. Look for Anomalies

- Unusual port numbers
- Large payloads in unexpected protocols
- High packet counts to single destination
- Non-standard protocols

### 2. Check All Tabs

Don't focus on just one tab:
- **Packets**: Raw packet data and details
- **Connections**: Flow analysis and conversation tracking
- **Statistics**: Protocol distribution and top talkers
- **Anomalies**: Suspicious patterns
- **Extracted Files**: Transferred files
- **Text & Payloads**: All readable content
- **CTF Utilities**: Automated flag/credential hunting
- **Decoder/Encoder**: Decoding tools

### 3. Use Filters

In the Packets tab, use filters to focus:
- `TCP` - Show only TCP packets
- `192.168.1.100` - Show packets involving this IP
- `port 80` - Show HTTP traffic
- Combine: `TCP and port 80`

### 4. Export Data

Export useful data for external analysis:
- **File > Export > Export Packets to CSV**
- **File > Export > Export Connections to CSV**
- **Analysis > Generate Report** (HTML format)

### 5. String Extraction

Click **Show All Strings** in CTF Utilities to see all printable strings extracted from packets. This is similar to running `strings` command on a binary.

## Example CTF Challenge Walkthrough

### Challenge: "Network Heist"

**Given**: PCAP file with suspicious network traffic

**Steps**:

1. **Initial Analysis**
   ```bash
   python pcap_analyzer.py -f challenge.pcap
   ```

2. **Check Connections Tab**
   - Found unusual connection to port 8888
   - Large data transfer (50KB)

3. **Search for Flags**
   - CTF Utilities > Find Flags
   - Found: `flag{n3tw0rk_f0r3ns1cs_101}`

4. **Additional Investigation**
   - Text & Payloads: Searched for "password"
   - Found Basic Auth credentials
   - Decoder tab: Decoded Base64 → `admin:secretpass123`

5. **File Extraction**
   - Extracted Files tab: Found `data.zip`
   - Contains additional clues

## Troubleshooting

### No Connections Showing

**Problem**: Connections tab is empty

**Possible Solutions**:
- Check if PCAP contains IP packets (not just Ethernet frames)
- Verify PCAP file format is valid
- Try regenerating PCAP with correct link-layer type

### No Text Extracted

**Problem**: Text & Payloads tab shows no content

**Possible Solutions**:
- Traffic might be encrypted (HTTPS, SSH, VPN)
- Packets might not contain payload data
- Look in Statistics tab for protocol distribution

### Decoding Fails

**Problem**: Decoder returns "Failed to decode"

**Possible Solutions**:
- Verify input format (hex needs valid hex characters)
- Try different encoding methods
- Use Smart Decode to try all methods
- Check for whitespace or formatting issues

## Keyboard Shortcuts

- `Ctrl+O` - Open PCAP file
- `Ctrl+Q` - Quit application
- `Ctrl+F` - Focus on filter/search box

## Additional Resources

- **User Manual**: Comprehensive feature documentation
- **Developer Guide**: For extending functionality
- **Project Overview**: Architecture and design details

## Support

For issues or questions:
- Check documentation in `docs/` directory
- Review examples in `samples/` directory
- See QUICKSTART.md for basic usage

---

**Happy CTF Solving! 🚩**
