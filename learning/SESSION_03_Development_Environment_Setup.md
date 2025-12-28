# Session 3: Setting Up the Development Environment

## Getting Your Workspace Ready 🛠️

Welcome to Session 3! Now that you understand network protocols, it's time to **set up your development environment** and get hands-on with packet analysis tools.

### What You'll Learn in This Session

1. Installing Python and required libraries
2. Understanding virtual environments
3. Setting up Scapy for packet manipulation
4. Installing and testing all dependencies
5. Creating your first test PCAP file
6. Verifying your setup with basic scripts

---

## 1. System Requirements

### Operating System Support

This project works on:
- ✅ **Linux** (Ubuntu, Debian, Fedora, etc.) - Recommended
- ✅ **macOS** (10.14+)
- ✅ **Windows** (10/11)

### Hardware Requirements

- **CPU**: Any modern processor (2+ cores recommended)
- **RAM**: 4 GB minimum (8 GB recommended for large PCAP files)
- **Storage**: 500 MB for dependencies, 2+ GB for working space
- **Network**: Internet connection for downloading packages

---

## 2. Installing Python

### Step 1: Check if Python is Already Installed

Open your terminal/command prompt and run:

```bash
python --version
# or
python3 --version
```

**Expected output**: `Python 3.8.x` or higher

If you see Python 3.8 or newer, **skip to Step 3**. Otherwise, continue to Step 2.

### Step 2: Install Python

#### On Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Python 3.8 or higher
sudo apt install python3 python3-pip python3-venv

# Verify installation
python3 --version
pip3 --version
```

#### On macOS

**Option 1: Using Homebrew (Recommended)**

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.9

# Verify
python3 --version
```

**Option 2: Download from python.org**

1. Visit https://www.python.org/downloads/
2. Download macOS installer for Python 3.8+
3. Run the installer
4. Verify in terminal

#### On Windows

1. Visit https://www.python.org/downloads/
2. Download **Windows installer** for Python 3.8+
3. **Important**: Check "Add Python to PATH" during installation!
4. Complete installation
5. Open Command Prompt and verify:

```cmd
python --version
pip --version
```

### Step 3: Understanding pip (Package Manager)

**pip** is Python's package installer. Think of it like an app store for Python libraries.

Test pip:

```bash
# Linux/macOS
pip3 --version

# Windows
pip --version
```

---

## 3. Setting Up a Virtual Environment

### What is a Virtual Environment?

A **virtual environment** is an isolated Python workspace. It's like having a separate "room" for each project with its own dependencies.

**Why use it?**
- ✅ Avoid conflicts between different projects
- ✅ Keep dependencies organized
- ✅ Easy to reproduce environment
- ✅ Don't pollute global Python installation

### Creating Your Virtual Environment

#### Step 1: Navigate to Project Directory

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/BitR1ft/pcapanalyze.git
cd pcapanalyze

# Or create a new directory
mkdir pcap-analyzer-project
cd pcap-analyzer-project
```

#### Step 2: Create Virtual Environment

```bash
# Linux/macOS
python3 -m venv venv

# Windows
python -m venv venv
```

This creates a `venv` folder containing the isolated Python environment.

#### Step 3: Activate Virtual Environment

```bash
# Linux/macOS
source venv/bin/activate

# Windows (Command Prompt)
venv\Scripts\activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

**You'll see** `(venv)` prefix in your terminal, indicating the virtual environment is active:

```
(venv) user@computer:~/pcapanalyze$
```

#### Step 4: Upgrade pip

```bash
pip install --upgrade pip
```

### Deactivating (When Done)

```bash
deactivate
```

**Note**: Always activate the virtual environment before working on the project!

---

## 4. Installing Project Dependencies

### Understanding requirements.txt

The `requirements.txt` file lists all Python packages needed:

```
PyQt5>=5.15.0          # GUI framework
scapy>=2.5.0           # Packet manipulation
matplotlib>=3.5.0      # Visualizations
pandas>=1.3.0          # Data analysis
dpkt>=1.9.8            # Alternative packet parsing
plotly>=5.0.0          # Interactive charts
reportlab>=3.6.0       # PDF generation
pytest>=7.0.0          # Testing framework
python-magic>=0.4.27   # File type detection
netifaces>=0.11.0      # Network interfaces
psutil>=5.9.0          # System utilities
```

### Install All Dependencies

```bash
# Make sure virtual environment is activated!
# You should see (venv) in your prompt

# Install all requirements
pip install -r requirements.txt
```

**This may take 5-10 minutes**. You'll see packages being downloaded and installed.

### Verify Installation

```bash
# List installed packages
pip list

# You should see all the packages from requirements.txt
```

### Platform-Specific Issues

#### Linux: Missing System Libraries

If you get errors about missing libraries:

```bash
# Ubuntu/Debian
sudo apt install python3-dev libpcap-dev

# Fedora/CentOS
sudo yum install python3-devel libpcap-devel
```

#### macOS: Xcode Command Line Tools

If installation fails:

```bash
# Install Xcode Command Line Tools
xcode-select --install
```

#### Windows: Microsoft Visual C++ Build Tools

If you see compilation errors:

1. Download "Microsoft C++ Build Tools" from:
   https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Install with "Desktop development with C++" workload
3. Restart terminal and try again

---

## 5. Testing Scapy

### What is Scapy?

**Scapy** is a powerful Python library for packet manipulation. It's the core of our packet analysis tool.

**Capabilities**:
- Read PCAP files
- Create custom packets
- Send/receive packets
- Analyze packet layers
- Sniff network traffic

### Basic Scapy Test

Create a test file `test_scapy.py`:

```python
#!/usr/bin/env python3
"""Test Scapy installation"""

from scapy.all import *

# Test 1: Import success
print("✅ Scapy imported successfully!")

# Test 2: Create a simple packet
packet = IP(dst="8.8.8.8")/ICMP()
print(f"✅ Created packet: {packet.summary()}")

# Test 3: Show packet structure
print("\n📦 Packet Structure:")
packet.show()

# Test 4: Access layer information
print(f"\n🔍 Destination IP: {packet[IP].dst}")
print(f"🔍 Protocol: {packet[IP].proto}")
print(f"🔍 ICMP Type: {packet[ICMP].type}")

print("\n✅ All Scapy tests passed!")
```

Run it:

```bash
python test_scapy.py
```

**Expected output**:

```
✅ Scapy imported successfully!
✅ Created packet: IP / ICMP

📦 Packet Structure:
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     =
  frag      = 0
  ttl       = 64
  proto     = icmp
  chksum    = None
  src       = 127.0.0.1
  dst       = 8.8.8.8
  \options   \
###[ ICMP ]###
     type      = echo-request
     code      = 0
     chksum    = None
     id        = 0x0
     seq       = 0x0

🔍 Destination IP: 8.8.8.8
🔍 Protocol: 1
🔍 ICMP Type: 8

✅ All Scapy tests passed!
```

---

## 6. Creating Your First PCAP File

### Using the Sample Generator

The project includes a PCAP generator. Let's test it:

```bash
# Navigate to tests directory
cd tests

# Generate sample traffic
python generate_sample_pcap.py
```

This creates `sample_traffic.pcap` with various protocols!

### Manual PCAP Creation with Scapy

Create `create_pcap.py`:

```python
#!/usr/bin/env python3
"""Create a simple PCAP file"""

from scapy.all import *

# Create an empty list to store packets
packets = []

# Create DNS query
dns_query = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="www.google.com"))
packets.append(dns_query)

# Create DNS response
dns_response = Ether()/IP(src="8.8.8.8")/UDP(sport=53)/DNS(
    qr=1,
    qd=DNSQR(qname="www.google.com"),
    an=DNSRR(rrname="www.google.com", rdata="142.250.185.78")
)
packets.append(dns_response)

# TCP Three-Way Handshake
# 1. SYN
syn = Ether()/IP(dst="142.250.185.78")/TCP(dport=80, flags="S", seq=1000)
packets.append(syn)

# 2. SYN-ACK
syn_ack = Ether()/IP(src="142.250.185.78")/TCP(sport=80, flags="SA", seq=2000, ack=1001)
packets.append(syn_ack)

# 3. ACK
ack = Ether()/IP(dst="142.250.185.78")/TCP(dport=80, flags="A", seq=1001, ack=2001)
packets.append(ack)

# HTTP GET Request
http_request = Ether()/IP(dst="142.250.185.78")/TCP(dport=80, flags="PA", seq=1001)/Raw(load="GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
packets.append(http_request)

# HTTP Response
http_response = Ether()/IP(src="142.250.185.78")/TCP(sport=80, flags="PA", ack=1100)/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello World!</body></html>")
packets.append(http_response)

# Save to PCAP file
wrpcap("my_first_capture.pcap", packets)

print(f"✅ Created PCAP file with {len(packets)} packets")
print("📁 File: my_first_capture.pcap")

# Read it back to verify
read_packets = rdpcap("my_first_capture.pcap")
print(f"\n📖 Read back {len(read_packets)} packets:")
for i, pkt in enumerate(read_packets, 1):
    print(f"  {i}. {pkt.summary()}")
```

Run it:

```bash
python create_pcap.py
```

**Output**:

```
✅ Created PCAP file with 7 packets
📁 File: my_first_capture.pcap

📖 Read back 7 packets:
  1. Ether / IP / UDP / DNS Qry "www.google.com."
  2. Ether / IP / UDP / DNS Ans "www.google.com."
  3. Ether / IP / TCP S
  4. Ether / IP / TCP SA
  5. Ether / IP / TCP A
  6. Ether / IP / TCP PA / Raw
  7. Ether / IP / TCP PA / Raw
```

---

## 7. Testing PyQt5 (GUI Framework)

### Simple GUI Test

Create `test_gui.py`:

```python
#!/usr/bin/env python3
"""Test PyQt5 installation"""

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget

def test_gui():
    """Create a simple test window"""
    app = QApplication(sys.argv)
    
    # Create main window
    window = QMainWindow()
    window.setWindowTitle("PCAP Analyzer - Setup Test")
    window.setGeometry(100, 100, 400, 200)
    
    # Create central widget
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    
    # Create layout
    layout = QVBoxLayout()
    central_widget.setLayout(layout)
    
    # Add label
    label = QLabel("✅ PyQt5 is working correctly!")
    label.setStyleSheet("font-size: 18px; padding: 20px;")
    layout.addWidget(label)
    
    # Add button
    button = QPushButton("Click me to test!")
    button.clicked.connect(lambda: label.setText("🎉 Button clicked! Setup complete!"))
    layout.addWidget(button)
    
    # Show window
    window.show()
    
    print("✅ PyQt5 test window opened!")
    print("   Close the window to continue...")
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    test_gui()
```

Run it:

```bash
python test_gui.py
```

A window should appear. Click the button to test interactivity!

---

## 8. Complete Setup Verification

### Comprehensive Test Script

Create `verify_setup.py`:

```python
#!/usr/bin/env python3
"""Comprehensive setup verification"""

import sys

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        __import__(module_name)
        print(f"✅ {package_name or module_name}")
        return True
    except ImportError as e:
        print(f"❌ {package_name or module_name}: {e}")
        return False

def main():
    print("=" * 60)
    print("PCAP Analyzer - Setup Verification")
    print("=" * 60)
    print()
    
    # Test Python version
    print("🐍 Python Version:")
    version = sys.version_info
    print(f"   {version.major}.{version.minor}.{version.micro}")
    if version.major >= 3 and version.minor >= 8:
        print("   ✅ Python 3.8+ detected")
    else:
        print("   ❌ Python 3.8+ required")
    print()
    
    # Test required packages
    print("📦 Required Packages:")
    results = []
    
    packages = [
        ("PyQt5", "PyQt5"),
        ("scapy.all", "scapy"),
        ("matplotlib", "matplotlib"),
        ("pandas", "pandas"),
        ("dpkt", "dpkt"),
        ("plotly", "plotly"),
        ("reportlab", "reportlab"),
        ("pytest", "pytest"),
        ("magic", "python-magic"),
        ("netifaces", "netifaces"),
        ("psutil", "psutil"),
    ]
    
    for module, name in packages:
        results.append(test_import(module, name))
    
    print()
    
    # Test Scapy functionality
    print("🔬 Testing Scapy:")
    try:
        from scapy.all import IP, TCP, Ether, wrpcap, rdpcap
        pkt = IP(dst="8.8.8.8")/TCP(dport=80)
        print(f"   ✅ Packet creation: {pkt.summary()}")
        
        # Test PCAP write/read
        wrpcap("/tmp/test.pcap", [pkt])
        read_pkt = rdpcap("/tmp/test.pcap")
        print(f"   ✅ PCAP write/read: {len(read_pkt)} packet(s)")
    except Exception as e:
        print(f"   ❌ Scapy test failed: {e}")
        results.append(False)
    
    print()
    
    # Summary
    print("=" * 60)
    total = len(results)
    passed = sum(results)
    print(f"Summary: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ Setup complete! You're ready to start development!")
    else:
        print("❌ Some tests failed. Please install missing packages.")
        print("\nRun: pip install -r requirements.txt")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
```

Run comprehensive verification:

```bash
python verify_setup.py
```

**Expected output** (all green checkmarks):

```
============================================================
PCAP Analyzer - Setup Verification
============================================================

🐍 Python Version:
   3.9.7
   ✅ Python 3.8+ detected

📦 Required Packages:
✅ PyQt5
✅ scapy
✅ matplotlib
✅ pandas
✅ dpkt
✅ plotly
✅ reportlab
✅ pytest
✅ python-magic
✅ netifaces
✅ psutil

🔬 Testing Scapy:
   ✅ Packet creation: IP / TCP
   ✅ PCAP write/read: 1 packet(s)

============================================================
Summary: 12/12 tests passed
✅ Setup complete! You're ready to start development!
============================================================
```

---

## 9. IDE/Editor Setup (Optional but Recommended)

### Recommended Editors

#### Visual Studio Code (Recommended)

1. Download from https://code.visualstudio.com/
2. Install Python extension
3. Open project folder
4. Select Python interpreter (the one in venv)

**Useful Extensions**:
- Python (Microsoft)
- Pylance
- Python Test Explorer
- GitLens

#### PyCharm Community Edition

1. Download from https://www.jetbrains.com/pycharm/
2. Open project
3. Configure Python interpreter → Select venv

#### Other Options

- **Sublime Text** with Python packages
- **Vim/Neovim** with Python plugins
- **Emacs** with Python mode
- **Jupyter Notebook** for experimentation

### VS Code Configuration

Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false
}
```

---

## 10. Project Structure Setup

### Create Directory Structure

```bash
# Ensure you're in project root
cd /path/to/pcapanalyze

# Directory structure should exist, but verify:
ls -la

# Expected directories:
# - core/
# - gui/
# - analysis/
# - utils/
# - tests/
# - docs/
# - learning/
```

### Understanding the Structure

```
pcapanalyze/
├── venv/                  # Virtual environment (don't commit!)
├── core/                  # Core functionality
├── gui/                   # GUI components
├── analysis/              # Advanced analysis
├── utils/                 # Utilities
├── tests/                 # Test files
├── docs/                  # Documentation
├── learning/              # Learning materials (you are here!)
├── pcap_analyzer.py       # Main entry point
├── requirements.txt       # Dependencies
└── README.md              # Project overview
```

---

## 11. Quick Reference Commands

### Virtual Environment

```bash
# Create
python3 -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Deactivate
deactivate
```

### Package Management

```bash
# Install requirements
pip install -r requirements.txt

# Install single package
pip install scapy

# List installed packages
pip list

# Save current packages
pip freeze > requirements.txt
```

### Running the Application

```bash
# GUI mode
python pcap_analyzer.py

# CLI mode
python pcap_analyzer.py -f capture.pcap

# Help
python pcap_analyzer.py --help
```

### Testing

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_core.py

# Verbose output
pytest -v
```

---

## 12. Troubleshooting Common Issues

### Issue 1: Permission Denied (Linux/Mac)

**Error**: `Permission denied` when creating PCAP files

**Solution**:
```bash
# Change script permissions
chmod +x test_scapy.py

# Or run with python explicitly
python3 test_scapy.py
```

### Issue 2: ModuleNotFoundError

**Error**: `ModuleNotFoundError: No module named 'scapy'`

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Reinstall requirements
pip install -r requirements.txt
```

### Issue 3: PyQt5 Won't Install on Windows

**Error**: Build errors during PyQt5 installation

**Solution**:
```bash
# Use pre-built wheel
pip install PyQt5 --prefer-binary

# Or download wheel from:
# https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyqt5
```

### Issue 4: Scapy Needs Root/Admin

**Error**: `Operation not permitted` when sniffing

**Note**: For this course, we **only read PCAP files**, we don't capture live traffic.  
If you need to capture:

```bash
# Linux: Use sudo
sudo python3 script.py

# Or add user to pcap group
sudo usermod -a -G pcap $USER
```

### Issue 5: Import Error on macOS

**Error**: `dyld: Library not loaded`

**Solution**:
```bash
# Install with Homebrew packages
brew install libpcap

# Reinstall scapy
pip uninstall scapy
pip install scapy
```

---

## 13. Practice Exercises

### Exercise 1: Create a Custom Packet

Write a script that creates an ICMP ping packet:

```python
from scapy.all import *

# Your code here
pkt = IP(dst="8.8.8.8")/ICMP()
pkt.show()
```

### Exercise 2: Read and Analyze

Create a PCAP, then read it back:

```python
from scapy.all import *

# Create packets
packets = [
    IP(dst="1.1.1.1")/TCP(dport=80),
    IP(dst="8.8.8.8")/UDP(dport=53),
]

# Save
wrpcap("test.pcap", packets)

# Read and print
for pkt in rdpcap("test.pcap"):
    print(pkt.summary())
```

### Exercise 3: Extract Information

Read a PCAP and extract IP addresses:

```python
from scapy.all import *

packets = rdpcap("sample.pcap")
ips = set()

for pkt in packets:
    if IP in pkt:
        ips.add(pkt[IP].src)
        ips.add(pkt[IP].dst)

print("Unique IP addresses:")
for ip in sorted(ips):
    print(f"  {ip}")
```

---

## 14. Summary

### What You Accomplished

✅ Installed Python 3.8+  
✅ Set up virtual environment  
✅ Installed all required packages  
✅ Tested Scapy functionality  
✅ Created your first PCAP file  
✅ Verified GUI framework (PyQt5)  
✅ Set up development workspace  

### Key Concepts

- **Virtual environments** isolate project dependencies
- **pip** manages Python packages
- **Scapy** is our core packet manipulation library
- **PyQt5** provides the GUI framework
- **PCAP files** store packet captures

### What's Next?

In **Session 4: Core Module - PCAP Parser Implementation**, you'll:

- Understand the PCAP file format
- Build a parser to read PCAP files
- Extract packet information
- Handle both PCAP and PCAPNG formats
- Implement error handling
- Create the `core/parser.py` module

---

**Ready for Session 4?** → [SESSION_04_PCAP_Parser_Implementation.md](SESSION_04_PCAP_Parser_Implementation.md)

---

**Status**: Session 3 Complete ✅  
**Next**: Session 4 - PCAP Parser  
**Time Invested**: ~1-2 hours  
**Progress**: 15% of total course  

Your development environment is ready! Let's start coding! 💻
