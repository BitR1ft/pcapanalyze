# Session 4: Core Module - PCAP Parser Implementation

## Building the Foundation: Reading PCAP Files 📖

Welcome to Session 4! Now we begin coding the actual project. We'll start with the **most fundamental component**: the PCAP parser that reads packet capture files.

### What You'll Learn in This Session

1. Understanding PCAP file format internals
2. Detecting PCAP vs PCAPNG formats
3. Reading packets using Scapy
4. Extracting file metadata
5. Implementing lazy loading for large files
6. Building the `core/parser.py` module
7. Error handling and logging

---

## 1. Understanding PCAP File Format

### Binary File Structure

PCAP is a **binary file format**. Let's understand what's inside:

#### PCAP File Header (24 bytes)

```
┌──────────────────────────────────────────────────────┐
│  PCAP Global Header (24 bytes)                       │
├──────────────┬────────────────────────────────────────┤
│ Magic Number │  0xa1b2c3d4 or 0xd4c3b2a1 (4 bytes)  │
│              │  Identifies file as PCAP              │
├──────────────┼────────────────────────────────────────┤
│ Version      │  Major: 2, Minor: 4 (4 bytes)         │
├──────────────┼────────────────────────────────────────┤
│ Timezone     │  GMT offset (4 bytes)                 │
├──────────────┼────────────────────────────────────────┤
│ Timestamp    │  Accuracy (4 bytes)                   │
├──────────────┼────────────────────────────────────────┤
│ Snaplen      │  Max packet length (4 bytes)          │
├──────────────┼────────────────────────────────────────┤
│ Link Type    │  1=Ethernet, 113=Linux cooked (4)     │
└──────────────┴────────────────────────────────────────┘
```

**Magic Number Importance**:
- `0xa1b2c3d4` = Big-endian
- `0xd4c3b2a1` = Little-endian (most common)

#### Packet Record (16 + N bytes)

Following the global header, each packet has:

```
┌──────────────────────────────────────────────────────┐
│  Packet Header (16 bytes)                            │
├──────────────┬────────────────────────────────────────┤
│ Timestamp    │  Seconds since epoch (4 bytes)        │
├──────────────┼────────────────────────────────────────┤
│ Microseconds │  Microseconds (4 bytes)               │
├──────────────┼────────────────────────────────────────┤
│ Captured Len │  Length saved in file (4 bytes)       │
├──────────────┼────────────────────────────────────────┤
│ Actual Len   │  Original packet length (4 bytes)     │
└──────────────┴────────────────────────────────────────┘
│  Packet Data (N bytes)                               │
│  Raw packet bytes                                    │
└──────────────────────────────────────────────────────┘
```

### PCAPNG Format (Next Generation)

PCAPNG is more flexible:

```
┌──────────────────────────────────────┐
│ Section Header Block                 │
├──────────────────────────────────────┤
│ Interface Description Block          │
├──────────────────────────────────────┤
│ Enhanced Packet Block 1              │
├──────────────────────────────────────┤
│ Enhanced Packet Block 2              │
├──────────────────────────────────────┤
│ ...                                  │
└──────────────────────────────────────┘
```

**Advantages of PCAPNG**:
- Multiple interfaces
- More metadata
- Comments and annotations
- Better extensibility

---

## 2. Format Detection

### Reading the Magic Number

Let's start with a simple function to detect the format:

```python
def detect_pcap_format(filename: str) -> str:
    """
    Detect if file is PCAP or PCAPNG by reading magic number
    
    Args:
        filename: Path to the file
        
    Returns:
        'PCAP', 'PCAPNG', or 'Unknown'
    """
    try:
        with open(filename, 'rb') as f:
            # Read first 4 bytes
            magic = f.read(4)
            
            # PCAP magic numbers (both endianness)
            if magic in [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1']:
                return 'PCAP'
            
            # PCAPNG magic number
            elif magic == b'\x0a\x0d\x0d\x0a':
                return 'PCAPNG'
            
            else:
                return 'Unknown'
                
    except Exception as e:
        print(f"Error reading file: {e}")
        return 'Unknown'
```

**Test it**:

```python
# Test with sample files
print(detect_pcap_format("sample.pcap"))     # Output: PCAP
print(detect_pcap_format("sample.pcapng"))   # Output: PCAPNG
print(detect_pcap_format("not_a_pcap.txt"))  # Output: Unknown
```

---

## 3. Complete Parser Class Implementation

Now let's build the complete `PCAPParser` class step by step.

### Step 1: Basic Class Structure

```python
"""
PCAP/PCAPNG file parser
Handles reading and parsing of packet capture files
"""
from scapy.all import rdpcap, PcapReader, wrpcap
import os
from typing import List, Dict, Any

class PCAPParser:
    """Parser for PCAP and PCAPNG files"""
    
    def __init__(self, filename: str = None):
        """
        Initialize parser
        
        Args:
            filename: Optional path to PCAP file
        """
        self.filename = filename
        self.packets = []
        self.file_info = {}
        self.is_loaded = False
```

**Key Attributes**:
- `filename`: Path to PCAP file
- `packets`: List of parsed packets
- `file_info`: Metadata dictionary
- `is_loaded`: Boolean flag for state tracking

### Step 2: Load File Method

```python
    def load_file(self, filename: str = None) -> bool:
        """
        Load a PCAP/PCAPNG file into memory
        
        Args:
            filename: Path to file (optional if set in __init__)
            
        Returns:
            True if successful, False otherwise
        """
        # Update filename if provided
        if filename:
            self.filename = filename
        
        # Validate file existence
        if not self.filename or not os.path.exists(self.filename):
            print(f"Error: File not found: {self.filename}")
            return False
        
        try:
            print(f"Loading file: {self.filename}")
            
            # Get file information
            self.file_info = {
                'filename': os.path.basename(self.filename),
                'filepath': self.filename,
                'size': os.path.getsize(self.filename),
                'format': self._detect_format()
            }
            
            # Read all packets using Scapy
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
            print(f"✅ Successfully loaded {len(self.packets)} packets")
            return True
            
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return False
```

**What's happening**:
1. Validate file exists
2. Extract file metadata (size, format)
3. Use Scapy's `rdpcap()` to read all packets
4. Calculate timing information
5. Set loaded flag

### Step 3: Helper Methods

```python
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
```

### Step 4: Packet Summary Method

```python
    def get_packet_summary(self, index: int) -> Dict[str, Any]:
        """
        Get a summary of a specific packet
        
        Args:
            index: Packet index (0-based)
            
        Returns:
            Dictionary with packet information
        """
        pkt = self.get_packet(index)
        if not pkt:
            return {}
        
        from scapy.all import Ether, IP, TCP, UDP
        
        summary = {
            'number': index + 1,
            'time': float(pkt.time) if hasattr(pkt, 'time') else 0,
            'length': len(pkt),
            'summary': pkt.summary()
        }
        
        # Extract layer-specific information
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
```

### Step 5: Save Packets Method

```python
    def save_packets(self, packets: List, filename: str) -> bool:
        """
        Save packets to a new PCAP file
        
        Args:
            packets: List of packets to save
            filename: Output file path
            
        Returns:
            True if successful
        """
        try:
            wrpcap(filename, packets)
            print(f"✅ Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            print(f"❌ Error saving packets: {e}")
            return False
```

### Step 6: Lazy Loading (Advanced)

For **very large PCAP files** (100MB+), loading everything into memory isn't efficient. Use lazy loading:

```python
    def lazy_load(self, filename: str = None):
        """
        Generator for lazy loading of large PCAP files
        Memory-efficient for huge captures
        
        Args:
            filename: Optional path to file
            
        Yields:
            Individual packets one at a time
        """
        if filename:
            self.filename = filename
        
        try:
            # PcapReader is a generator - yields packets one by one
            with PcapReader(self.filename) as pcap_reader:
                for pkt in pcap_reader:
                    yield pkt
        except Exception as e:
            print(f"Error in lazy loading: {e}")
            return
```

**Usage**:

```python
parser = PCAPParser("huge_file.pcap")

# Don't load all into memory
for packet in parser.lazy_load():
    # Process one packet at a time
    print(packet.summary())
```

---

## 4. Complete Implementation

Here's the full `core/parser.py` file:

```python
"""
PCAP/PCAPNG file parser
Handles reading and parsing of packet capture files
"""
from scapy.all import rdpcap, PcapReader, wrpcap, IP, TCP, UDP, Ether
import os
from typing import List, Dict, Any

class PCAPParser:
    """Parser for PCAP and PCAPNG files"""
    
    def __init__(self, filename: str = None):
        """Initialize parser"""
        self.filename = filename
        self.packets = []
        self.file_info = {}
        self.is_loaded = False
    
    def load_file(self, filename: str = None) -> bool:
        """Load a PCAP/PCAPNG file"""
        if filename:
            self.filename = filename
        
        if not self.filename or not os.path.exists(self.filename):
            print(f"Error: File not found: {self.filename}")
            return False
        
        try:
            print(f"Loading file: {self.filename}")
            
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
            print(f"✅ Successfully loaded {len(self.packets)} packets")
            return True
            
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return False
    
    def _detect_format(self) -> str:
        """Detect if file is PCAP or PCAPNG"""
        try:
            with open(self.filename, 'rb') as f:
                magic = f.read(4)
                if magic in [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1']:
                    return 'PCAP'
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
            wrpcap(filename, packets)
            print(f"✅ Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            print(f"❌ Error saving packets: {e}")
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
            print(f"Error in lazy loading: {e}")
            return
```

---

## 5. Testing the Parser

### Test Script

Create `test_parser.py`:

```python
#!/usr/bin/env python3
"""Test the PCAP parser"""

import sys
sys.path.insert(0, '..')  # Add parent directory

from core.parser import PCAPParser

def test_parser():
    """Test parser functionality"""
    
    print("=" * 60)
    print("PCAP Parser Test")
    print("=" * 60)
    print()
    
    # Create parser instance
    parser = PCAPParser()
    
    # Load a file
    if parser.load_file("sample_traffic.pcap"):
        print("\n📊 File Information:")
        info = parser.get_file_info()
        print(f"  Filename: {info['filename']}")
        print(f"  Format: {info['format']}")
        print(f"  Size: {info['size']:,} bytes")
        print(f"  Packets: {info['packet_count']}")
        print(f"  Duration: {info.get('duration', 0):.2f} seconds")
        
        # Show first 5 packets
        print("\n📦 First 5 Packets:")
        for i in range(min(5, len(parser.get_packets()))):
            summary = parser.get_packet_summary(i)
            print(f"\n  Packet {summary['number']}:")
            print(f"    Time: {summary['time']:.6f}")
            print(f"    Length: {summary['length']} bytes")
            if 'src_ip' in summary:
                print(f"    {summary['src_ip']}:{summary.get('src_port', 'N/A')} -> " +
                      f"{summary['dst_ip']}:{summary.get('dst_port', 'N/A')}")
            print(f"    Summary: {summary['summary']}")
    
    print("\n" + "=" * 60)
    print("✅ Parser test complete!")
    print("=" * 60)

if __name__ == "__main__":
    test_parser()
```

Run it:

```bash
python test_parser.py
```

---

## 6. Key Concepts Explained

### Memory Management

**Full Load vs Lazy Load**:

```python
# Full load - all packets in memory (fast access, high memory)
parser = PCAPParser("file.pcap")
parser.load_file()
packets = parser.get_packets()  # All packets

# Lazy load - one packet at a time (slow access, low memory)
for packet in parser.lazy_load("file.pcap"):
    process(packet)  # Memory efficient
```

**When to use each**:
- **Full load**: Small files (<100MB), need random access
- **Lazy load**: Large files (>100MB), sequential processing

### Error Handling

Always handle errors gracefully:

```python
try:
    parser.load_file("nonexistent.pcap")
except FileNotFoundError:
    print("File not found!")
except PermissionError:
    print("No permission to read file!")
except Exception as e:
    print(f"Unexpected error: {e}")
```

---

## 7. Practice Exercises

### Exercise 1: Add File Validation

Add a method to validate PCAP file before loading:

```python
def validate_file(self) -> bool:
    """Validate if file is a valid PCAP/PCAPNG"""
    # Check extension
    # Check magic number
    # Check minimum size
    pass
```

### Exercise 2: Extract Statistics

Add a method to get basic statistics:

```python
def get_basic_stats(self) -> Dict:
    """Get basic packet statistics"""
    # Count TCP vs UDP
    # Count unique IPs
    # Calculate average packet size
    pass
```

### Exercise 3: Filter by Protocol

Add a method to filter packets:

```python
def filter_by_protocol(self, protocol: str) -> List:
    """Filter packets by protocol (TCP, UDP, ICMP, etc.)"""
    pass
```

---

## 8. Summary

### What You Accomplished

✅ Understood PCAP file format structure  
✅ Implemented format detection (PCAP vs PCAPNG)  
✅ Built complete parser class  
✅ Added packet extraction methods  
✅ Implemented lazy loading for large files  
✅ Created comprehensive error handling  

### Key Takeaways

1. **PCAP files** have a specific binary structure
2. **Magic numbers** identify file format
3. **Scapy** handles the complex parsing
4. **Lazy loading** is memory-efficient for large files
5. **Error handling** is crucial for robustness

### What's Next?

In **Session 5: Core Module - Packet Dissector Deep Dive**, you'll:

- Understand packet layers in detail
- Extract information from each layer
- Build the dissector module
- Parse Ethernet, IP, TCP, UDP headers
- Handle application layer protocols

---

**Ready for Session 5?** → [SESSION_05_Packet_Dissector_Deep_Dive.md](SESSION_05_Packet_Dissector_Deep_Dive.md)

---

**Status**: Session 4 Complete ✅  
**Next**: Session 5 - Packet Dissector  
**Time Invested**: ~2-3 hours  
**Progress**: 20% of total course

You've built the foundation! 🎉
