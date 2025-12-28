# Session 2: Understanding Network Protocols and Packet Structure

## Deep Dive into Network Communication 🌐

Welcome to Session 2! Now that you understand the basics of packet analysis, let's explore **how network communication actually works** at a fundamental level.

### What You'll Learn in This Session

1. The OSI Model and TCP/IP Stack
2. Network layers and their purposes
3. Packet structure layer by layer
4. Common protocols (TCP, UDP, HTTP, DNS, etc.)
5. Header fields and their meanings
6. Hands-on packet anatomy

---

## 1. The OSI Model: Understanding Network Layers

### What is the OSI Model?

The **OSI (Open Systems Interconnection) Model** is a conceptual framework that describes how data travels across a network. Think of it as a **blueprint for network communication**.

### The 7 Layers (Remember: "Please Do Not Throw Sausage Pizza Away")

```
┌─────────────────────────────────────────────────────────┐
│  Layer 7: APPLICATION    │  What humans interact with   │
│  (HTTP, FTP, SMTP, DNS)  │  "I want to visit a website" │
├─────────────────────────────────────────────────────────┤
│  Layer 6: PRESENTATION   │  Data format/encryption      │
│  (SSL/TLS, JPEG, ASCII)  │  "Encrypt and compress data" │
├─────────────────────────────────────────────────────────┤
│  Layer 5: SESSION        │  Manages connections         │
│  (NetBIOS, RPC)          │  "Start/end conversations"   │
├─────────────────────────────────────────────────────────┤
│  Layer 4: TRANSPORT      │  End-to-end delivery         │
│  (TCP, UDP)              │  "Reliable or fast delivery?"│
├─────────────────────────────────────────────────────────┤
│  Layer 3: NETWORK        │  Routing between networks    │
│  (IP, ICMP)              │  "Find path to destination"  │
├─────────────────────────────────────────────────────────┤
│  Layer 2: DATA LINK      │  Local network delivery      │
│  (Ethernet, Wi-Fi)       │  "Send to next device"       │
├─────────────────────────────────────────────────────────┤
│  Layer 1: PHYSICAL       │  Raw bits on wire            │
│  (Cables, Radio waves)   │  "Electrical signals"        │
└─────────────────────────────────────────────────────────┘
```

### Real-World Analogy: Sending a Package

Let's say you're sending a birthday gift:

1. **Application Layer** - You decide to send a gift (your intention)
2. **Presentation Layer** - You wrap the gift nicely (formatting)
3. **Session Layer** - You call to confirm they're home (session management)
4. **Transport Layer** - You choose shipping method: express or regular (TCP or UDP)
5. **Network Layer** - The postal service determines the route (IP routing)
6. **Data Link Layer** - Local post office handles it (Ethernet/Wi-Fi)
7. **Physical Layer** - Truck physically carries the package (cables/waves)

### The TCP/IP Model (Simplified, More Practical)

In practice, we often use the **TCP/IP model** which has 4 layers:

```
┌────────────────────────────────────────┐
│  APPLICATION LAYER                     │
│  (HTTP, DNS, FTP, SMTP, etc.)         │
│  [Combines OSI Layers 5-7]            │
├────────────────────────────────────────┤
│  TRANSPORT LAYER                       │
│  (TCP, UDP)                            │
│  [OSI Layer 4]                         │
├────────────────────────────────────────┤
│  INTERNET LAYER                        │
│  (IP, ICMP, ARP)                       │
│  [OSI Layer 3]                         │
├────────────────────────────────────────┤
│  LINK LAYER                            │
│  (Ethernet, Wi-Fi)                     │
│  [OSI Layers 1-2]                      │
└────────────────────────────────────────┘
```

**We'll use the TCP/IP model for this course** as it's more practical!

---

## 2. Layer-by-Layer Breakdown

### Layer 1: Link Layer (Ethernet/Wi-Fi)

**Purpose**: Transfer data between devices on the same local network

**Key Concepts**:
- **MAC Address**: Physical address of network card (e.g., `00:11:22:33:44:55`)
- **Frame**: Unit of data at this layer
- **Switches**: Connect devices on local network

**Ethernet Frame Structure**:

```
┌─────────────────────────────────────────────────────────┐
│ Ethernet Frame                                          │
├──────────────┬──────────────┬────────────┬─────────────┤
│ Destination  │   Source     │   Type     │   Payload   │
│ MAC Address  │  MAC Address │  (IPv4/v6) │   (Data)    │
│  (6 bytes)   │  (6 bytes)   │  (2 bytes) │ (46-1500 B) │
└──────────────┴──────────────┴────────────┴─────────────┘
```

**Example**:
```
Destination MAC: AA:BB:CC:DD:EE:FF (your router)
Source MAC:      11:22:33:44:55:66 (your computer)
Type:            0x0800 (IPv4)
Payload:         IP packet (see next layer)
```

### Layer 2: Internet Layer (IP)

**Purpose**: Route packets across different networks (the entire Internet!)

**Key Concepts**:
- **IP Address**: Logical address (e.g., `192.168.1.1`)
- **IPv4**: 32-bit addresses (4.3 billion addresses)
- **IPv6**: 128-bit addresses (practically unlimited)
- **Routers**: Direct traffic between networks

**IPv4 Header Structure**:

```
┌─────────────────────────────────────────────────────────────┐
│ IPv4 Header (20 bytes minimum)                              │
├──────┬──────┬──────┬─────────┬──────────────────────────────┤
│ Ver  │ IHL  │ ToS  │  Total  │  Identification              │
│ (4)  │ (4)  │ (8)  │ Length  │  (16 bits)                   │
├──────┴──────┴──────┴─────────┼─────┬────────────────────────┤
│                               │Flags│  Fragment Offset       │
│                               │ (3) │  (13 bits)             │
├───────────────┬───────────────┴─────┴────────────────────────┤
│  Time to Live │  Protocol  │  Header Checksum               │
│  (8 bits)     │  (8 bits)  │  (16 bits)                     │
├───────────────┴────────────┴────────────────────────────────┤
│  Source IP Address (32 bits)                                │
├─────────────────────────────────────────────────────────────┤
│  Destination IP Address (32 bits)                           │
├─────────────────────────────────────────────────────────────┤
│  Options (if IHL > 5)                                       │
└─────────────────────────────────────────────────────────────┘
```

**Important IPv4 Fields**:

| Field | Size | Description | Example |
|-------|------|-------------|---------|
| Version | 4 bits | IP version (4 or 6) | 4 |
| IHL | 4 bits | Header length | 5 (20 bytes) |
| ToS | 8 bits | Quality of service | 0 (normal) |
| Total Length | 16 bits | Entire packet size | 60 bytes |
| TTL | 8 bits | Hops before discard | 64 |
| Protocol | 8 bits | Next layer protocol | 6 (TCP), 17 (UDP) |
| Source IP | 32 bits | Sender's address | 192.168.1.100 |
| Dest IP | 32 bits | Receiver's address | 8.8.8.8 |

**TTL (Time To Live)**: Each router decrements TTL by 1. When it reaches 0, packet is discarded. This prevents infinite loops!

**Protocol Numbers**:
- **1** = ICMP (ping)
- **6** = TCP (reliable)
- **17** = UDP (fast)

### Layer 3: Transport Layer (TCP/UDP)

**Purpose**: Ensure data gets from application to application reliably (TCP) or quickly (UDP)

#### TCP (Transmission Control Protocol)

**Characteristics**:
- ✅ **Reliable**: Guarantees delivery
- ✅ **Ordered**: Packets arrive in order
- ✅ **Connection-oriented**: Establishes connection first
- ❌ **Slower**: More overhead
- **Use cases**: Web browsing, email, file transfer

**TCP Header Structure**:

```
┌────────────────────────────────────────────────────────────┐
│ TCP Header (20 bytes minimum)                              │
├──────────────────────────┬─────────────────────────────────┤
│  Source Port (16 bits)   │  Destination Port (16 bits)     │
├──────────────────────────┴─────────────────────────────────┤
│  Sequence Number (32 bits)                                 │
├────────────────────────────────────────────────────────────┤
│  Acknowledgment Number (32 bits)                           │
├──────┬──────┬─────────────┬───────────────────────────────┤
│ Offset│ Res  │   Flags     │  Window Size (16 bits)        │
│ (4)   │ (4)  │   (8)       │                               │
├───────┴──────┴─────────────┴───────────────────────────────┤
│  Checksum (16 bits)      │  Urgent Pointer (16 bits)       │
├──────────────────────────┴─────────────────────────────────┤
│  Options (if offset > 5)                                   │
└────────────────────────────────────────────────────────────┘
```

**Important TCP Fields**:

| Field | Description | Example |
|-------|-------------|---------|
| Source Port | Sender's port number | 54321 |
| Dest Port | Receiver's port | 80 (HTTP), 443 (HTTPS) |
| Sequence Number | Packet order tracking | 1000 |
| ACK Number | Next expected sequence | 1001 |
| Flags | Control bits | SYN, ACK, FIN, RST, PSH |
| Window Size | Flow control | 65535 bytes |

**TCP Flags** (Most Important!):

```
┌──────┬──────┬──────┬──────┬──────┬──────┐
│ URG  │ ACK  │ PSH  │ RST  │ SYN  │ FIN  │
└──────┴──────┴──────┴──────┴──────┴──────┘
   │      │      │      │      │      │
   │      │      │      │      │      └─ Close connection
   │      │      │      │      └──────── Start connection
   │      │      │      └─────────────── Reset connection (error)
   │      │      └────────────────────── Push data immediately
   │      └───────────────────────────── Acknowledgment
   └──────────────────────────────────── Urgent data
```

**TCP Three-Way Handshake** (Connection Establishment):

```
Client                                Server
   │                                     │
   │  1. SYN (seq=100)                  │
   │───────────────────────────────────>│
   │                                     │
   │  2. SYN-ACK (seq=200, ack=101)     │
   │<───────────────────────────────────│
   │                                     │
   │  3. ACK (ack=201)                  │
   │───────────────────────────────────>│
   │                                     │
   │  Connection Established!            │
```

**Explanation**:
1. Client sends **SYN** (synchronize) - "Let's connect!"
2. Server responds **SYN-ACK** - "OK, I'm ready too!"
3. Client sends **ACK** (acknowledge) - "Great, let's start!"

#### UDP (User Datagram Protocol)

**Characteristics**:
- ✅ **Fast**: Minimal overhead
- ✅ **Simple**: Just send data
- ❌ **Unreliable**: No delivery guarantee
- ❌ **Unordered**: Packets may arrive out of order
- **Use cases**: Video streaming, gaming, DNS queries, VoIP

**UDP Header Structure** (Much simpler!):

```
┌─────────────────────────────────────────┐
│ UDP Header (8 bytes - very simple!)    │
├──────────────────────┬──────────────────┤
│  Source Port         │  Dest Port       │
│  (16 bits)           │  (16 bits)       │
├──────────────────────┴──────────────────┤
│  Length (16 bits)    │  Checksum (16)   │
└──────────────────────┴──────────────────┘
```

**TCP vs UDP Comparison**:

| Feature | TCP | UDP |
|---------|-----|-----|
| Reliability | ✅ Guaranteed | ❌ Best effort |
| Speed | Slower | ✅ Faster |
| Connection | Required | None |
| Ordering | ✅ Ordered | ❌ Unordered |
| Header Size | 20+ bytes | 8 bytes |
| Use Case | Web, Email | Streaming, Gaming |

### Layer 4: Application Layer (HTTP, DNS, etc.)

**Purpose**: Protocols that applications use directly

Let's explore common protocols:

#### HTTP (Hypertext Transfer Protocol)

**Port**: 80 (HTTP), 443 (HTTPS)  
**Purpose**: Transfer web pages

**HTTP Request Example**:
```
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html
Connection: keep-alive

```

**HTTP Response Example**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1024
Server: Apache/2.4

<html>
  <body>Hello World!</body>
</html>
```

#### DNS (Domain Name System)

**Port**: 53 (UDP/TCP)  
**Purpose**: Translate domain names to IP addresses

**DNS Query Example**:
```
Question: What is the IP address of www.google.com?

DNS Query Packet:
  Transaction ID: 0x1234
  Flags: Standard query
  Questions: 1
  Question: www.google.com, Type A (IPv4 address)
```

**DNS Response Example**:
```
Answer: www.google.com = 142.250.185.78

DNS Response Packet:
  Transaction ID: 0x1234
  Flags: Response, No error
  Answers: 1
  Answer: www.google.com -> 142.250.185.78 (TTL: 300s)
```

#### FTP (File Transfer Protocol)

**Ports**: 20 (data), 21 (control)  
**Purpose**: Transfer files between systems

**Commands**: USER, PASS, LIST, RETR, STOR, QUIT

#### SMTP (Simple Mail Transfer Protocol)

**Port**: 25, 587  
**Purpose**: Send emails

**Commands**: HELO, MAIL FROM, RCPT TO, DATA, QUIT

#### ICMP (Internet Control Message Protocol)

**Purpose**: Network diagnostics and error reporting

**Common Uses**:
- **Ping**: Test connectivity
- **Traceroute**: Trace packet path
- **Error messages**: Destination unreachable, TTL exceeded

---

## 3. Complete Packet Anatomy Example

Let's analyze a real packet from visiting `http://example.com`:

### The Full Packet Structure

```
┌──────────────────────────────────────────────────────────┐
│  ETHERNET FRAME                                          │
├──────────────────────────────────────────────────────────┤
│  Destination MAC: AA:BB:CC:DD:EE:FF                      │
│  Source MAC:      11:22:33:44:55:66                      │
│  Type:            0x0800 (IPv4)                          │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  IP HEADER                                         │ │
│  ├────────────────────────────────────────────────────┤ │
│  │  Version:     4                                    │ │
│  │  IHL:         5 (20 bytes)                         │ │
│  │  Total Length: 60                                  │ │
│  │  Protocol:    6 (TCP)                              │ │
│  │  TTL:         64                                   │ │
│  │  Source IP:   192.168.1.100                        │ │
│  │  Dest IP:     93.184.216.34 (example.com)          │ │
│  │                                                    │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │  TCP HEADER                                  │ │ │
│  │  ├──────────────────────────────────────────────┤ │ │
│  │  │  Source Port:     54321                      │ │ │
│  │  │  Dest Port:       80 (HTTP)                  │ │ │
│  │  │  Sequence:        1000                       │ │ │
│  │  │  Acknowledgment:  0                          │ │ │
│  │  │  Flags:           SYN                        │ │ │
│  │  │  Window:          65535                      │ │ │
│  │  │                                              │ │ │
│  │  │  ┌────────────────────────────────────────┐ │ │ │
│  │  │  │  HTTP REQUEST (Application Data)      │ │ │ │
│  │  │  ├────────────────────────────────────────┤ │ │ │
│  │  │  │  GET / HTTP/1.1                       │ │ │ │
│  │  │  │  Host: example.com                    │ │ │ │
│  │  │  │  User-Agent: MyBrowser/1.0            │ │ │ │
│  │  │  │                                       │ │ │ │
│  │  │  └────────────────────────────────────────┘ │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### What Happens Step by Step

1. **Application Layer**: Browser creates HTTP GET request
2. **Transport Layer**: TCP wraps it with port 80, adds SYN flag
3. **Internet Layer**: IP adds source (your computer) and destination (example.com) addresses
4. **Link Layer**: Ethernet adds MAC addresses for local delivery
5. **Physical Layer**: Converts to electrical/radio signals and transmits

### Reading the Hex Dump

Here's what the actual bytes look like:

```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
0000    AA BB CC DD EE FF 11 22 33 44 55 66 08 00 45 00  .........."3DUf..E.
0010    00 3C 1C 46 40 00 40 06 B1 E6 C0 A8 01 64 5D B8  .<.F@.@......d].
0020    D8 22 D4 31 00 50 00 00 03 E8 00 00 00 00 A0 02  .".1.P..........
0030    FF FF FE 30 00 00 02 04 05 B4 04 02 08 0A 00 03  ...0............
0040    47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A  GET / HTTP/1.1..
```

**Breaking it down**:
- `AA BB CC DD EE FF` - Destination MAC
- `11 22 33 44 55 66` - Source MAC
- `08 00` - EtherType (IPv4)
- `45` - IP version (4) and header length (5)
- `06` - Protocol (6 = TCP)
- `C0 A8 01 64` - Source IP (192.168.1.100)
- `5D B8 D8 22` - Dest IP (93.184.216.34)
- `D4 31` - Source port (54321)
- `00 50` - Dest port (80)
- `47 45 54 20 2F` - "GET /" in ASCII

---

## 4. Common Protocols Summary

### Protocol Reference Table

| Protocol | Layer | Port | Reliable? | Use Case |
|----------|-------|------|-----------|----------|
| HTTP | Application | 80 | Yes (TCP) | Web browsing |
| HTTPS | Application | 443 | Yes (TCP) | Secure web |
| FTP | Application | 20,21 | Yes (TCP) | File transfer |
| SSH | Application | 22 | Yes (TCP) | Remote access |
| SMTP | Application | 25,587 | Yes (TCP) | Send email |
| POP3 | Application | 110 | Yes (TCP) | Receive email |
| IMAP | Application | 143 | Yes (TCP) | Receive email |
| DNS | Application | 53 | No (UDP) | Name resolution |
| DHCP | Application | 67,68 | No (UDP) | IP assignment |
| TFTP | Application | 69 | No (UDP) | Simple file transfer |
| NTP | Application | 123 | No (UDP) | Time sync |
| SNMP | Application | 161,162 | No (UDP) | Network management |
| SIP | Application | 5060 | Both | VoIP calls |
| RDP | Application | 3389 | Yes (TCP) | Remote desktop |
| ICMP | Network | N/A | N/A | Ping, diagnostics |
| ARP | Link | N/A | N/A | MAC address discovery |

### Well-Known Port Numbers

**System Ports (0-1023)**:
- 20/21: FTP
- 22: SSH
- 23: Telnet
- 25: SMTP
- 53: DNS
- 80: HTTP
- 110: POP3
- 143: IMAP
- 443: HTTPS
- 445: SMB
- 3389: RDP

**Registered Ports (1024-49151)**:
- 3306: MySQL
- 5432: PostgreSQL
- 6379: Redis
- 8080: HTTP alternate

**Dynamic/Private Ports (49152-65535)**:
- Used for client connections

---

## 5. Hands-On: Understanding a Packet Capture

### Scenario: Visiting a Website

When you visit `http://www.example.com`, here's the complete flow:

#### Step 1: DNS Resolution

```
Packet 1: DNS Query
  Ethernet: Your MAC -> Router MAC
  IP: Your IP (192.168.1.100) -> DNS Server (8.8.8.8)
  UDP: Port 54321 -> Port 53
  DNS: Query for www.example.com

Packet 2: DNS Response
  Ethernet: Router MAC -> Your MAC
  IP: DNS Server (8.8.8.8) -> Your IP
  UDP: Port 53 -> Port 54321
  DNS: Answer = 93.184.216.34
```

#### Step 2: TCP Connection

```
Packet 3: SYN
  IP: 192.168.1.100 -> 93.184.216.34
  TCP: Port 54322 -> Port 80, SYN flag set

Packet 4: SYN-ACK
  IP: 93.184.216.34 -> 192.168.1.100
  TCP: Port 80 -> Port 54322, SYN+ACK flags set

Packet 5: ACK
  IP: 192.168.1.100 -> 93.184.216.34
  TCP: Port 54322 -> Port 80, ACK flag set
```

#### Step 3: HTTP Request/Response

```
Packet 6: HTTP GET
  IP: 192.168.1.100 -> 93.184.216.34
  TCP: Port 54322 -> Port 80, PSH+ACK flags
  HTTP: GET / HTTP/1.1\r\nHost: www.example.com\r\n

Packet 7: HTTP Response
  IP: 93.184.216.34 -> 192.168.1.100
  TCP: Port 80 -> Port 54322, PSH+ACK flags
  HTTP: HTTP/1.1 200 OK\r\n... HTML content ...
```

#### Step 4: Connection Teardown

```
Packet 8: FIN
  IP: 192.168.1.100 -> 93.184.216.34
  TCP: Port 54322 -> Port 80, FIN+ACK flags

Packet 9: FIN-ACK
  IP: 93.184.216.34 -> 192.168.1.100
  TCP: Port 80 -> Port 54322, FIN+ACK flags

Packet 10: ACK
  IP: 192.168.1.100 -> 93.184.216.34
  TCP: Port 54322 -> Port 80, ACK flag
```

**Total: 10 packets just to load a simple webpage!**

---

## 6. Key Concepts Recap

### Network Models
- **OSI Model**: 7 layers (conceptual)
- **TCP/IP Model**: 4 layers (practical)
- **Encapsulation**: Each layer wraps the previous layer

### Layer Functions
- **Link**: Local network delivery (MAC addresses)
- **Internet**: Routing across networks (IP addresses)
- **Transport**: Application-to-application (ports, reliability)
- **Application**: User-facing protocols (HTTP, DNS, etc.)

### Protocols
- **TCP**: Reliable, ordered, connection-oriented
- **UDP**: Fast, connectionless, unreliable
- **HTTP**: Web traffic
- **DNS**: Name resolution
- **ICMP**: Network diagnostics

### Packet Structure
- **Headers**: Metadata added by each layer
- **Payload**: Actual data being transmitted
- **Encapsulation**: Data wrapped in multiple layers

---

## 7. Practice Exercises

### Exercise 1: Identify the Layers

Given this packet description, identify each layer:

```
Source MAC: AA:BB:CC:DD:EE:FF
Dest MAC: 11:22:33:44:55:66
Source IP: 192.168.1.50
Dest IP: 8.8.8.8
Source Port: 53214
Dest Port: 53
Protocol: UDP
Data: DNS query for google.com
```

**Answer**:
- Link Layer: MAC addresses
- Internet Layer: IP addresses
- Transport Layer: Ports, UDP
- Application Layer: DNS query

### Exercise 2: TCP vs UDP

For each scenario, decide TCP or UDP:

1. Streaming a live video → **UDP** (speed over reliability)
2. Downloading a file → **TCP** (need complete file)
3. Voice call → **UDP** (real-time)
4. Email → **TCP** (must be reliable)
5. Online gaming → **UDP** (low latency)
6. Web browsing → **TCP** (need complete pages)

### Exercise 3: Port Identification

What protocol uses these ports?

1. Port 80 → **HTTP**
2. Port 443 → **HTTPS**
3. Port 22 → **SSH**
4. Port 25 → **SMTP**
5. Port 53 → **DNS**
6. Port 3389 → **RDP**

### Exercise 4: TCP Flags

What do these flag combinations mean?

1. SYN → **Start connection**
2. SYN+ACK → **Accept connection**
3. ACK → **Acknowledge data**
4. FIN → **Close connection**
5. RST → **Reset/abort connection**
6. PSH → **Push data immediately**

---

## 8. How This Relates to Our Project

### Parser Module (core/parser.py)

The parser reads PCAP files containing these packets:

```python
# Reads binary PCAP file
packets = rdpcap("capture.pcap")

# Each packet contains all these layers!
for pkt in packets:
    if pkt.haslayer(Ether):  # Link layer
        print(f"MAC: {pkt[Ether].src}")
    if pkt.haslayer(IP):     # Internet layer
        print(f"IP: {pkt[IP].src}")
    if pkt.haslayer(TCP):    # Transport layer
        print(f"Port: {pkt[TCP].sport}")
```

### Dissector Module (core/dissector.py)

The dissector extracts information from each layer:

```python
def get_ip_info(packet):
    """Extract IP layer information"""
    if packet.haslayer(IP):
        return {
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'proto': packet[IP].proto,
            'ttl': packet[IP].ttl
        }
```

### Connection Tracker (core/connection_tracker.py)

Tracks TCP connections using the three-way handshake:

```python
# Detects SYN packet (connection start)
if TCP in pkt and pkt[TCP].flags & 0x02:
    # New connection!
    connection_id = (src_ip, src_port, dst_ip, dst_port)
    connections[connection_id] = 'SYN_SENT'
```

---

## 9. Additional Resources

### Interactive Tools

1. **Wireshark Tutorial**: https://www.wireshark.org/docs/wsug_html_chunked/
2. **Packet Analysis Practice**: https://www.malware-traffic-analysis.net/
3. **Protocol RFCs**: https://www.rfc-editor.org/

### Recommended Videos

- "How Does the Internet Work?" - Khan Academy
- "TCP vs UDP" - Computerphile
- "Packet Traveling" - Practical Networking

### Books

- "Computer Networking: A Top-Down Approach" - Kurose & Ross
- "TCP/IP Illustrated" - Richard Stevens
- "Wireshark Network Analysis" - Laura Chappell

---

## 10. Summary and Next Steps

### What You Accomplished

✅ Understood the OSI and TCP/IP models  
✅ Learned layer-by-layer packet structure  
✅ Explored common protocols (TCP, UDP, HTTP, DNS)  
✅ Analyzed packet headers and fields  
✅ Traced complete network communication flows  

### Key Takeaways

1. **Packets are layered** - Each layer adds headers
2. **TCP is reliable** - UDP is fast
3. **IP addresses** route between networks
4. **MAC addresses** deliver locally
5. **Ports** identify applications
6. **Flags** control TCP behavior

### What's Next?

In **Session 3: Setting Up the Development Environment**, you'll:

- Install Python and required libraries
- Set up your development workspace
- Test Scapy packet manipulation
- Generate sample PCAP files
- Run your first packet analysis

### Challenge

Before the next session, try to:

1. Install Wireshark on your computer
2. Capture 1 minute of your own network traffic
3. Find a DNS query packet
4. Find a TCP three-way handshake
5. Identify at least 3 different protocols

This hands-on experience will make the next sessions much more meaningful!

---

**Ready for Session 3?** → [SESSION_03_Development_Environment_Setup.md](SESSION_03_Development_Environment_Setup.md)

---

**Status**: Session 2 Complete ✅  
**Next**: Session 3 - Development Setup  
**Time Invested**: ~2-3 hours  
**Progress**: 10% of total course  

Keep learning! 📚
