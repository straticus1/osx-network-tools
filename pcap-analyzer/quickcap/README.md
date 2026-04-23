# QuickCap - PCAP Analyzer

A comprehensive packet capture analyzer that detects network protocols, reconstructs TCP streams, identifies routing protocols, and detects packet filtering.

## Features

- **Protocol Detection**: Identifies protocols across OSI layers (L2-L7)
  - Layer 2: Ethernet
  - Layer 3: IPv4, IPv6, ARP, ICMP, OSPF, EIGRP
  - Layer 4: TCP, UDP
  - Layer 7: HTTP, DNS, and service port identification

- **TCP Stream Reconstruction**: Tracks TCP connections through 3-way handshakes
  - Monitors SYN/SYN-ACK/ACK sequences
  - Tracks connection states (SYN_SENT, ESTABLISHED, FIN_WAIT, etc.)
  - Records data transfer statistics
  - Identifies incomplete handshakes

- **Routing Protocol Analysis**: Detects and analyzes routing protocols
  - OSPF (IP Protocol 89) - Hello, LSA Updates, etc.
  - RIP (UDP Port 520) - Routing table advertisements
  - BGP (TCP Port 179) - OPEN, UPDATE, KEEPALIVE messages
  - EIGRP (IP Protocol 88) - Hello and Update packets

- **Packet Filter Detection**: Identifies evidence of packet filtering
  - Unanswered SYN packets (dropped connections)
  - ICMP administratively prohibited messages
  - TTL anomalies (TTL-based filtering)
  - Excessive TCP RST packets
  - Port scanning detection

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python pcap_analyzer.py capture.pcap
```

Verbose mode (shows progress):

```bash
python pcap_analyzer.py -v traffic.pcap
```

Make it executable:

```bash
chmod +x pcap_analyzer.py
./pcap_analyzer.py capture.pcap
```

## Example Output

```
PROTOCOL DETECTION SUMMARY
==============================================================

Layer 2 (Data Link):
  Ethernet            :   1234 packets

Layer 3 (Network):
  IPv4                :   1200 packets
  ARP                 :     34 packets

Layer 4 (Transport):
  TCP                 :    890 packets
  UDP                 :    310 packets

TCP STREAM ANALYSIS
==============================================================

Total TCP connections: 45
Established connections: 42
Incomplete handshakes: 3

ROUTING PROTOCOL ANALYSIS
==============================================================

Detected Routing Protocols:
  OSPF                :     15 packets
  BGP                 :     23 packets

PACKET FILTER DETECTION
==============================================================

Detected 2 filtering indicator(s):

[HIGH] UNANSWERED_SYN
  3 SYN packets (6.7%) without SYN-ACK response
```

## Architecture

The analyzer consists of five main modules:

1. **protocol_detector.py**: Multi-layer protocol identification
2. **tcp_stream.py**: TCP connection tracking and state management
3. **routing_analyzer.py**: Routing protocol detection and update parsing
4. **filter_detector.py**: Packet filtering detection through anomaly analysis
5. **pcap_analyzer.py**: Main orchestrator and CLI interface

## Requirements

- Python 3.6+
- Scapy 2.5.0+

## Use Cases

- Network troubleshooting and diagnostics
- Security analysis and intrusion detection
- Protocol verification in lab environments
- Identifying firewall and filtering behavior
- Routing protocol monitoring
- TCP connection analysis

## Technical Details

### TCP Stream Tracking

The analyzer tracks TCP connections using a 4-tuple key (src_ip, src_port, dst_ip, dst_port) and monitors:
- SYN flag (0x02): Connection initiation
- SYN-ACK flags (0x02 | 0x10): Server response
- ACK flag (0x10): Handshake completion
- FIN flag (0x01): Connection termination
- RST flag (0x04): Connection reset

### Filter Detection Methods

The analyzer uses multiple heuristics to detect filtering:
- **Incomplete handshakes**: High percentage of SYN without SYN-ACK
- **ICMP responses**: Administratively prohibited messages (codes 9, 10, 13)
- **TTL anomalies**: Packets with TTL ≤ 1
- **RST analysis**: Excessive reset packets indicating connection blocking
- **Port scanning**: Detection of systematic port probes

### Routing Protocol Identification

- **OSPF**: IP protocol 89, parses packet types from header
- **EIGRP**: IP protocol 88, identifies opcodes
- **RIP**: UDP port 520, extracts version and command
- **BGP**: TCP port 179, validates marker and parses message types

## License

MIT License
