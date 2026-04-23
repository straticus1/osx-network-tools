"""Packet filter and firewall detection through anomaly analysis."""

from collections import defaultdict, Counter
from scapy.all import IP, TCP, ICMP, UDP


class FilterIndicator:
    """Represents an indicator of packet filtering."""
    
    def __init__(self, indicator_type, confidence, description, evidence=None):
        self.type = indicator_type
        self.confidence = confidence  # 'LOW', 'MEDIUM', 'HIGH'
        self.description = description
        self.evidence = evidence or []
        
    def __repr__(self):
        return f"FilterIndicator({self.type}, {self.confidence})"


class FilterDetector:
    """Detects packet filtering through various analysis techniques."""
    
    def __init__(self):
        self.indicators = []
        self.syn_packets = {}  # Track SYN packets
        self.synack_packets = set()  # Track SYN-ACK responses
        self.icmp_unreachable = []
        self.icmp_filtered = []
        self.rst_packets = []
        self.ttl_anomalies = []
        self.port_scan_syns = defaultdict(set)  # Track potential port scans
        self.total_packets = 0
        
    def analyze_packet(self, packet, timestamp=None):
        """Analyze a packet for filtering indicators."""
        self.total_packets += 1
        
        if not packet.haslayer(IP):
            return
            
        ip = packet[IP]
        
        # Check for TTL anomalies
        if ip.ttl <= 1:
            self.ttl_anomalies.append({
                'src': ip.src,
                'dst': ip.dst,
                'ttl': ip.ttl,
                'timestamp': timestamp
            })
            
        # Analyze ICMP messages
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            
            # Type 3 = Destination Unreachable
            if icmp.type == 3:
                code_meanings = {
                    0: 'Network Unreachable',
                    1: 'Host Unreachable',
                    2: 'Protocol Unreachable',
                    3: 'Port Unreachable',
                    9: 'Network Administratively Prohibited',
                    10: 'Host Administratively Prohibited',
                    13: 'Communication Administratively Prohibited'
                }
                
                self.icmp_unreachable.append({
                    'src': ip.src,
                    'dst': ip.dst,
                    'code': icmp.code,
                    'meaning': code_meanings.get(icmp.code, 'Unknown'),
                    'timestamp': timestamp
                })
                
                # Codes 9, 10, 13 indicate filtering
                if icmp.code in [9, 10, 13]:
                    self.icmp_filtered.append({
                        'src': ip.src,
                        'dst': ip.dst,
                        'code': icmp.code,
                        'meaning': code_meanings[icmp.code],
                        'timestamp': timestamp
                    })
                    
        # Analyze TCP connections
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.flags
            
            conn_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            
            # Track SYN packets
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                self.syn_packets[conn_key] = {
                    'timestamp': timestamp,
                    'responded': False
                }
                # Track for port scan detection
                self.port_scan_syns[ip.src].add(tcp.dport)
                
            # Track SYN-ACK responses
            elif flags & 0x02 and flags & 0x10:  # SYN-ACK
                reverse_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
                if reverse_key in self.syn_packets:
                    self.syn_packets[reverse_key]['responded'] = True
                self.synack_packets.add(conn_key)
                
            # Track RST packets (could indicate filtering)
            elif flags & 0x04:  # RST
                self.rst_packets.append({
                    'src': ip.src,
                    'src_port': tcp.sport,
                    'dst': ip.dst,
                    'dst_port': tcp.dport,
                    'timestamp': timestamp
                })
                
    def analyze_filtering(self):
        """Perform analysis to detect filtering indicators."""
        self.indicators = []
        
        # 1. Check for unanswered SYN packets
        unanswered_syns = [k for k, v in self.syn_packets.items() if not v['responded']]
        if unanswered_syns:
            # Calculate percentage
            total_syns = len(self.syn_packets)
            unanswered_pct = (len(unanswered_syns) / total_syns * 100) if total_syns > 0 else 0
            
            if unanswered_pct > 50:
                confidence = 'HIGH'
            elif unanswered_pct > 20:
                confidence = 'MEDIUM'
            else:
                confidence = 'LOW'
                
            self.indicators.append(FilterIndicator(
                'UNANSWERED_SYN',
                confidence,
                f'{len(unanswered_syns)} SYN packets ({unanswered_pct:.1f}%) without SYN-ACK response',
                unanswered_syns[:10]
            ))
            
        # 2. Check for ICMP filtering messages
        if self.icmp_filtered:
            self.indicators.append(FilterIndicator(
                'ICMP_ADMIN_PROHIBITED',
                'HIGH',
                f'{len(self.icmp_filtered)} ICMP administratively prohibited messages',
                self.icmp_filtered[:10]
            ))
            
        # 3. Check for ICMP unreachable (not admin)
        non_admin_unreachable = [u for u in self.icmp_unreachable if u['code'] not in [9, 10, 13]]
        if non_admin_unreachable:
            self.indicators.append(FilterIndicator(
                'ICMP_UNREACHABLE',
                'MEDIUM',
                f'{len(non_admin_unreachable)} ICMP destination unreachable messages',
                non_admin_unreachable[:10]
            ))
            
        # 4. Check for TTL anomalies
        if self.ttl_anomalies:
            self.indicators.append(FilterIndicator(
                'TTL_ANOMALY',
                'MEDIUM',
                f'{len(self.ttl_anomalies)} packets with TTL <= 1 (possible TTL-based filtering)',
                self.ttl_anomalies[:10]
            ))
            
        # 5. Check for excessive RST packets
        if len(self.rst_packets) > 10:
            rst_pct = (len(self.rst_packets) / self.total_packets * 100) if self.total_packets > 0 else 0
            if rst_pct > 5:
                self.indicators.append(FilterIndicator(
                    'EXCESSIVE_RST',
                    'MEDIUM',
                    f'{len(self.rst_packets)} TCP RST packets ({rst_pct:.1f}% of traffic)',
                    self.rst_packets[:10]
                ))
                
        # 6. Detect port scanning (could trigger filters)
        for src_ip, ports in self.port_scan_syns.items():
            if len(ports) > 10:  # Threshold for port scan
                self.indicators.append(FilterIndicator(
                    'PORT_SCAN_DETECTED',
                    'MEDIUM',
                    f'Potential port scan from {src_ip} to {len(ports)} ports',
                    [{'src': src_ip, 'ports_scanned': len(ports)}]
                ))
                
    def print_summary(self):
        """Print filter detection summary."""
        print("\n" + "="*60)
        print("PACKET FILTER DETECTION")
        print("="*60)
        
        # Perform analysis before printing
        self.analyze_filtering()
        
        if not self.indicators:
            print("\nNo packet filtering indicators detected.")
            return
            
        print(f"\nDetected {len(self.indicators)} filtering indicator(s):")
        
        # Sort by confidence
        confidence_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_indicators = sorted(self.indicators, key=lambda x: confidence_order.get(x.confidence, 3))
        
        for indicator in sorted_indicators:
            print(f"\n[{indicator.confidence}] {indicator.type}")
            print(f"  {indicator.description}")
            
            if indicator.evidence and len(indicator.evidence) > 0:
                print(f"  Sample evidence:")
                for i, evidence in enumerate(indicator.evidence[:3], 1):
                    if isinstance(evidence, dict):
                        print(f"    {i}. {evidence}")
                    else:
                        print(f"    {i}. {evidence}")
