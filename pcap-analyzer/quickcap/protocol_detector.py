"""Protocol detection engine for various network layers."""

from collections import Counter
from scapy.all import Ether, IP, IPv6, ARP, ICMP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse


class ProtocolDetector:
    """Detects and tracks network protocols across OSI layers."""
    
    def __init__(self):
        self.l2_protocols = Counter()
        self.l3_protocols = Counter()
        self.l4_protocols = Counter()
        self.l7_protocols = Counter()
        self.port_services = Counter()
        
    def analyze_packet(self, packet):
        """Analyze a single packet for protocol information."""
        # Layer 2 - Data Link
        if packet.haslayer(Ether):
            ether_type = packet[Ether].type
            self.l2_protocols['Ethernet'] += 1
            
        # Layer 3 - Network
        if packet.haslayer(IP):
            self.l3_protocols['IPv4'] += 1
            proto = packet[IP].proto
            
            if proto == 89:
                self.l3_protocols['OSPF'] += 1
            elif proto == 88:
                self.l3_protocols['EIGRP'] += 1
                
        elif packet.haslayer(IPv6):
            self.l3_protocols['IPv6'] += 1
            
        if packet.haslayer(ARP):
            self.l3_protocols['ARP'] += 1
            
        if packet.haslayer(ICMP):
            self.l3_protocols['ICMP'] += 1
            
        # Layer 4 - Transport
        if packet.haslayer(TCP):
            self.l4_protocols['TCP'] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Check for well-known ports
            if sport == 179 or dport == 179:
                self.l7_protocols['BGP'] += 1
            elif sport == 80 or dport == 80:
                self.port_services['HTTP'] += 1
            elif sport == 443 or dport == 443:
                self.port_services['HTTPS'] += 1
            elif sport == 22 or dport == 22:
                self.port_services['SSH'] += 1
            elif sport == 21 or dport == 21:
                self.port_services['FTP'] += 1
            elif sport == 23 or dport == 23:
                self.port_services['Telnet'] += 1
            elif sport == 25 or dport == 25:
                self.port_services['SMTP'] += 1
                
        elif packet.haslayer(UDP):
            self.l4_protocols['UDP'] += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if sport == 520 or dport == 520:
                self.l7_protocols['RIP'] += 1
            elif sport == 53 or dport == 53:
                self.port_services['DNS'] += 1
            elif sport == 67 or dport == 68:
                self.port_services['DHCP'] += 1
            elif sport == 123 or dport == 123:
                self.port_services['NTP'] += 1
            elif sport == 161 or dport == 161:
                self.port_services['SNMP'] += 1
                
        # Layer 7 - Application
        if packet.haslayer(DNS):
            self.l7_protocols['DNS'] += 1
            
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self.l7_protocols['HTTP'] += 1
            
    def get_summary(self):
        """Return a summary of detected protocols."""
        return {
            'Layer 2 (Data Link)': dict(self.l2_protocols),
            'Layer 3 (Network)': dict(self.l3_protocols),
            'Layer 4 (Transport)': dict(self.l4_protocols),
            'Layer 7 (Application)': dict(self.l7_protocols),
            'Port Services': dict(self.port_services)
        }
        
    def print_summary(self):
        """Print protocol detection summary."""
        summary = self.get_summary()
        
        print("\n" + "="*60)
        print("PROTOCOL DETECTION SUMMARY")
        print("="*60)
        
        for layer, protocols in summary.items():
            if protocols:
                print(f"\n{layer}:")
                for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {proto:20s}: {count:6d} packets")
