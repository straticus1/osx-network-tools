"""Routing protocol detection and analysis."""

from collections import defaultdict
from scapy.all import IP, TCP, UDP, Raw


class RoutingUpdate:
    """Represents a routing protocol update."""
    
    def __init__(self, protocol, src_ip, dst_ip, timestamp, details=None):
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.timestamp = timestamp
        self.details = details or {}
        
    def __repr__(self):
        return f"RoutingUpdate({self.protocol}, {self.src_ip} -> {self.dst_ip})"


class RoutingAnalyzer:
    """Analyzes routing protocols and their updates."""
    
    def __init__(self):
        self.ospf_packets = []
        self.rip_packets = []
        self.bgp_packets = []
        self.eigrp_packets = []
        self.routing_updates = []
        
    def analyze_packet(self, packet, timestamp=None):
        """Analyze a packet for routing protocol information."""
        if not packet.haslayer(IP):
            return
            
        ip = packet[IP]
        proto = ip.proto
        src_ip = ip.src
        dst_ip = ip.dst
        
        # OSPF - IP Protocol 89
        if proto == 89:
            self.ospf_packets.append(packet)
            update = RoutingUpdate('OSPF', src_ip, dst_ip, timestamp)
            
            # Try to parse OSPF packet types
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if len(payload) >= 2:
                    # OSPF header: version (1 byte) + type (1 byte)
                    ospf_type = payload[1] if len(payload) > 1 else 0
                    type_names = {
                        1: 'Hello',
                        2: 'Database Description',
                        3: 'Link State Request',
                        4: 'Link State Update',
                        5: 'Link State Acknowledgment'
                    }
                    update.details['type'] = type_names.get(ospf_type, f'Unknown ({ospf_type})')
                    
            self.routing_updates.append(update)
            
        # EIGRP - IP Protocol 88
        elif proto == 88:
            self.eigrp_packets.append(packet)
            update = RoutingUpdate('EIGRP', src_ip, dst_ip, timestamp)
            
            # Try to parse EIGRP opcode
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if len(payload) >= 2:
                    # EIGRP header includes opcode
                    eigrp_opcode = payload[1] if len(payload) > 1 else 0
                    opcode_names = {
                        1: 'Update',
                        3: 'Query',
                        4: 'Reply',
                        5: 'Hello',
                        10: 'SIA Query',
                        11: 'SIA Reply'
                    }
                    update.details['opcode'] = opcode_names.get(eigrp_opcode, f'Unknown ({eigrp_opcode})')
                    
            self.routing_updates.append(update)
            
        # RIP - UDP Port 520
        if packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.sport == 520 or udp.dport == 520:
                self.rip_packets.append(packet)
                update = RoutingUpdate('RIP', src_ip, dst_ip, timestamp)
                
                # Try to parse RIP version and command
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load)
                    if len(payload) >= 4:
                        # RIP header: command (1 byte) + version (1 byte)
                        rip_command = payload[0]
                        rip_version = payload[1]
                        command_names = {1: 'Request', 2: 'Response'}
                        update.details['command'] = command_names.get(rip_command, f'Unknown ({rip_command})')
                        update.details['version'] = f'RIPv{rip_version}'
                        
                self.routing_updates.append(update)
                
        # BGP - TCP Port 179
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.sport == 179 or tcp.dport == 179:
                self.bgp_packets.append(packet)
                
                # Only process established connections with payload
                if packet.haslayer(Raw) and len(packet[Raw].load) >= 19:
                    payload = bytes(packet[Raw].load)
                    
                    # BGP message marker is 16 bytes of 0xFF
                    if payload[:16] == b'\xff' * 16:
                        update = RoutingUpdate('BGP', src_ip, dst_ip, timestamp)
                        
                        # BGP header: marker (16) + length (2) + type (1)
                        if len(payload) >= 19:
                            bgp_type = payload[18]
                            type_names = {
                                1: 'OPEN',
                                2: 'UPDATE',
                                3: 'NOTIFICATION',
                                4: 'KEEPALIVE'
                            }
                            update.details['type'] = type_names.get(bgp_type, f'Unknown ({bgp_type})')
                            
                        self.routing_updates.append(update)
                        
    def get_summary(self):
        """Return routing protocol summary."""
        return {
            'OSPF': len(self.ospf_packets),
            'RIP': len(self.rip_packets),
            'BGP': len(self.bgp_packets),
            'EIGRP': len(self.eigrp_packets),
            'Total Updates': len(self.routing_updates)
        }
        
    def print_summary(self):
        """Print routing protocol summary."""
        print("\n" + "="*60)
        print("ROUTING PROTOCOL ANALYSIS")
        print("="*60)
        
        summary = self.get_summary()
        
        print("\nDetected Routing Protocols:")
        for proto, count in summary.items():
            if count > 0:
                print(f"  {proto:20s}: {count:6d} packets")
                
        if self.routing_updates:
            print("\n" + "-"*60)
            print("ROUTING UPDATES:")
            print("-"*60)
            
            # Group by protocol
            by_protocol = defaultdict(list)
            for update in self.routing_updates:
                by_protocol[update.protocol].append(update)
                
            for protocol, updates in sorted(by_protocol.items()):
                print(f"\n{protocol} Updates ({len(updates)} total):")
                for update in updates[:5]:  # Show first 5 per protocol
                    details_str = ""
                    if update.details:
                        details_str = " - " + ", ".join(f"{k}: {v}" for k, v in update.details.items())
                    print(f"  {update.src_ip} -> {update.dst_ip}{details_str}")
                    
                if len(updates) > 5:
                    print(f"  ... and {len(updates) - 5} more")
