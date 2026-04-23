"""TCP stream reconstruction and connection tracking."""

from collections import defaultdict
from scapy.all import TCP, IP


class TCPConnection:
    """Represents a TCP connection with state tracking."""
    
    STATES = ['SYN_SENT', 'SYN_RECEIVED', 'ESTABLISHED', 'FIN_WAIT', 'CLOSED']
    
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.state = None
        self.packets = []
        self.syn_seq = None
        self.synack_seq = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.start_time = None
        self.end_time = None
        
    def add_packet(self, packet, timestamp):
        """Add a packet to this connection."""
        self.packets.append((packet, timestamp))
        
        if self.start_time is None:
            self.start_time = timestamp
        self.end_time = timestamp
        
        # Track data bytes
        if packet.haslayer(TCP) and packet.haslayer(IP):
            payload_len = len(packet[TCP].payload)
            if packet[IP].src == self.src_ip:
                self.bytes_sent += payload_len
            else:
                self.bytes_received += payload_len
                
    def __repr__(self):
        return f"TCPConnection({self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}, state={self.state})"


class TCPStreamTracker:
    """Tracks TCP connections and reconstructs streams."""
    
    def __init__(self):
        self.connections = {}
        self.incomplete_handshakes = []
        self.completed_connections = []
        
    def _get_connection_key(self, src_ip, src_port, dst_ip, dst_port):
        """Generate a bidirectional connection key."""
        # Sort to make it bidirectional
        tuple1 = (src_ip, src_port, dst_ip, dst_port)
        tuple2 = (dst_ip, dst_port, src_ip, src_port)
        return min(tuple1, tuple2)
        
    def analyze_packet(self, packet, timestamp=None):
        """Analyze a TCP packet and update connection state."""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
            
        tcp = packet[TCP]
        ip = packet[IP]
        
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport
        
        conn_key = self._get_connection_key(src_ip, src_port, dst_ip, dst_port)
        
        # Get or create connection
        if conn_key not in self.connections:
            # Use the actual direction from the first packet
            self.connections[conn_key] = TCPConnection(src_ip, src_port, dst_ip, dst_port)
            
        conn = self.connections[conn_key]
        conn.add_packet(packet, timestamp)
        
        # Analyze TCP flags for state transitions
        flags = tcp.flags
        
        # SYN flag set (connection initiation)
        if flags & 0x02:  # SYN
            if flags & 0x10:  # SYN-ACK
                conn.state = 'SYN_RECEIVED'
                conn.synack_seq = tcp.seq
            else:  # Just SYN
                conn.state = 'SYN_SENT'
                conn.syn_seq = tcp.seq
                
        # ACK without SYN (completing handshake or data transfer)
        elif flags & 0x10 and conn.state == 'SYN_RECEIVED':  # ACK
            conn.state = 'ESTABLISHED'
            
        # FIN flag (connection termination)
        elif flags & 0x01:  # FIN
            if conn.state == 'ESTABLISHED':
                conn.state = 'FIN_WAIT'
                
        # RST flag (connection reset)
        elif flags & 0x04:  # RST
            conn.state = 'CLOSED'
            
    def get_connections(self):
        """Return all tracked connections."""
        return list(self.connections.values())
        
    def get_established_connections(self):
        """Return only connections that completed the 3-way handshake."""
        return [conn for conn in self.connections.values() 
                if conn.state in ['ESTABLISHED', 'FIN_WAIT', 'CLOSED']]
                
    def get_incomplete_handshakes(self):
        """Return connections that didn't complete handshake."""
        return [conn for conn in self.connections.values() 
                if conn.state in ['SYN_SENT', 'SYN_RECEIVED']]
                
    def print_summary(self):
        """Print TCP stream summary."""
        print("\n" + "="*60)
        print("TCP STREAM ANALYSIS")
        print("="*60)
        
        established = self.get_established_connections()
        incomplete = self.get_incomplete_handshakes()
        
        print(f"\nTotal TCP connections: {len(self.connections)}")
        print(f"Established connections: {len(established)}")
        print(f"Incomplete handshakes: {len(incomplete)}")
        
        if established:
            print("\n" + "-"*60)
            print("ESTABLISHED CONNECTIONS:")
            print("-"*60)
            for conn in established[:10]:  # Show first 10
                duration = ""
                if conn.start_time and conn.end_time:
                    duration = f" ({conn.end_time - conn.start_time:.2f}s)"
                print(f"{conn.src_ip}:{conn.src_port} <-> {conn.dst_ip}:{conn.dst_port}")
                print(f"  State: {conn.state}, Packets: {len(conn.packets)}")
                print(f"  Data: {conn.bytes_sent} bytes sent, {conn.bytes_received} bytes received{duration}")
                
        if incomplete:
            print("\n" + "-"*60)
            print("INCOMPLETE HANDSHAKES (Possible Filtering):")
            print("-"*60)
            for conn in incomplete[:10]:  # Show first 10
                print(f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}")
                print(f"  State: {conn.state}, Packets: {len(conn.packets)}")
