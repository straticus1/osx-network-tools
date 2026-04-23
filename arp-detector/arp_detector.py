#!/usr/bin/env python3
"""
ARP Spoofing Detector
Monitors the network for ARP spoofing attacks by tracking IP-MAC address mappings.
"""

import argparse
import time
from collections import defaultdict
from scapy.all import sniff, ARP, Ether
from datetime import datetime


class ARPDetector:
    """Detects ARP spoofing attacks."""
    
    def __init__(self, interface=None, verbose=False):
        self.interface = interface
        self.verbose = verbose
        self.arp_table = {}  # IP -> MAC mapping
        self.mac_changes = defaultdict(list)  # Track changes per IP
        self.alerts = []
        
    def process_packet(self, packet):
        """Process an ARP packet."""
        if not packet.haslayer(ARP):
            return
            
        arp = packet[ARP]
        
        # Only process ARP replies (is-at) and requests (who-has)
        if arp.op not in [1, 2]:  # 1=request, 2=reply
            return
            
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        
        # Ignore zero/broadcast addresses
        if src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if this IP has been seen before
        if src_ip in self.arp_table:
            stored_mac = self.arp_table[src_ip]
            
            # MAC address changed for this IP - possible spoofing!
            if stored_mac != src_mac:
                alert = {
                    'timestamp': timestamp,
                    'ip': src_ip,
                    'old_mac': stored_mac,
                    'new_mac': src_mac,
                    'type': 'MAC_CHANGE'
                }
                self.alerts.append(alert)
                self.mac_changes[src_ip].append((timestamp, stored_mac, src_mac))
                
                print(f"\n[!] ALERT: Possible ARP Spoofing Detected!")
                print(f"    Time: {timestamp}")
                print(f"    IP: {src_ip}")
                print(f"    Old MAC: {stored_mac}")
                print(f"    New MAC: {src_mac}")
                
                # Update to new MAC
                self.arp_table[src_ip] = src_mac
        else:
            # First time seeing this IP
            self.arp_table[src_ip] = src_mac
            if self.verbose:
                print(f"[+] New ARP entry: {src_ip} -> {src_mac}")
                
    def start_monitoring(self):
        """Start monitoring for ARP packets."""
        print(f"Starting ARP spoofing detection...")
        if self.interface:
            print(f"Monitoring interface: {self.interface}")
        print(f"Press Ctrl+C to stop\n")
        
        try:
            sniff(
                filter="arp",
                prn=self.process_packet,
                iface=self.interface,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nStopping ARP monitoring...")
            self.print_summary()
            
    def print_summary(self):
        """Print detection summary."""
        print("\n" + "="*60)
        print("ARP SPOOFING DETECTION SUMMARY")
        print("="*60)
        print(f"Total IPs tracked: {len(self.arp_table)}")
        print(f"Alerts generated: {len(self.alerts)}")
        
        if self.alerts:
            print("\n" + "-"*60)
            print("ALERTS:")
            print("-"*60)
            for alert in self.alerts:
                print(f"\n{alert['timestamp']} - {alert['type']}")
                print(f"  IP: {alert['ip']}")
                print(f"  Old MAC: {alert['old_mac']}")
                print(f"  New MAC: {alert['new_mac']}")
                
        if self.mac_changes:
            print("\n" + "-"*60)
            print("IPs WITH MAC CHANGES:")
            print("-"*60)
            for ip, changes in self.mac_changes.items():
                print(f"\n{ip}: {len(changes)} change(s)")
                for ts, old_mac, new_mac in changes:
                    print(f"  {ts}: {old_mac} -> {new_mac}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='ARP Spoofing Detector - Monitor for ARP attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s
  sudo %(prog)s -i en0
  sudo %(prog)s -i eth0 -v

Note: This tool requires root/sudo privileges to capture packets.
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor (default: all interfaces)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output (all ARP entries)'
    )
    
    args = parser.parse_args()
    
    detector = ARPDetector(interface=args.interface, verbose=args.verbose)
    detector.start_monitoring()


if __name__ == '__main__':
    main()
