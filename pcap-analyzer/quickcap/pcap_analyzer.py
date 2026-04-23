#!/usr/bin/env python3
"""
QuickCap - PCAP Analyzer
Analyzes packet captures for protocol detection, TCP stream reconstruction,
routing protocols, and packet filtering indicators.
"""

import argparse
import sys
from scapy.all import rdpcap, PcapReader

from protocol_detector import ProtocolDetector
from tcp_stream import TCPStreamTracker
from routing_analyzer import RoutingAnalyzer
from filter_detector import FilterDetector


class PcapAnalyzer:
    """Main PCAP analyzer orchestrating all analysis modules."""
    
    def __init__(self):
        self.protocol_detector = ProtocolDetector()
        self.tcp_tracker = TCPStreamTracker()
        self.routing_analyzer = RoutingAnalyzer()
        self.filter_detector = FilterDetector()
        self.packet_count = 0
        
    def analyze_file(self, pcap_file, verbose=False):
        """Analyze a PCAP file."""
        print(f"Analyzing PCAP file: {pcap_file}")
        print("="*60)
        
        try:
            # Use PcapReader for memory efficiency with large files
            with PcapReader(pcap_file) as pcap:
                for packet in pcap:
                    self.packet_count += 1
                    
                    # Get timestamp from packet if available
                    timestamp = packet.time if hasattr(packet, 'time') else None
                    
                    # Run all analyzers
                    self.protocol_detector.analyze_packet(packet)
                    self.tcp_tracker.analyze_packet(packet, timestamp)
                    self.routing_analyzer.analyze_packet(packet, timestamp)
                    self.filter_detector.analyze_packet(packet, timestamp)
                    
                    if verbose and self.packet_count % 1000 == 0:
                        print(f"Processed {self.packet_count} packets...", end='\r')
                        
        except FileNotFoundError:
            print(f"Error: File '{pcap_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            sys.exit(1)
            
        if verbose:
            print()  # New line after progress
            
        print(f"\nTotal packets analyzed: {self.packet_count}")
        
    def print_report(self):
        """Print comprehensive analysis report."""
        self.protocol_detector.print_summary()
        self.tcp_tracker.print_summary()
        self.routing_analyzer.print_summary()
        self.filter_detector.print_summary()
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='QuickCap - Analyze PCAP files for protocols, TCP streams, routing, and filtering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s -v traffic.pcap
  %(prog)s --verbose network_capture.pcapng
        """
    )
    
    parser.add_argument(
        'pcap_file',
        help='Path to the PCAP file to analyze'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output during analysis'
    )
    
    args = parser.parse_args()
    
    # Create analyzer and run
    analyzer = PcapAnalyzer()
    analyzer.analyze_file(args.pcap_file, verbose=args.verbose)
    analyzer.print_report()


if __name__ == '__main__':
    main()
