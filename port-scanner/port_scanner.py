#!/usr/bin/env python3
"""
Port Scanner
Fast and flexible port scanner with multiple scan modes.
"""

import socket
import argparse
import concurrent.futures
from datetime import datetime
import sys
import ipaddress
import json
from contextlib import contextmanager

@contextmanager
def socket_timeout(timeout):
    """Context manager for socket operations."""
    yield

class PortScanner:
    """Network port scanner."""
    
    # Common ports to scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443
    ]
    
    def __init__(self, target, timeout=1.0, threads=100):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.closed_ports = []
        
    def scan_port(self, port):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                # Try to grab banner
                service = self.get_service_name(port)
                banner = self.grab_banner(port)
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
            else:
                return {
                    'port': port,
                    'state': 'closed'
                }
        except socket.gaierror:
            return {'port': port, 'state': 'error', 'error': 'Hostname resolution failed'}
        except socket.error:
            return {'port': port, 'state': 'closed'}
            
    def get_service_name(self, port):
        """Get common service name for a port."""
        try:
            return socket.getservbyport(port)
        except:
            return 'unknown'
            
    def grab_banner(self, port):
        """Try to grab service banner."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0) # Increased timeout slightly for banner
            sock.connect((self.target, port))
            
            # Send a basic request for common protocols
            if port in [80, 8080, 8443]:
                # minimal HTTP request
                sock.send(b'GET / HTTP/1.0\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
            elif port == 22:
                pass  # SSH sends banner immediately
            else:
                sock.send(b'\r\n')
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else None
        except:
            return None
        finally:
            if sock:
                sock.close()
            
    def scan_range(self, start_port, end_port, verbose=False):
        """Scan a range of ports."""
        print(f"Scanning {self.target} from port {start_port} to {end_port}")
        print(f"Timeout: {self.timeout}s, Threads: {self.threads}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        ports = range(start_port, end_port + 1)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            completed = 0
            total = len(ports)
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                completed += 1
                
                if result['state'] == 'open':
                    self.open_ports.append(result)
                    banner_info = f" - {result['banner']}" if result['banner'] else ""
                    print(f"[+] Port {result['port']}/tcp open  {result['service']}{banner_info}")
                elif verbose and result['state'] == 'closed':
                    self.closed_ports.append(result)
                    
                # Progress indicator
                if not verbose and completed % 100 == 0:
                    sys.stdout.write(f"\rProgress: {completed}/{total} ports scanned")
                    sys.stdout.flush()
                    
        if not verbose:
            print()  # New line after progress
            
    def scan_common_ports(self, verbose=False):
        """Scan common ports."""
        print(f"Scanning {self.target} for common ports")
        print(f"Timeout: {self.timeout}s, Threads: {self.threads}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in self.COMMON_PORTS]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                
                if result['state'] == 'open':
                    self.open_ports.append(result)
                    banner_info = f" - {result['banner']}" if result['banner'] else ""
                    print(f"[+] Port {result['port']}/tcp open  {result['service']}{banner_info}")
                elif verbose and result['state'] == 'closed':
                    self.closed_ports.append(result)
                    
    def print_summary(self):
        """Print scan summary."""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Open ports: {len(self.open_ports)}")
        print(f"Closed ports: {len(self.closed_ports)}")
        print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.open_ports:
            print("\n" + "-"*60)
            print("OPEN PORTS:")
            print("-"*60)
            print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'BANNER'}")
            print("-"*60)
            for p in sorted(self.open_ports, key=lambda x: x['port']):
                banner = (p['banner'][:40] + '...') if p['banner'] and len(p['banner']) > 40 else (p['banner'] or '')
                print(f"{p['port']:<10} {p['state']:<10} {p['service']:<20} {banner}")


    def to_dict(self):
        """Return scan results as dictionary."""
        return {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': self.open_ports,
            'closed_port_count': len(self.closed_ports)
        }

def is_valid_cidr(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Port Scanner - Scan network ports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s 192.168.1.0/24  (Scan entire subnet)
  %(prog)s example.com -p 1-1000 --json results.json
  %(prog)s 10.0.0.1 -c
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP address, hostname, or CIDR (e.g. 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-p', '--ports',
        help='Port specification: single (80), range (1-1000), or list (80,443,8080)'
    )
    
    parser.add_argument(
        '-c', '--common',
        action='store_true',
        help='Scan only common ports'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=100,
        help='Number of threads (default: 100)'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Connection timeout in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show closed ports'
    )
    
    parser.add_argument(
        '--json',
        help='Save results to JSON file'
    )
    
    args = parser.parse_args()
    
    targets = []
    if is_valid_cidr(args.target):
        try:
            network = ipaddress.ip_network(args.target, strict=False)
            # Skip network and broadcast addresses for /24 or smaller
            if network.prefixlen < 32:
                targets = [str(ip) for ip in network.hosts()]
            else:
                targets = [str(network.network_address)]
            print(f"Expanded CIDR {args.target} to {len(targets)} hosts.")
        except Exception as e:
            print(f"Error parsing CIDR: {e}")
            sys.exit(1)
    else:
        targets = [args.target]

    all_results = []

    for target in targets:
        print(f"\n--- Scanning Target: {target} ---")
        scanner = PortScanner(target, timeout=args.timeout, threads=args.threads)
        
        try:
            if args.common:
                scanner.scan_common_ports(verbose=args.verbose)
            elif args.ports:
                # Parse port specification
                if ',' in args.ports:
                    # List of ports
                    ports = [int(p) for p in args.ports.split(',')]
                    for port in ports:
                        result = scanner.scan_port(port)
                        if result['state'] == 'open':
                            scanner.open_ports.append(result)
                            banner_info = f" - {result['banner']}" if result['banner'] else ""
                            print(f"[+] Port {result['port']}/tcp open  {result['service']}{banner_info}")
                elif '-' in args.ports:
                    # Range of ports
                    start, end = map(int, args.ports.split('-'))
                    scanner.scan_range(start, end, verbose=args.verbose)
                else:
                    # Single port
                    port = int(args.ports)
                    result = scanner.scan_port(port)
                    if result['state'] == 'open':
                        scanner.open_ports.append(result)
                        banner_info = f" - {result['banner']}" if result['banner'] else ""
                        print(f"[+] Port {result['port']}/tcp open  {result['service']}{banner_info}")
            else:
                # Default: scan common ports
                scanner.scan_common_ports(verbose=args.verbose)
                
            scanner.print_summary()
            all_results.append(scanner.to_dict())
            
        except KeyboardInterrupt:
            print("\n\nScan interrupted by user")
            break
        except Exception as e:
            print(f"Error scanning {target}: {e}")
            continue

    if args.json:
        try:
            with open(args.json, 'w') as f:
                json.dump(all_results, f, indent=2)
            print(f"\n✓ Results saved to {args.json}")
        except Exception as e:
            print(f"⚠ Error saving JSON: {e}")


if __name__ == '__main__':
    main()
