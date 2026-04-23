# ARP Spoofing Detector

Monitors network traffic for ARP spoofing attacks by tracking IP-to-MAC address mappings and alerting when they change.

## Features

- Real-time ARP packet monitoring
- Detects MAC address changes for tracked IPs
- Alerts on potential ARP spoofing attacks
- Tracks all IP-MAC mappings on the network
- Detailed summary of alerts and changes

## Installation

```bash
pip install -r requirements.txt
```

## Usage

**Note:** Requires root/sudo privileges to capture packets.

Basic usage (monitor all interfaces):
```bash
sudo ./arp_detector.py
```

Monitor specific interface:
```bash
sudo ./arp_detector.py -i en0
```

Verbose mode (show all ARP entries):
```bash
sudo ./arp_detector.py -v
```

## How It Works

ARP spoofing is a technique where an attacker sends fake ARP messages to associate their MAC address with the IP address of another host (typically the gateway). This detector:

1. Monitors all ARP packets on the network
2. Maintains a table of IP-to-MAC mappings
3. Alerts when a MAC address changes for a known IP
4. Tracks the history of all changes

## Example Output

```
Starting ARP spoofing detection...
Press Ctrl+C to stop

[+] New ARP entry: 192.168.1.1 -> aa:bb:cc:dd:ee:ff
[+] New ARP entry: 192.168.1.100 -> 11:22:33:44:55:66

[!] ALERT: Possible ARP Spoofing Detected!
    Time: 2026-01-19 19:45:23
    IP: 192.168.1.1
    Old MAC: aa:bb:cc:dd:ee:ff
    New MAC: 99:88:77:66:55:44
```

## Security Note

This tool is for educational and defensive security purposes only. Use it to protect your network and learn about ARP spoofing attacks.
