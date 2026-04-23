# Port Scanner

Fast, multi-threaded network port scanner with banner grabbing capabilities.

## Features

- Fast multi-threaded scanning
- Scan specific ports, ranges, or common ports
- Service detection
- Banner grabbing
- Progress indicators
- Configurable timeout and thread count

## Usage

Scan common ports (default):
```bash
./port_scanner.py 192.168.1.1
```

Scan specific port range:
```bash
./port_scanner.py example.com -p 1-1000
```

Scan specific ports:
```bash
./port_scanner.py scanme.nmap.org -p 80,443,8080
```

Scan all ports (full scan):
```bash
./port_scanner.py 10.0.0.1 -p 1-65535 -t 200
```

Verbose mode (show closed ports):
```bash
./port_scanner.py 192.168.1.1 -v
```

Custom timeout and threads:
```bash
./port_scanner.py target.com -p 1-1000 --timeout 0.5 -t 200
```

## Example Output

```
Scanning 192.168.1.1 for common ports
Timeout: 1.0s, Threads: 100
Started at: 2026-01-19 19:45:00

[+] Port 22/tcp open  ssh - SSH-2.0-OpenSSH_8.9
[+] Port 80/tcp open  http
[+] Port 443/tcp open  https

============================================================
SCAN SUMMARY
============================================================
Target: 192.168.1.1
Open ports: 3
Closed ports: 0
Completed at: 2026-01-19 19:45:02

------------------------------------------------------------
OPEN PORTS:
------------------------------------------------------------
PORT       STATE      SERVICE              BANNER
------------------------------------------------------------
22         open       ssh                  SSH-2.0-OpenSSH_8.9
80         open       http
443        open       https
```

## Options

- `-p, --ports`: Port specification (single, range, or comma-separated list)
- `-c, --common`: Scan only common ports
- `-t, --threads`: Number of concurrent threads (default: 100)
- `--timeout`: Connection timeout in seconds (default: 1.0)
- `-v, --verbose`: Show closed ports

## Common Ports Scanned

21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 135 (RPC), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS), 445 (SMB), 993 (IMAPS), 995 (POP3S), 1723 (PPTP), 3306 (MySQL), 3389 (RDP), 5900 (VNC), 8080 (HTTP-ALT), 8443 (HTTPS-ALT)

## Performance Tips

- Increase threads for faster scans: `-t 200`
- Decrease timeout for faster scans (may miss slower services): `--timeout 0.5`
- For full port scans, use more threads: `-p 1-65535 -t 500`

## Security Note

Only scan networks and systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.
