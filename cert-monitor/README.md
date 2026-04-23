# Certificate Monitor

A Go utility to monitor SSL/TLS certificate expiration for websites and services.

## Features

- Check certificate expiration for any host
- Monitor multiple hosts from a file
- Configurable warning threshold
- Detailed certificate information (issuer, validity period, etc.)
- Summary report with expiring/expired certificates

## Installation

```bash
go build
```

## Usage

### Check a single host
```bash
./cert-monitor -host google.com
```

### Check with custom port
```bash
./cert-monitor -host example.com -port 8443
```

### Monitor multiple hosts
Create a hosts file (e.g., `hosts.txt`):
```
google.com
github.com
example.com:8443
```

Then run:
```bash
./cert-monitor -hosts-file hosts.txt
```

### Set warning threshold
```bash
./cert-monitor -host example.com -warn-days 60
```

This will warn if certificate expires within 60 days (default is 30).

## Options

- `-host`: Single host to check (e.g., `google.com`)
- `-port`: Port to connect to (default: 443)
- `-hosts-file`: File containing list of hosts (one per line)
- `-warn-days`: Warn if certificate expires within this many days (default: 30)

## Example Output

```
🔐 Certificate Monitor
================================================================================

📜 google.com
   Common Name: *.google.com
   Issuer: GTS CA 1C3
   Valid From: 2024-11-18 08:42:39
   Valid Until: 2025-02-10 08:42:38
   Status: ✅ Valid (52 days left)

================================================================================
Summary: 1 healthy, 0 expiring soon, 0 expired
```

## Use Cases

- Monitor certificate expiration for production services
- Set up cron jobs to check daily and alert on expiring certs
- Audit certificate status across multiple domains
- Verify certificate deployment after renewal

## Automation Example

Add to crontab to check daily:
```bash
0 9 * * * /path/to/cert-monitor -hosts-file /path/to/hosts.txt -warn-days 30
```

## Go Learning Highlights

This project demonstrates:
- **TLS/Crypto**: Working with `crypto/tls` for certificate inspection
- **Network programming**: Using `net.Dialer` with timeouts
- **Time calculations**: Computing days until expiration
- **File parsing**: Reading and parsing host lists
- **Structured data**: Using structs to organize certificate information
- **Error handling**: Graceful handling of connection errors
