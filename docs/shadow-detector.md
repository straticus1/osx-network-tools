# Shadow IT Detector

The Shadow IT Detector identifies unauthorized services, cloud applications, and Shadow IT on your network through passive DNS monitoring and TLS traffic analysis.

## Overview

Shadow IT refers to information technology systems, devices, software, applications, and services used without explicit organizational approval. This tool helps security teams discover and monitor such unauthorized services.

## Features

- **DNS Monitoring**: Captures and analyzes DNS queries to identify services
- **TLS/SNI Extraction**: Extracts Server Name Indication from HTTPS traffic
- **Cloud Service Detection**: Identifies AWS, Azure, GCP, and SaaS applications
- **Suspicious Domain Detection**: Detects potential data exfiltration via DNS
- **DNS Tunneling Detection**: Identifies DNS tunneling attempts
- **Service Fingerprinting**: Maintains database of known services

## Installation

```bash
# Build the tool
make build

# Or build individually
cd cmd/shadow-detector
go build -o shadow-detector
```

## Usage

### DNS Monitoring

Monitor DNS queries to identify services:

```bash
sudo ./bin/shadow-detector dns --interface en0 --duration 300
```

**Output:**
```
Monitoring DNS traffic on en0...
Press Ctrl+C to stop

☁️  CLOUD SERVICE: AWS - S3 (bucket.s3.amazonaws.com)
☁️  CLOUD SERVICE: SaaS - Dropbox (www.dropbox.com)
⚠️  SUSPICIOUS: long-random-string-abc123.example.com from 192.168.1.10

DNS MONITORING SUMMARY
================================================================================
Total Queries: 1,234
Suspicious Queries: 5
Cloud Services Detected: 12

Cloud Services:
  - AWS:S3
  - AWS:CloudFront
  - SaaS:Dropbox
  - SaaS:Slack
```

### TLS Monitoring

Extract SNI from TLS handshakes:

```bash
sudo ./bin/shadow-detector tls --interface en0 --duration 300
```

**Output:**
```
Monitoring TLS/HTTPS traffic on en0...

🔒 TLS Connection: api.dropbox.com (Dropbox)
🔒 TLS Connection: slack.com (Slack)
🔒 TLS Connection: s3.amazonaws.com (AWS)

TLS MONITORING SUMMARY
================================================================================
Total Connections: 456
Unique Hosts: 123

Services Detected:
  - Dropbox: 45 connections
  - Slack: 78 connections
  - AWS: 123 connections
```

### Full Scan

Comprehensive scan combining DNS and TLS:

```bash
sudo ./bin/shadow-detector scan --interface en0 --duration 300 --output report.txt
```

**Output:**
```
Starting full network scan...
Interface: en0
Duration: 300 seconds

================================================================================
SHADOW IT DETECTION REPORT
================================================================================
Generated: 2024-01-15 14:30:00

DNS Activity:
  Total Queries: 2,345
  Suspicious Domains: 8

  Suspicious Domains:
    - base64encodeddata.suspicious.tk
    - very-long-subdomain-name-here.example.com
    ... and 6 more

TLS Activity:
  Total Connections: 567
  Unique Hosts: 234

Cloud Services: 15
  By Provider:
    - AWS: 8 services
    - Azure: 3 services
    - SaaS: 4 services

Service Usage:
  - Dropbox: 45 connections
  - Slack: 78 connections
  - GitHub: 23 connections
```

### Cloud Service Detection

Focused cloud service discovery:

```bash
sudo ./bin/shadow-detector cloud --interface en0 --duration 60
```

**Output:**
```
Detecting cloud services...
Monitoring for 60 seconds...

================================================================================
CLOUD SERVICES DETECTED
================================================================================

AWS:
  - S3
    Domain: bucket.s3.amazonaws.com
    Access Count: 45
    First Seen: 14:25:12
    Last Seen: 14:26:03

  - CloudFront
    Domain: d111111abcdef8.cloudfront.net
    Access Count: 23
    First Seen: 14:25:15
    Last Seen: 14:26:01

SaaS:
  - Dropbox
    Domain: www.dropbox.com
    Access Count: 12
    First Seen: 14:25:20
    Last Seen: 14:25:58
```

## Configuration

Edit `configs/shadow-it-policies.yaml`:

### Approved Services

```yaml
# Approved cloud services
approved_services:
  aws:
    enabled: true
    services:
      - "S3"
      - "EC2"
      - "Lambda"
    alert_on_unknown: true

# Approved SaaS applications
approved_saas:
  - "GitHub"
  - "Slack"
  - "Zoom"
```

### DNS Monitoring

```yaml
dns_monitoring:
  enabled: true

  suspicious_patterns:
    max_subdomain_length: 50
    entropy_threshold: 4.5

    suspicious_tlds:
      - ".tk"
      - ".ml"
      - ".xyz"

  tunneling_detection:
    enabled: true
    query_threshold: 10
    max_subdomain_depth: 5
```

### Alerts

```yaml
alerts:
  enabled: true

  conditions:
    unauthorized_service: true
    suspicious_dns: true
    dns_tunneling: true
    blocked_service: true

  destinations:
    console: true
    log_file: "/var/log/shadow-it.log"
```

## Detection Methods

### 1. DNS Query Analysis

**What it detects:**
- Queries to cloud services (AWS, Azure, GCP)
- SaaS application access
- Suspicious domains
- DNS tunneling attempts

**Indicators:**
- Long subdomain names (> 50 characters)
- High entropy strings (random-looking)
- Base64-encoded patterns
- Frequent queries to same domain
- Unusual TLDs

### 2. TLS/SNI Extraction

**What it detects:**
- HTTPS connections without DNS resolution
- Direct IP connections with SNI
- Service fingerprints

**How it works:**
- Captures TLS ClientHello packets
- Extracts Server Name Indication
- Matches against service database

### 3. Cloud Service Identification

**Supported Providers:**
- **AWS**: S3, EC2, Lambda, CloudFront, RDS, DynamoDB
- **Azure**: Blob Storage, VMs, SQL Database, Key Vault
- **GCP**: Cloud Storage, Compute Engine, Firestore
- **SaaS**: Dropbox, Box, GitHub, GitLab, Slack, Zoom, Salesforce, etc.

### 4. DNS Tunneling Detection

**Indicators:**
- High query rate (> 10/minute)
- Long subdomain names
- High entropy in queries
- Many subdomains (> 5 levels)
- Base64-like patterns

### 5. Suspicious Domain Detection

**Patterns detected:**
- Free/suspicious TLDs (.tk, .ml, .ga, etc.)
- Data exfiltration patterns
- Encoded data in subdomains
- DGA (Domain Generation Algorithm) domains

## Use Cases

### 1. Unauthorized Cloud Usage

**Scenario**: Employees using personal Dropbox to store work files

**Detection**:
```bash
sudo ./bin/shadow-detector cloud --interface en0 --duration 300
```

**Result**: Identifies Dropbox connections not in approved services list

### 2. Data Exfiltration

**Scenario**: Malware exfiltrating data via DNS

**Detection**:
```bash
sudo ./bin/shadow-detector dns --interface en0 --duration 600
```

**Result**: Detects suspicious DNS patterns:
- Long encoded subdomains
- High query frequency
- Unusual TLDs

### 3. Shadow SaaS Applications

**Scenario**: Teams using unauthorized project management tools

**Detection**:
```bash
sudo ./bin/shadow-detector scan --interface en0 --duration 3600
```

**Result**: Comprehensive report of all SaaS usage

### 4. Compliance Monitoring

**Scenario**: Ensure only approved services are used

**Detection**:
```bash
# Run continuously
while true; do
  sudo ./bin/shadow-detector scan --interface en0 --duration 3600 --output "report-$(date +%Y%m%d).txt"
  sleep 3600
done
```

**Result**: Hourly reports for compliance audits

## Integration

### SIEM Integration

Export data to SIEM:

```bash
sudo ./bin/shadow-detector scan --interface en0 --duration 300 | \
  logger -t shadow-detector -p local0.info
```

### Alerting

Send alerts on detection:

```bash
#!/bin/bash
OUTPUT=$(sudo ./bin/shadow-detector scan --interface en0 --duration 300)

if echo "$OUTPUT" | grep -q "SUSPICIOUS\|Unauthorized"; then
    # Send alert
    mail -s "Shadow IT Alert" security@example.com <<< "$OUTPUT"
fi
```

### Continuous Monitoring

Run as a service:

```bash
# Create systemd service
sudo tee /etc/systemd/system/shadow-detector.service <<EOF
[Unit]
Description=Shadow IT Detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shadow-detector scan --interface en0 --duration 3600
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable shadow-detector
sudo systemctl start shadow-detector
```

## Best Practices

1. **Baseline Normal Behavior**: Run for a week to understand normal patterns
2. **Whitelist Known Services**: Add approved services to configuration
3. **Monitor Continuously**: Don't rely on one-time scans
4. **Review Reports Daily**: Check for new unauthorized services
5. **Educate Users**: Make approved alternatives available
6. **Incident Response**: Have a plan for detected Shadow IT

## Limitations

1. **Encrypted DNS**: Cannot analyze DNS over HTTPS (DoH)
2. **VPN Traffic**: Cannot inspect traffic through VPNs
3. **Direct IP Connections**: May miss connections without DNS/SNI
4. **False Positives**: May flag legitimate services as suspicious

## Troubleshooting

### No Traffic Captured

```bash
# Check interface name
ifconfig

# Verify permissions
sudo ./bin/shadow-detector dns --interface en0
```

### Too Many False Positives

Adjust thresholds in config:

```yaml
suspicious_patterns:
  max_subdomain_length: 100  # Increase
  entropy_threshold: 5.0     # Increase
```

### Missing Cloud Services

Add to service database:

```yaml
approved_services:
  custom:
    enabled: true
    services:
      - "Your Service"
```

## Performance

- **CPU Usage**: Low (< 5% on modern systems)
- **Memory**: ~50-100 MB
- **Disk**: Logs grow ~10-50 MB/day
- **Network Impact**: Passive monitoring (no additional traffic)

## Security Considerations

- Requires root/sudo for packet capture
- Does not decrypt HTTPS traffic
- Only analyzes metadata (DNS, SNI)
- Respects user privacy (no payload inspection)
- Complies with monitoring policies

## See Also

- [Egress Auditor](egress-auditor.md) - Data exfiltration detection
- [Zero Trust Policies](zero-trust-policies.md) - Policy configuration
- [Architecture](architecture.md) - System design
