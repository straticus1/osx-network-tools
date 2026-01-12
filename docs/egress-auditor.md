# Egress Auditor / Data Exfiltration Detector

The Egress Auditor monitors outbound network connections and detects data exfiltration patterns, unauthorized data transfers, and command & control (C2) communication.

## Overview

Data exfiltration is the unauthorized transfer of data from a computer or network. This tool provides real-time monitoring and pattern-based detection of suspicious outbound traffic.

## Features

- **Connection Tracking**: Monitor all outbound network connections
- **Large Upload Detection**: Identify unusual data uploads
- **C2 Beaconing Detection**: Detect periodic command & control communication
- **DNS Tunneling Detection**: Identify data exfiltration via DNS
- **Unusual Port Monitoring**: Track connections to non-standard ports
- **Pattern Analysis**: Statistical analysis of traffic patterns
- **Real-time Alerting**: Immediate notification of suspicious activity

## Installation

```bash
# Build the tool
make build

# Or build individually
cd cmd/egress-auditor
go build -o egress-auditor
```

## Usage

### Monitor Outbound Connections

Track all outbound connections in real-time:

```bash
sudo ./bin/egress-auditor monitor --interface en0
```

**Output:**
```
Tracking connections on en0...

→ 54.239.28.85:443 (TCP)
→ 142.250.185.206:443 (TCP)
→ 13.107.42.14:443 (TCP)

CONNECTION SUMMARY
================================================================================
Total Connections: 1,234
  Outbound: 856
  Inbound: 378

Data Transfer:
  Sent: 125.4 MB
  Received: 456.7 MB

By Protocol:
  TCP: 1,120
  UDP: 114

Top Ports:
  443: 789 connections
  80: 234 connections
  22: 45 connections
```

### Analyze for Exfiltration

Analyze traffic for data exfiltration patterns:

```bash
sudo ./bin/egress-auditor analyze --interface en0 --duration 300 --threshold 104857600
```

**Output:**
```
Starting exfiltration analysis...
Interface: en0, Duration: 300 seconds
Large upload threshold: 100.0 MB

❌ [HIGH] Large data upload detected: 125.4 MB
   Confidence: 80%
   Time: 14:35:42
   Connection: 192.168.1.10:54321 -> 185.220.101.15:443
   Indicators:
     - Uploaded 125.4 MB
     - Destination: 185.220.101.15:443

⚠️  [MEDIUM] Connection to unusual port 8888
   Confidence: 50%
   Time: 14:36:15
   Connection: 192.168.1.10:54322 -> 203.0.113.45:8888
   Indicators:
     - Port: 8888
     - Destination: 203.0.113.45
     - Data sent: 12.3 MB

================================================================================
EXFILTRATION ANALYSIS REPORT
================================================================================

Connections Analyzed: 856
Total Data Sent: 145.7 MB
Patterns Detected: 8

By Severity:
  ❌ HIGH: 2
  ⚠️  MEDIUM: 6
```

### Top Data Senders

Display connections with highest data transfer:

```bash
sudo ./bin/egress-auditor top --interface en0 --duration 60 --continuous
```

**Output:**
```
TOP DATA SENDERS
================================================================================
Updated: 14:40:25

SOURCE          PORT   DEST            PORT   SENT         RECEIVED
--------------------------------------------------------------------------------
192.168.1.10    54321  185.220.101.15  443    125.4 MB     2.3 MB
192.168.1.10    54322  203.0.113.45    8888   45.6 MB      1.1 MB
192.168.1.15    50234  54.239.28.85    443    23.4 MB      156.7 MB
192.168.1.20    51456  142.250.185.206 443    12.3 MB      89.4 MB
```

### Detect C2 Beaconing

Identify periodic communication patterns:

```bash
sudo ./bin/egress-auditor beacon --interface en0 --duration 300
```

**Output:**
```
Detecting C2 beaconing patterns...
Monitoring for 300 seconds...

================================================================================
BEACONING DETECTION REPORT
================================================================================

⚠️  Found 2 potential beaconing patterns:

1. Periodic beaconing detected to 185.220.101.15:443
   Severity: CRITICAL (Confidence: 85%)
   Indicators:
     - Connections: 15
     - Avg interval: 60.2 seconds
     - Jitter: 2.3 seconds
     - Indicates possible C2 communication

2. Periodic beaconing detected to 203.0.113.45:8888
   Severity: CRITICAL (Confidence: 85%)
   Indicators:
     - Connections: 12
     - Avg interval: 120.5 seconds
     - Jitter: 4.1 seconds
     - Indicates possible C2 communication
```

### Generate Security Report

Comprehensive security report:

```bash
sudo ./bin/egress-auditor report --interface en0 --duration 300 --output security-report.txt
```

**Output:**
```
Generating security report...
Monitoring for 300 seconds...

================================================================================
EGRESS SECURITY REPORT
================================================================================

Generated: 2024-01-15 14:45:00

CONNECTION STATISTICS:
  Total Connections: 1,234
  Outbound: 856
  Data Sent: 145.7 MB
  Data Received: 678.9 MB

SECURITY FINDINGS: 10 patterns detected

CRITICAL THREATS: 2
  - Periodic beaconing detected to 185.220.101.15:443
  - Periodic beaconing detected to 203.0.113.45:8888

HIGH SEVERITY: 3
  - Large data upload detected: 125.4 MB
  - Large data upload detected: 45.6 MB
  - Connection to suspicious IP range

MEDIUM SEVERITY: 5
  - Connection to unusual port 8888
  - Connection to unusual port 9999
  - Long-duration connection with data transfer
  - Large data transfer over UDP
  - Connection to unusual port 1337

TOP DATA SENDERS:
  1. 185.220.101.15:443 (125.4 MB sent)
  2. 203.0.113.45:8888 (45.6 MB sent)
  3. 54.239.28.85:443 (23.4 MB sent)

RECOMMENDATIONS:
  - Critical threats detected - immediate action required
  - Review firewall rules for outbound connections
  - Implement data loss prevention (DLP) policies
  - Enable enhanced logging for high-risk connections

================================================================================

✓ Report saved to: security-report.txt
```

## Configuration

Edit `configs/egress-policies.yaml`:

### Detection Thresholds

```yaml
thresholds:
  # Large upload detection
  large_upload:
    bytes: 104857600  # 100 MB
    duration: 300     # 5 minutes
    alert_immediate: true

  # Unusual port detection
  unusual_ports:
    high_port_threshold: 49152
    connection_threshold: 5

  # Long connections
  long_connections:
    max_duration: 3600  # 1 hour
    min_data_transfer: 1048576  # 1 MB
```

### Beaconing Detection

```yaml
beaconing:
  enabled: true
  min_connections: 5
  max_jitter: 5.0
  min_interval: 10
  max_interval: 300
  severity: "CRITICAL"
```

### Port Policies

```yaml
ports:
  # Always allowed
  allowed:
    - 80    # HTTP
    - 443   # HTTPS
    - 22    # SSH

  # Blocked (always alert)
  blocked:
    - 23    # Telnet
    - 21    # FTP

  # Suspicious
  suspicious:
    - 1337
    - 4444  # Metasploit
    - 8888
```

### Alerts

```yaml
alerts:
  enabled: true

  severities:
    CRITICAL:
      enabled: true
      immediate: true
    HIGH:
      enabled: true
      immediate: true

  destinations:
    console:
      enabled: true
    file:
      enabled: true
      path: "/var/log/egress-alerts.log"
    email:
      enabled: false
      to: "security@example.com"
```

## Detection Techniques

### 1. Large Upload Detection

**Indicators:**
- Upload size exceeds threshold (default: 100 MB)
- Rapid data transfer
- Unusual destination

**Configuration:**
```yaml
large_upload:
  bytes: 104857600  # Adjust threshold
  duration: 300
```

### 2. C2 Beaconing Detection

**Indicators:**
- Periodic connections (low jitter)
- Regular intervals (10-300 seconds)
- Small data transfers
- Consistent destination

**How it works:**
- Tracks connection timing
- Calculates interval statistics
- Detects patterns with low jitter

### 3. DNS Tunneling Detection

**Indicators:**
- High DNS query rate (> 10/minute)
- Long subdomain names
- High entropy in queries
- Base64-like patterns

### 4. Unusual Port Detection

**Indicators:**
- Connections to non-standard ports
- Ports above 49152 (dynamic range)
- Known malware ports (1337, 4444, etc.)

### 5. Suspicious Destination Detection

**Indicators:**
- Connections to known malicious IPs
- Tor exit nodes
- Bulletproof hosting providers
- Unusual geographic locations

### 6. Protocol Anomalies

**Indicators:**
- Large UDP transfers (not DNS)
- Unusual protocol usage
- Protocol on wrong port

## Attack Scenarios

### Scenario 1: Data Theft

**Attack**: Employee exfiltrating company data

**Detection**:
```bash
sudo ./bin/egress-auditor analyze --threshold 50000000
```

**Indicators:**
- Large file upload
- Unusual destination
- After-hours activity

### Scenario 2: Malware C2

**Attack**: Malware communicating with C2 server

**Detection**:
```bash
sudo ./bin/egress-auditor beacon --duration 600
```

**Indicators:**
- Periodic beaconing
- Low jitter
- Unknown destination

### Scenario 3: DNS Tunneling

**Attack**: Data exfiltration via DNS

**Detection**:
```bash
sudo ./bin/egress-auditor analyze --duration 300
```

**Indicators:**
- High DNS query rate
- Long encoded subdomains
- Unusual TLDs

### Scenario 4: Insider Threat

**Attack**: Insider slowly exfiltrating data

**Detection**:
```bash
sudo ./bin/egress-auditor report --duration 3600
```

**Indicators:**
- Multiple smaller uploads
- Over extended period
- To personal cloud storage

## Integration

### SIEM Export

Export to SIEM:

```bash
sudo ./bin/egress-auditor report --interface en0 --duration 300 | \
  logger -t egress-auditor -p local1.warn
```

### Automated Response

Block suspicious connections:

```bash
#!/bin/bash
OUTPUT=$(sudo ./bin/egress-auditor analyze --interface en0 --duration 60)

if echo "$OUTPUT" | grep -q "CRITICAL"; then
    # Extract suspicious IP
    SUSPICIOUS_IP=$(echo "$OUTPUT" | grep "Destination:" | awk '{print $2}' | cut -d: -f1)

    # Block with firewall
    sudo pfctl -t blocklist -T add $SUSPICIOUS_IP

    # Alert
    mail -s "CRITICAL: Data Exfiltration Detected" security@example.com <<< "$OUTPUT"
fi
```

### Continuous Monitoring

Run as daemon:

```bash
# systemd service
sudo tee /etc/systemd/system/egress-auditor.service <<EOF
[Unit]
Description=Egress Auditor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/egress-auditor monitor --interface en0
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable egress-auditor
sudo systemctl start egress-auditor
```

## Best Practices

1. **Establish Baseline**: Monitor for 1-2 weeks to understand normal patterns
2. **Tune Thresholds**: Adjust based on your environment
3. **Enable Logging**: Keep detailed logs for forensics
4. **Alert Fatigue**: Start with high severity only
5. **Incident Response**: Have playbooks ready
6. **Regular Reviews**: Check reports daily
7. **Integration**: Feed data to SIEM/SOAR
8. **User Training**: Educate on data handling

## Limitations

1. **Encrypted Traffic**: Cannot inspect encrypted payloads
2. **VPN Traffic**: Limited visibility into VPN tunnels
3. **Legitimate Large Transfers**: May flag backups, updates
4. **Performance**: High-traffic environments may need sampling
5. **Evasion**: Sophisticated attackers may evade detection

## Troubleshooting

### High False Positive Rate

Adjust thresholds:

```yaml
large_upload:
  bytes: 524288000  # Increase to 500 MB

unusual_ports:
  high_port_threshold: 60000  # Increase
```

### Missing Connections

Check interface:

```bash
# List interfaces
ifconfig

# Monitor correct interface
sudo ./bin/egress-auditor monitor --interface en1
```

### Performance Issues

Enable sampling:

```yaml
performance:
  sampling:
    enabled: true
    rate: 0.1  # Sample 10%
```

## Performance

- **CPU Usage**: 5-15% (depends on traffic volume)
- **Memory**: 100-500 MB (depends on connections tracked)
- **Disk**: Logs grow 50-200 MB/day
- **Network Impact**: Passive monitoring only

## Security Considerations

- Requires root/sudo for packet capture
- Does not decrypt traffic (privacy-preserving)
- Stores connection metadata only
- Complies with privacy regulations
- Audit all access to logs

## See Also

- [Shadow IT Detector](shadow-detector.md) - Unauthorized service detection
- [Zero Trust Policies](zero-trust-policies.md) - Policy configuration
- [Architecture](architecture.md) - System design
