# OSX Network Security Tools

Comprehensive security toolkit for OSX and Linux featuring Zero Trust authentication, Shadow IT detection, and data exfiltration prevention.

## Components

### 1. mTLS Certificate Validator (Go)
Validates mutual TLS certificates, monitors certificate rotation, and enforces certificate policies.

**Features:**
- Client/server certificate verification
- Real-time certificate expiration monitoring
- OCSP/CRL validation
- Certificate pinning enforcement
- Automatic rotation detection

### 2. JWT/OAuth Inspector (Python)
Analyzes and validates JWT tokens and OAuth flows in network traffic.

**Features:**
- JWT token extraction from HTTP traffic
- Signature verification (RS256, ES256, HS256)
- Claims inspection and validation
- Token expiration monitoring
- OAuth 2.0 flow analysis

### 3. SSH Key Manager (Python)
Manages SSH keys with automated rotation and auditing.

**Features:**
- Key rotation scheduling
- Usage auditing and logging
- SSH certificate support
- Key strength validation
- Authorized keys management

### 4. Shadow IT Detector (Go)
Discovers unauthorized services, cloud applications, and Shadow IT on your network.

**Features:**
- DNS query monitoring and analysis
- SNI extraction from HTTPS traffic
- Cloud service identification (AWS, Azure, GCP, SaaS)
- Suspicious domain detection
- DNS tunneling detection
- Service fingerprinting

### 5. Egress Auditor / Data Exfiltration Detector (Go)
Monitors outbound connections and detects data exfiltration patterns.

**Features:**
- Connection tracking and analysis
- Large upload detection
- C2 beaconing detection
- DNS tunneling detection
- Unusual port monitoring
- Data transfer rate analysis
- Pattern-based threat detection

### 6. Zero Trust Policy Engine
Context-aware access control and continuous authentication verification.

**Features:**
- Device trust validation
- Location-based policies
- Time-based access control
- Session anomaly detection
- MFA enforcement

## Installation

### Prerequisites

**Go**: 1.21+
```bash
brew install go
```

**Python**: 3.10+
```bash
brew install python@3.10
```

**System Dependencies**:
```bash
# macOS
brew install libpcap openssl

# Linux (Debian/Ubuntu)
sudo apt-get install libpcap-dev libssl-dev
```

### Build

```bash
# Build Go components
cd cmd/zt-validator
go build -o zt-validator

# Install Python dependencies
pip install -r python/requirements.txt
```

## Quick Start

### mTLS Validator
```bash
# Validate specific certificate
./bin/zt-validator validate --cert /path/to/cert.pem

# Display certificate info
./bin/zt-validator info --cert /path/to/cert.pem

# Monitor TLS connections (requires root)
sudo ./bin/zt-validator monitor --interface en0
```

### Shadow IT Detector
```bash
# Monitor DNS queries for unauthorized services
sudo ./bin/shadow-detector dns --interface en0 --duration 300

# Monitor TLS/HTTPS connections
sudo ./bin/shadow-detector tls --interface en0 --duration 300

# Full scan (DNS + TLS)
sudo ./bin/shadow-detector scan --interface en0 --duration 300

# Detect cloud services
sudo ./bin/shadow-detector cloud --interface en0 --duration 60
```

### Egress Auditor
```bash
# Monitor outbound connections
sudo ./bin/egress-auditor monitor --interface en0

# Analyze for data exfiltration
sudo ./bin/egress-auditor analyze --interface en0 --duration 300

# Show top data senders
sudo ./bin/egress-auditor top --interface en0 --duration 60

# Detect C2 beaconing
sudo ./bin/egress-auditor beacon --interface en0 --duration 300

# Generate security report
sudo ./bin/egress-auditor report --interface en0 --duration 300 --output report.txt
```

### JWT Inspector
```bash
# Capture and analyze JWT tokens
sudo python3 python/jwt_inspector/inspector.py --interface en0

# Validate a JWT token
python3 python/jwt_inspector/inspector.py --token "eyJ..."
```

### SSH Key Manager
```bash
# Audit SSH keys
python3 python/ssh_manager/manager.py --audit

# Rotate SSH key
python3 python/ssh_manager/manager.py --rotate ~/.ssh/id_rsa

# Check authorized_keys
python3 python/ssh_manager/manager.py --check-authorized-keys
```

## Configuration

Configuration files are in YAML format in the `configs/` directory:

- `configs/mtls-policies.yaml` - Certificate validation policies
- `configs/jwt-validation.yaml` - JWT validation rules
- `configs/ssh-policies.yaml` - SSH key management policies
- `configs/shadow-it-policies.yaml` - Shadow IT detection policies
- `configs/egress-policies.yaml` - Data exfiltration detection policies
- `configs/zero-trust-policies.yaml` - Zero trust access rules

## Documentation

See `docs/` for detailed documentation:
- [Architecture Overview](docs/architecture.md)
- [mTLS Validator Guide](docs/mtls-validator.md)
- [JWT Inspector Guide](docs/jwt-inspector.md)
- [SSH Manager Guide](docs/ssh-manager.md)
- [Policy Configuration](docs/policies.md)

## Security Considerations

These tools are designed for authorized security testing, monitoring, and defensive security purposes only. Always ensure:

- You have proper authorization before monitoring network traffic
- You comply with your organization's security policies
- You handle sensitive data (certificates, keys, tokens) securely
- You use appropriate access controls for configuration files

## License

MIT License - See LICENSE file for details
