# Architecture Overview

This document describes the architecture and design philosophy of the OSX Network Security Tools suite.

## Design Philosophy

### Zero Trust Principles

The tools are built around core zero trust principles:

1. **Verify Explicitly**: Always authenticate and authorize based on all available data
2. **Least Privilege Access**: Limit user access with just-in-time and just-enough-access
3. **Assume Breach**: Minimize blast radius and verify end-to-end encryption

### Multi-Language Approach

The toolkit uses both Go and Python strategically:

- **Go**: Performance-critical components (packet capture, certificate validation)
- **Python**: Flexibility and rapid development (analysis, reporting, integration)

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OSX Network Security Tools               │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌──────────────┐   ┌──────────────┐
│ mTLS Validator│   │JWT Inspector │   │ SSH Manager  │
│     (Go)      │   │   (Python)   │   │   (Python)   │
└───────────────┘   └──────────────┘   └──────────────┘
        │                   │                   │
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────────────────────────────────────────────┐
│              Shared Configuration Engine              │
│         (configs/zero-trust-policies.yaml)            │
└───────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. mTLS Certificate Validator (Go)

```
┌─────────────────────────────────────────┐
│         zt-validator CLI                │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
┌──────────────┐    ┌────────────────┐
│ Validator    │    │ Packet Capture │
│ Engine       │    │ (gopacket)     │
└──────┬───────┘    └────────┬───────┘
       │                     │
       │    ┌────────────────┘
       │    │
       ▼    ▼
┌─────────────────────────┐
│  Certificate Analysis   │
│  - X.509 Parsing        │
│  - Chain Validation     │
│  - OCSP Checking        │
│  - Policy Enforcement   │
└─────────────────────────┘
```

**Key Components**:

- **Validator Engine** (`pkg/mtls/validator.go`):
  - Certificate parsing and validation
  - Chain verification
  - Policy enforcement
  - OCSP/CRL checking

- **CLI** (`cmd/zt-validator/main.go`):
  - Command-line interface using Cobra
  - Subcommands: validate, monitor, ocsp, info

**Design Decisions**:

- **Go for Performance**: Certificate validation and packet capture are CPU-intensive
- **Native Libraries**: Uses Go's crypto/x509 for certificate handling
- **Extensible Policies**: YAML configuration for validation rules

### 2. JWT/OAuth Inspector (Python)

```
┌─────────────────────────────────────────┐
│      JWT Inspector CLI/API              │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
┌──────────────┐    ┌────────────────┐
│ Token Parser │    │ Network Capture│
│ (PyJWT)      │    │ (Scapy)        │
└──────┬───────┘    └────────┬───────┘
       │                     │
       │    ┌────────────────┘
       │    │
       ▼    ▼
┌─────────────────────────┐
│  Token Analysis         │
│  - Header Parsing       │
│  - Claims Validation    │
│  - Signature Verify     │
│  - Policy Checks        │
└─────────────────────────┘
```

**Key Components**:

- **Token Parser** (`python/jwt_inspector/inspector.py`):
  - JWT decoding and parsing
  - Claims extraction
  - Signature verification
  - Policy validation

- **Network Capture**:
  - Uses Scapy for packet capture
  - Extracts JWT tokens from HTTP traffic
  - Monitors Authorization headers, cookies, JSON bodies

**Design Decisions**:

- **Python for Flexibility**: JWT handling benefits from Python's string processing
- **PyJWT Library**: Industry-standard JWT library
- **Real-time Analysis**: Stream processing for network capture

### 3. SSH Key Manager (Python)

```
┌─────────────────────────────────────────┐
│       SSH Manager CLI                   │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
┌──────────────┐    ┌────────────────┐
│ Key Analyzer │    │ Key Generator  │
└──────┬───────┘    └────────┬───────┘
       │                     │
       │    ┌────────────────┘
       │    │
       ▼    ▼
┌─────────────────────────┐
│  SSH Operations         │
│  - Key Auditing         │
│  - Rotation             │
│  - Auth Keys Mgmt       │
│  - Policy Enforcement   │
└─────────────────────────┘
```

**Key Components**:

- **Key Analyzer** (`python/ssh_manager/manager.py`):
  - SSH key inspection
  - Fingerprint calculation
  - Age tracking
  - Security validation

- **Key Generator**:
  - Uses ssh-keygen subprocess
  - Automated rotation with backup
  - Policy-compliant generation

**Design Decisions**:

- **Python for Scripting**: SSH operations are primarily file-based
- **ssh-keygen Integration**: Leverages system OpenSSH tools
- **Policy-Driven**: All operations follow configured policies

## Configuration System

### Layered Configuration

```
┌─────────────────────────────────────────┐
│    Zero Trust Policies (Master)         │
│    configs/zero-trust-policies.yaml     │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
┌──────────────┐    ┌────────────────┐
│ Component    │    │  Component     │
│ Configs      │    │  Configs       │
│              │    │                │
│ mtls-        │    │ jwt-           │
│ policies     │    │ validation     │
│              │    │                │
│ ssh-         │    │                │
│ policies     │    │                │
└──────────────┘    └────────────────┘
```

**Configuration Hierarchy**:

1. **Master Policy** (`zero-trust-policies.yaml`):
   - Overall security posture
   - Cross-component rules
   - Global settings

2. **Component Policies**:
   - Tool-specific settings
   - Validation rules
   - Thresholds and limits

3. **Local Overrides** (optional):
   - User-specific settings
   - Development vs. production
   - Environment-specific rules

## Data Flow

### Certificate Validation Flow

```
Certificate File
       │
       ▼
┌────────────┐
│   Parse    │
│   X.509    │
└─────┬──────┘
      │
      ▼
┌────────────┐     ┌──────────────┐
│  Validate  │────►│ Check Policy │
│   Chain    │     │   Rules      │
└─────┬──────┘     └──────┬───────┘
      │                   │
      ▼                   ▼
┌────────────┐     ┌──────────────┐
│   OCSP     │     │   Generate   │
│   Check    │     │   Report     │
└─────┬──────┘     └──────┬───────┘
      │                   │
      └──────────┬────────┘
                 ▼
         Validation Result
```

### JWT Token Flow

```
Network Traffic / Token String
       │
       ▼
┌────────────┐
│  Extract   │
│   Token    │
└─────┬──────┘
      │
      ▼
┌────────────┐     ┌──────────────┐
│   Decode   │     │   Verify     │
│   JWT      │────►│  Signature   │
└─────┬──────┘     └──────┬───────┘
      │                   │
      ▼                   ▼
┌────────────┐     ┌──────────────┐
│  Validate  │     │   Check      │
│   Claims   │────►│   Policy     │
└─────┬──────┘     └──────┬───────┘
      │                   │
      └──────────┬────────┘
                 ▼
          Token Analysis
```

### SSH Key Flow

```
SSH Directory Scan
       │
       ▼
┌────────────┐
│  Identify  │
│    Keys    │
└─────┬──────┘
      │
      ▼
┌────────────┐     ┌──────────────┐
│  Extract   │     │   Check      │
│   Info     │────►│  Permissions │
└─────┬──────┘     └──────┬───────┘
      │                   │
      ▼                   ▼
┌────────────┐     ┌──────────────┐
│  Validate  │     │   Compare    │
│   Type     │────►│   Policy     │
└─────┬──────┘     └──────┬───────┘
      │                   │
      └──────────┬────────┘
                 ▼
           Audit Report
```

## Security Considerations

### Privilege Requirements

- **mTLS Validator**: Requires root for packet capture (monitor mode)
- **JWT Inspector**: Requires root for network capture
- **SSH Manager**: Runs as regular user (accesses user's .ssh)

### Data Protection

1. **Sensitive Data Handling**:
   - Never log full JWT tokens in production
   - Certificate private keys never accessed
   - SSH private keys read permissions only

2. **Memory Safety**:
   - Go provides memory safety for crypto operations
   - Python uses secure libraries (cryptography, PyJWT)

3. **File Permissions**:
   - Config files: 644 (readable)
   - Report files: 600 (user-only)
   - Backup keys: 600 (user-only)

### Threat Model

**Protected Against**:
- Expired certificates
- Weak cryptographic algorithms
- Insecure JWT tokens (alg: none)
- Unprotected SSH keys
- Deprecated key types
- Missing security controls

**Not Protected Against**:
- Compromised CA roots
- Stolen credentials
- Social engineering
- Physical access attacks

## Extension Points

### Adding New Validators

1. Create validator in appropriate language
2. Implement standard interface
3. Add configuration schema
4. Integrate with reporting

### Custom Policies

1. Extend YAML configuration
2. Implement policy checks
3. Add to validation pipeline
4. Update documentation

### Integration Hooks

1. **Pre-commit Hooks**: Validate certificates/keys before commit
2. **CI/CD Pipeline**: Automated security checks
3. **Monitoring Systems**: Export metrics/alerts
4. **SIEM Integration**: Send events to security systems

## Performance Characteristics

### mTLS Validator

- **Certificate Validation**: < 10ms per certificate
- **Chain Validation**: < 50ms per chain
- **OCSP Check**: 100-500ms (network dependent)

### JWT Inspector

- **Token Parsing**: < 1ms per token
- **Signature Verification**: 1-5ms per token
- **Network Capture**: Real-time (no buffering delay)

### SSH Manager

- **Key Scan**: < 100ms for typical ~/.ssh directory
- **Key Generation**: 100ms-1s (depending on type/size)
- **Audit Report**: < 500ms for 10-20 keys

## Future Enhancements

### Planned Features

1. **Real-time Monitoring Dashboard**:
   - Web-based UI
   - Live certificate/token monitoring
   - Alert management

2. **Certificate Transparency Integration**:
   - Automated CT log queries
   - Certificate monitoring
   - Anomaly detection

3. **SSH Certificate Support**:
   - SSH-CERT generation
   - Certificate authority management
   - Short-lived certificates

4. **Policy as Code**:
   - Programmatic policy definition
   - Version control integration
   - Policy testing framework

5. **Machine Learning**:
   - Anomaly detection
   - Risk scoring
   - Behavioral analysis

### Integration Roadmap

- Kubernetes admission controller
- AWS/Azure/GCP cloud integration
- HashiCorp Vault integration
- Okta/Auth0 integration
- Prometheus metrics export

## Contributing

See main README for contribution guidelines.

## References

- [NIST Zero Trust Architecture (SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [JWT Best Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)
- [X.509 Certificate Standard](https://tools.ietf.org/html/rfc5280)
- [SSH Protocol](https://tools.ietf.org/html/rfc4251)
