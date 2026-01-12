# mTLS Certificate Validator

The mTLS Certificate Validator is a Go-based tool for validating X.509 certificates, monitoring TLS connections, and enforcing certificate security policies.

## Features

- **Certificate Validation**: Validates certificates against security policies
- **Chain Verification**: Validates certificate chains up to trusted roots
- **OCSP Checking**: Checks certificate revocation status
- **Real-time Monitoring**: Captures and analyzes TLS handshakes (coming soon)
- **Certificate Pinning**: Enforces certificate pinning policies
- **Policy Engine**: Configurable validation policies

## Installation

```bash
cd cmd/zt-validator
go build -o zt-validator
```

## Usage

### Validate a Certificate

```bash
./zt-validator validate --cert /path/to/certificate.pem
```

Example output:
```
✓ Certificate is VALID

Certificate Details:
  Subject: CN=example.com,O=Example Inc
  Issuer: CN=Example CA,O=Example Inc
  Valid From: 2024-01-01 00:00:00 UTC
  Valid Until: 2025-01-01 00:00:00 UTC
  Status: Valid (180 days remaining)
  Signature Algorithm: SHA256-RSA
  DNS Names:
    - example.com
    - www.example.com
```

### Display Certificate Information

```bash
./zt-validator info --cert /path/to/certificate.pem
```

### Check OCSP Status

```bash
./zt-validator ocsp --cert /path/to/certificate.pem --issuer /path/to/issuer.pem
```

### Monitor TLS Connections (Coming Soon)

```bash
sudo ./zt-validator monitor --interface en0
```

This will capture TLS handshakes in real-time and validate certificates against your policies.

## Configuration

Edit `configs/mtls-policies.yaml` to configure validation policies:

```yaml
# Minimum key size in bits
min_key_size: 2048

# Maximum certificate validity period (days)
max_cert_age_days: 825

# Require OCSP responder
require_ocsp: true

# Allow self-signed certificates (dev only)
allow_self_signed: false

# Days before expiration to warn
expiry_warning_days: 30
```

## Validation Policies

### Key Size Requirements

- **RSA**: Minimum 2048 bits (4096 recommended)
- **ECDSA**: Minimum 256 bits (384+ recommended)
- **Ed25519**: Fixed 256 bits

### Certificate Age

Certificates with validity periods exceeding 825 days will trigger warnings (Apple/Google policy).

### Signature Algorithms

**Allowed**:
- SHA256WithRSA
- SHA384WithRSA
- SHA512WithRSA
- ECDSAWithSHA256
- ECDSAWithSHA384
- Ed25519

**Blocked** (deprecated):
- SHA1WithRSA
- MD5WithRSA

### Self-Signed Certificates

Self-signed certificates are rejected by default. Enable `allow_self_signed: true` only for development/testing.

## Security Checks

The validator performs these security checks:

1. **Expiration**: Checks if certificate is expired or expiring soon
2. **Key Size**: Validates key meets minimum size requirements
3. **Chain**: Verifies certificate chain to trusted root CA
4. **Revocation**: Checks OCSP status (if available)
5. **Signature**: Validates signature algorithm is not deprecated
6. **Usage**: Validates key usage and extended key usage
7. **Self-Signed**: Detects and warns about self-signed certificates

## Exit Codes

- `0`: Certificate is valid
- `1`: Validation failed or error occurred

## Examples

### Validate Server Certificate

```bash
# Download server certificate
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -out server.pem

# Validate it
./zt-validator validate --cert server.pem
```

### Check Multiple Certificates

```bash
#!/bin/bash
for cert in certs/*.pem; do
  echo "Validating $cert..."
  ./zt-validator validate --cert "$cert"
  echo ""
done
```

### Automated Monitoring

```bash
# Run in background and log output
sudo ./zt-validator monitor --interface en0 > /var/log/tls-monitor.log 2>&1 &
```

## Troubleshooting

### Permission Denied

Network monitoring requires root privileges:
```bash
sudo ./zt-validator monitor --interface en0
```

### Certificate Chain Validation Fails

Ensure you have the intermediate certificates. Some systems require explicit intermediate cert files.

### OCSP Check Fails

OCSP checking requires network access to the OCSP responder. Firewalls may block OCSP traffic.

## Best Practices

1. **Regular Audits**: Run validation on all certificates monthly
2. **Automate**: Integrate with CI/CD to validate certificates before deployment
3. **Monitor Expiration**: Set up alerts 30 days before expiration
4. **Update Roots**: Keep system root CA store updated
5. **Certificate Pinning**: Use certificate pinning for critical services

## Integration

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Validate Certificates
  run: |
    ./zt-validator validate --cert ./certs/server.pem
```

### Alerting

Parse output and send alerts:
```bash
./zt-validator validate --cert server.pem | grep "INVALID" && \
  curl -X POST https://alerts.example.com/webhook
```

## See Also

- [Zero Trust Policies](zero-trust-policies.md)
- [JWT Inspector](jwt-inspector.md)
- [SSH Manager](ssh-manager.md)
