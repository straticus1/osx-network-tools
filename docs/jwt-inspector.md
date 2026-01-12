# JWT/OAuth Token Inspector

A Python-based tool for capturing, analyzing, and validating JWT (JSON Web Tokens) from network traffic or direct input.

## Features

- **Network Capture**: Capture JWT tokens from live network traffic
- **Token Analysis**: Parse and display JWT header, payload, and claims
- **Signature Validation**: Verify JWT signatures with public keys
- **Policy Enforcement**: Validate tokens against security policies
- **OAuth Flow Detection**: Identify and analyze OAuth 2.0 flows
- **Threat Detection**: Detect insecure tokens (algorithm: none, expired, etc.)

## Installation

```bash
# Install dependencies
pip install -r python/requirements.txt

# Make script executable
chmod +x python/jwt_inspector/inspector.py
```

## Usage

### Analyze a Single Token

```bash
python3 python/jwt_inspector/inspector.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Example output:
```
================================================================================
JWT TOKEN ANALYSIS
================================================================================

Header:
{
  "alg": "RS256",
  "typ": "JWT"
}

Payload:
{
  "iss": "https://auth.example.com",
  "sub": "user@example.com",
  "aud": "api.example.com",
  "exp": 1704067200,
  "iat": 1704063600
}

Claims:
  Algorithm: RS256
  Issuer: https://auth.example.com
  Subject: user@example.com
  Audience: api.example.com
  Issued At: 2024-01-01 00:00:00+00:00
  Expiration: 2024-01-01 01:00:00+00:00 [Valid]
```

### Capture Tokens from Network

```bash
# Capture on default interface (requires root)
sudo python3 python/jwt_inspector/inspector.py --interface en0

# Capture with custom filter
sudo python3 python/jwt_inspector/inspector.py --interface en0 --filter "tcp port 8080"

# Limit capture to 100 packets
sudo python3 python/jwt_inspector/inspector.py --interface en0 --count 100
```

### Use Configuration File

```bash
python3 python/jwt_inspector/inspector.py --config configs/jwt-validation.yaml --token "..."
```

## Configuration

Edit `configs/jwt-validation.yaml`:

```yaml
# Trusted issuers
trusted_issuers:
  - "https://accounts.google.com"
  - "https://auth.yourcompany.com"

# Required claims
required_claims:
  - "iss"
  - "sub"
  - "exp"

# Allowed algorithms
allowed_algorithms:
  - "RS256"
  - "ES256"

# Blocked algorithms
blocked_algorithms:
  - "none"
  - "HS256"
```

## Token Detection

The inspector detects JWT tokens in:

1. **Authorization Headers**: `Authorization: Bearer <token>`
2. **JSON Bodies**: `{"access_token": "<token>"}`
3. **Cookies**: `token=<token>; jwt=<token>`

## Validation

### Algorithm Validation

**Critical Alerts**:
- `algorithm: none` - No signature (immediate rejection)
- Weak algorithms (MD5, SHA1)

**Warnings**:
- Symmetric algorithms (HS256, HS384, HS512) - Shared secret risk

### Expiration Checking

Tokens are checked for:
- Already expired
- Expiring soon (configurable threshold)
- Issued in the future (clock skew)

### Issuer Validation

When `trusted_issuers` is configured:
- Validates `iss` claim matches trusted list
- Alerts on unknown issuers
- Can fetch public keys from JWKS endpoints

### Claims Validation

Checks for:
- Required claims presence
- Standard claims format (exp, iat, nbf as numbers)
- Custom claim requirements

## Security Features

### Threat Detection

The inspector detects:

1. **Algorithm None Attack**: `{"alg": "none"}` - CRITICAL
2. **Expired Tokens**: Token past expiration time
3. **Missing Claims**: Required claims not present
4. **Untrusted Issuers**: Tokens from unknown sources
5. **Long-lived Tokens**: Tokens with excessive validity periods

### Signature Verification

```python
from jwt_inspector import JWTInspector, TokenInfo

inspector = JWTInspector()
token_info = TokenInfo("eyJ...")

# Load public key
with open('public_key.pem', 'r') as f:
    public_key = f.read()

# Validate signature
is_valid = inspector.validate_token(token_info, public_key)
```

## OAuth 2.0 Support

### Flow Detection

Detects common OAuth flows:
- Authorization Code Flow
- Implicit Flow (deprecated)
- Client Credentials Flow
- Refresh Token Flow

### Token Types

Identifies:
- Access tokens
- Refresh tokens
- ID tokens (OpenID Connect)

## Monitoring Mode

Real-time monitoring features:

```bash
sudo python3 python/jwt_inspector/inspector.py --interface en0
```

Output includes:
- Token capture timestamp
- Full token analysis
- Validation results
- Summary statistics

### Summary Statistics

At the end of capture (Ctrl+C):
```
================================================================================
CAPTURE SUMMARY
================================================================================
Total tokens captured: 42
Unique tokens: 38

Algorithms:
  RS256: 35
  HS256: 7

Issuers:
  https://auth.example.com: 30
  https://accounts.google.com: 12

⚠ Expired tokens: 3
```

## Examples

### Validate API Authentication

```bash
# Capture tokens from API server
sudo python3 python/jwt_inspector/inspector.py \
  --interface lo0 \
  --filter "tcp port 8000"
```

### Audit Application Tokens

```bash
# Extract token from curl request
TOKEN=$(curl -s https://api.example.com/auth | jq -r .access_token)

# Analyze it
python3 python/jwt_inspector/inspector.py --token "$TOKEN"
```

### Monitor OAuth Flows

```bash
# Capture during OAuth authentication
sudo python3 python/jwt_inspector/inspector.py \
  --interface en0 \
  --filter "tcp port 443"
```

## Integration

### As a Library

```python
from jwt_inspector import JWTInspector, TokenInfo

# Analyze a token
inspector = JWTInspector(config={
    'trusted_issuers': ['https://auth.example.com'],
    'required_claims': ['sub', 'exp']
})

token_info = inspector.analyze_token_from_string(token_string)

if token_info.errors:
    print(f"Invalid token: {token_info.errors}")
else:
    print(f"Valid token for {token_info.subject}")
```

### With Web Frameworks

```python
from flask import request
from jwt_inspector import TokenInfo

@app.before_request
def validate_jwt():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        token_info = TokenInfo(token)

        if token_info.errors:
            return {'error': 'Invalid token'}, 401
```

## Troubleshooting

### No Tokens Captured

1. Check interface name: `ifconfig` or `ip addr`
2. Verify capture filter: Use `tcp port 80 or tcp port 443`
3. Ensure root privileges: `sudo python3 ...`
4. Check if traffic is HTTPS (tokens encrypted)

### Scapy Not Available

```bash
pip install scapy

# On macOS, may need:
pip install --no-binary :all: scapy
```

### Permission Denied (Packet Capture)

Packet capture requires root:
```bash
sudo python3 python/jwt_inspector/inspector.py --interface en0
```

## Best Practices

1. **Use RS256 or ES256**: Avoid symmetric algorithms (HS256)
2. **Short-lived Tokens**: Keep access token lifetime < 1 hour
3. **Validate Signatures**: Always verify signatures in production
4. **Rotate Keys**: Regularly rotate signing keys
5. **Monitor Usage**: Track token usage patterns
6. **Secure Storage**: Never log tokens in production

## Security Notes

- This tool captures sensitive authentication data
- Use only on networks/systems you own or have authorization to monitor
- Do not log full tokens in production environments
- Protect captured token data appropriately
- Comply with privacy regulations (GDPR, etc.)

## See Also

- [mTLS Validator](mtls-validator.md)
- [SSH Key Manager](ssh-manager.md)
- [Zero Trust Policies](zero-trust-policies.md)
- [JWT.io](https://jwt.io) - JWT debugger
