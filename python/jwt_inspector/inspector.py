#!/usr/bin/env python3
"""
JWT/OAuth Token Inspector
Captures and validates JWT tokens from network traffic
"""

import argparse
import base64
import json
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import hashlib

try:
    from scapy.all import sniff, TCP, IP, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy", file=sys.stderr)

try:
    import jwt
    from jwt import PyJWK, PyJWKClient
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    print("Warning: PyJWT not installed. Install with: pip install PyJWT cryptography", file=sys.stderr)


class TokenInfo:
    """Information extracted from a JWT token"""

    def __init__(self, raw_token: str):
        self.raw_token = raw_token
        self.header = {}
        self.payload = {}
        self.signature = ""
        self.algorithm = "unknown"
        self.issuer = None
        self.subject = None
        self.audience = None
        self.expiration = None
        self.issued_at = None
        self.not_before = None
        self.token_id = None
        self.is_expired = False
        self.is_valid = None
        self.errors = []
        self.warnings = []

        self._parse_token()

    def _parse_token(self):
        """Parse JWT token into header, payload, and signature"""
        parts = self.raw_token.split('.')

        if len(parts) != 3:
            self.errors.append("Invalid JWT format (expected 3 parts)")
            return

        try:
            # Decode header
            header_bytes = base64.urlsafe_b64decode(parts[0] + '==')
            self.header = json.loads(header_bytes)
            self.algorithm = self.header.get('alg', 'unknown')

            # Decode payload
            payload_bytes = base64.urlsafe_b64decode(parts[1] + '==')
            self.payload = json.loads(payload_bytes)

            # Extract signature
            self.signature = parts[2]

            # Extract standard claims
            self.issuer = self.payload.get('iss')
            self.subject = self.payload.get('sub')
            self.audience = self.payload.get('aud')
            self.token_id = self.payload.get('jti')

            # Parse timestamps
            if 'exp' in self.payload:
                self.expiration = datetime.fromtimestamp(self.payload['exp'], tz=timezone.utc)
                self.is_expired = self.expiration < datetime.now(timezone.utc)

            if 'iat' in self.payload:
                self.issued_at = datetime.fromtimestamp(self.payload['iat'], tz=timezone.utc)

            if 'nbf' in self.payload:
                self.not_before = datetime.fromtimestamp(self.payload['nbf'], tz=timezone.utc)

            # Validation checks
            if self.is_expired:
                self.errors.append("Token has expired")

            if self.algorithm == 'none':
                self.errors.append("CRITICAL: Algorithm is 'none' (no signature)")

            if self.algorithm in ['HS256', 'HS384', 'HS512']:
                self.warnings.append("Using symmetric algorithm (shared secret)")

        except Exception as e:
            self.errors.append(f"Failed to parse token: {str(e)}")

    def get_fingerprint(self) -> str:
        """Generate a fingerprint for this token"""
        token_str = f"{self.issuer}:{self.subject}:{self.algorithm}"
        return hashlib.sha256(token_str.encode()).hexdigest()[:16]


class JWTInspector:
    """JWT Token Inspector and Validator"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.captured_tokens = []
        self.unique_tokens = set()
        self.validation_keys = {}
        self.trusted_issuers = self.config.get('trusted_issuers', [])
        self.required_claims = self.config.get('required_claims', [])
        # Never derive accepted algorithms from an untrusted JWT header. The
        # asymmetric default also avoids treating a public key as an HMAC key.
        self.accepted_algorithms = self.config.get(
            'accepted_algorithms',
            ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA']
        )

    def capture_tokens(self, interface: str, count: int = 0, filter_str: str = "tcp port 80 or tcp port 443"):
        """Capture JWT tokens from network traffic"""
        if not SCAPY_AVAILABLE:
            print("Error: scapy is required for packet capture")
            return

        print(f"Starting packet capture on {interface}...")
        print(f"Filter: {filter_str}")
        print("Press Ctrl+C to stop\n")

        def packet_handler(packet):
            tokens = self._extract_tokens_from_packet(packet)
            for token in tokens:
                self._process_token(token)

        try:
            sniff(iface=interface, filter=filter_str, prn=packet_handler, count=count, store=False)
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
            self._print_summary()

    def _extract_tokens_from_packet(self, packet) -> List[str]:
        """Extract JWT tokens from a network packet"""
        tokens = []

        if not packet.haslayer(Raw):
            return tokens

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Look for Authorization header
            auth_match = re.search(r'Authorization:\s*Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', payload)
            if auth_match:
                tokens.append(auth_match.group(1))

            # Look for tokens in JSON bodies
            json_matches = re.findall(r'"(?:token|access_token|id_token)":\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"', payload)
            tokens.extend(json_matches)

            # Look for tokens in cookies
            cookie_matches = re.findall(r'(?:token|jwt)=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', payload)
            tokens.extend(cookie_matches)

        except Exception:
            pass

        return tokens

    def _process_token(self, token: str):
        """Process a captured token"""
        # Check if we've seen this token before
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash in self.unique_tokens:
            return

        self.unique_tokens.add(token_hash)

        token_info = TokenInfo(token)
        self.captured_tokens.append(token_info)

        print(f"\n{'='*80}")
        print(f"Token #{len(self.captured_tokens)} captured at {datetime.now()}")
        print(f"{'='*80}")
        self.print_token_info(token_info)

        # Validate if configured
        if self.trusted_issuers or self.required_claims:
            self.validate_token(token_info)

    def validate_token(self, token_info: TokenInfo, public_key: Optional[str] = None) -> bool:
        """Validate a JWT token"""
        if not JWT_AVAILABLE:
            print("Warning: PyJWT not available for signature validation")
            return False

        is_valid = True

        # Check issuer
        if self.trusted_issuers and token_info.issuer not in self.trusted_issuers:
            token_info.errors.append(f"Untrusted issuer: {token_info.issuer}")
            is_valid = False

        # Check required claims
        for claim in self.required_claims:
            if claim not in token_info.payload:
                token_info.errors.append(f"Missing required claim: {claim}")
                is_valid = False

        # Verify signature if public key provided
        if public_key:
            try:
                if token_info.algorithm not in self.accepted_algorithms:
                    token_info.errors.append(
                        f"Disallowed JWT algorithm: {token_info.algorithm}"
                    )
                    is_valid = False
                    return is_valid
                jwt.decode(
                    token_info.raw_token,
                    public_key,
                    algorithms=self.accepted_algorithms,
                    options={"verify_exp": True}
                )
                print("✓ Signature is valid")
            except jwt.ExpiredSignatureError:
                token_info.errors.append("Token signature expired")
                is_valid = False
            except jwt.InvalidSignatureError:
                token_info.errors.append("Invalid signature")
                is_valid = False
            except Exception as e:
                token_info.errors.append(f"Validation error: {str(e)}")
                is_valid = False

        token_info.is_valid = is_valid
        return is_valid

    def print_token_info(self, token_info: TokenInfo):
        """Print detailed token information"""
        print("\nHeader:")
        print(json.dumps(token_info.header, indent=2))

        print("\nPayload:")
        print(json.dumps(token_info.payload, indent=2))

        print("\nClaims:")
        print(f"  Algorithm: {token_info.algorithm}")
        if token_info.issuer:
            print(f"  Issuer: {token_info.issuer}")
        if token_info.subject:
            print(f"  Subject: {token_info.subject}")
        if token_info.audience:
            print(f"  Audience: {token_info.audience}")
        if token_info.issued_at:
            print(f"  Issued At: {token_info.issued_at}")
        if token_info.expiration:
            status = "EXPIRED" if token_info.is_expired else "Valid"
            print(f"  Expiration: {token_info.expiration} [{status}]")
        if token_info.token_id:
            print(f"  Token ID: {token_info.token_id}")

        if token_info.errors:
            print("\n⚠ Errors:")
            for error in token_info.errors:
                print(f"  ✗ {error}")

        if token_info.warnings:
            print("\n⚠ Warnings:")
            for warning in token_info.warnings:
                print(f"  ! {warning}")

    def _print_summary(self):
        """Print summary of captured tokens"""
        print(f"\n{'='*80}")
        print("CAPTURE SUMMARY")
        print(f"{'='*80}")
        print(f"Total tokens captured: {len(self.captured_tokens)}")
        print(f"Unique tokens: {len(self.unique_tokens)}")

        if self.captured_tokens:
            print("\nToken Statistics:")
            algorithms = {}
            issuers = {}
            expired = 0

            for token in self.captured_tokens:
                algorithms[token.algorithm] = algorithms.get(token.algorithm, 0) + 1
                if token.issuer:
                    issuers[token.issuer] = issuers.get(token.issuer, 0) + 1
                if token.is_expired:
                    expired += 1

            print(f"\nAlgorithms:")
            for alg, count in algorithms.items():
                print(f"  {alg}: {count}")

            if issuers:
                print(f"\nIssuers:")
                for issuer, count in issuers.items():
                    print(f"  {issuer}: {count}")

            if expired > 0:
                print(f"\n⚠ Expired tokens: {expired}")

    def analyze_token_from_string(self, token: str):
        """Analyze a token provided as a string"""
        token_info = TokenInfo(token)
        print(f"{'='*80}")
        print("JWT TOKEN ANALYSIS")
        print(f"{'='*80}")
        self.print_token_info(token_info)

        return token_info


def main():
    parser = argparse.ArgumentParser(
        description='JWT/OAuth Token Inspector - Capture and validate JWT tokens'
    )

    parser.add_argument('-i', '--interface', default='en0',
                       help='Network interface to capture on (default: en0)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-f', '--filter', default='tcp port 80 or tcp port 443',
                       help='BPF filter for packet capture')
    parser.add_argument('-t', '--token',
                       help='Analyze a specific JWT token')
    parser.add_argument('--config',
                       help='Configuration file (YAML)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Load configuration
    config = {}
    if args.config:
        try:
            import yaml
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Failed to load config: {e}", file=sys.stderr)

    inspector = JWTInspector(config)

    if args.token:
        # Analyze single token
        inspector.analyze_token_from_string(args.token)
    else:
        # Capture tokens from network
        if not SCAPY_AVAILABLE:
            print("Error: scapy is required for network capture")
            print("Install with: pip install scapy")
            sys.exit(1)

        inspector.capture_tokens(args.interface, args.count, args.filter)


if __name__ == '__main__':
    main()
