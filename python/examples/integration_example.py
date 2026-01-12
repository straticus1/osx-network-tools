#!/usr/bin/env python3
"""
Example: Using all Zero Trust tools together
Demonstrates programmatic usage of SSH Manager and JWT Inspector
"""

import sys
import os
from pathlib import Path

# Add parent directory to path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from ssh_manager import SSHKeyManager, SSHKeyInfo
from jwt_inspector import JWTInspector, TokenInfo


def audit_ssh_security():
    """Perform comprehensive SSH security audit"""
    print("=" * 80)
    print("SSH SECURITY AUDIT")
    print("=" * 80)
    print()

    # Create SSH manager with custom policies
    manager = SSHKeyManager(config={
        'max_key_age_days': 365,
        'min_key_size': 2048,
        'require_passphrase': True
    })

    # Audit all SSH keys
    keys = manager.audit_keys()

    # Analyze results
    critical_issues = []
    warnings = []

    for key in keys:
        if key.errors:
            critical_issues.extend([
                f"{key.path.name}: {error}" for error in key.errors
            ])

        if key.warnings:
            warnings.extend([
                f"{key.path.name}: {warning}" for warning in key.warnings
            ])

    # Report findings
    print("\nFINDINGS:")
    if critical_issues:
        print(f"\n❌ {len(critical_issues)} Critical Issues:")
        for issue in critical_issues[:5]:  # Show first 5
            print(f"  - {issue}")

    if warnings:
        print(f"\n⚠  {len(warnings)} Warnings:")
        for warning in warnings[:5]:  # Show first 5
            print(f"  - {warning}")

    if not critical_issues and not warnings:
        print("✓ No issues found - SSH configuration is secure!")

    return len(critical_issues) == 0


def analyze_jwt_token(token: str):
    """Analyze a JWT token with security policies"""
    print("\n" + "=" * 80)
    print("JWT TOKEN ANALYSIS")
    print("=" * 80)
    print()

    # Create inspector with security policies
    inspector = JWTInspector(config={
        'trusted_issuers': [
            'https://accounts.google.com',
            'https://auth.yourcompany.com'
        ],
        'required_claims': ['iss', 'sub', 'exp', 'iat']
    })

    # Analyze token
    token_info = inspector.analyze_token_from_string(token)

    # Security assessment
    security_score = 100

    if token_info.errors:
        print(f"\n❌ {len(token_info.errors)} Security Errors:")
        for error in token_info.errors:
            print(f"  - {error}")
            security_score -= 30

    if token_info.warnings:
        print(f"\n⚠  {len(token_info.warnings)} Security Warnings:")
        for warning in token_info.warnings:
            print(f"  - {warning}")
            security_score -= 10

    # Algorithm assessment
    if token_info.algorithm in ['RS256', 'ES256', 'EdDSA']:
        print(f"\n✓ Strong algorithm: {token_info.algorithm}")
    elif token_info.algorithm in ['HS256', 'HS384', 'HS512']:
        print(f"\n⚠  Symmetric algorithm: {token_info.algorithm} (shared secret)")
        security_score -= 20
    elif token_info.algorithm == 'none':
        print(f"\n❌ CRITICAL: No signature algorithm!")
        security_score = 0

    # Expiration check
    if token_info.expiration:
        if token_info.is_expired:
            print(f"❌ Token is EXPIRED")
            security_score = 0
        else:
            print(f"✓ Token valid until {token_info.expiration}")

    print(f"\nSecurity Score: {max(0, security_score)}/100")

    return security_score > 50


def zero_trust_validation():
    """Perform zero trust validation checks"""
    print("\n" + "=" * 80)
    print("ZERO TRUST VALIDATION")
    print("=" * 80)
    print()

    checks = {
        'SSH Keys Secure': False,
        'Certificates Valid': False,
        'Tokens Validated': False,
        'Policies Enforced': True
    }

    # SSH validation
    print("1. Validating SSH security...")
    try:
        manager = SSHKeyManager()
        keys = manager.audit_keys()

        # Check for critical issues
        has_critical = any(key.errors for key in keys)
        checks['SSH Keys Secure'] = not has_critical

        if checks['SSH Keys Secure']:
            print("   ✓ SSH keys are secure")
        else:
            print("   ❌ SSH keys have security issues")

    except Exception as e:
        print(f"   ⚠  Could not validate SSH: {e}")

    # Certificate validation (would use Go validator)
    print("\n2. Validating certificates...")
    print("   ⚠  Manual certificate validation required")
    print("   Run: ./bin/zt-validator validate --cert <path>")

    # Overall assessment
    print("\n" + "=" * 80)
    print("ZERO TRUST STATUS")
    print("=" * 80)

    for check, passed in checks.items():
        status = "✓" if passed else "❌"
        print(f"{status} {check}")

    all_passed = all(checks.values())
    print()
    if all_passed:
        print("✓ Zero Trust posture is STRONG")
    else:
        print("⚠  Zero Trust posture needs improvement")

    return all_passed


def demonstrate_key_rotation():
    """Demonstrate automated key rotation logic"""
    print("\n" + "=" * 80)
    print("KEY ROTATION RECOMMENDATION")
    print("=" * 80)
    print()

    manager = SSHKeyManager(config={'max_key_age_days': 365})
    keys = manager.audit_keys()

    keys_to_rotate = []
    for key in keys:
        if key.age_days and key.age_days > 365:
            keys_to_rotate.append((key.path, key.age_days))

    if keys_to_rotate:
        print(f"Found {len(keys_to_rotate)} keys requiring rotation:\n")
        for path, age in keys_to_rotate:
            print(f"  - {path.name} (age: {age} days)")

        print("\nTo rotate keys:")
        for path, _ in keys_to_rotate:
            print(f"  python3 python/ssh_manager/manager.py --rotate {path}")
    else:
        print("✓ All keys are within rotation policy")


def main():
    """Main integration example"""
    print("=" * 80)
    print("ZERO TRUST SECURITY TOOLS - INTEGRATION EXAMPLE")
    print("=" * 80)
    print()

    # 1. SSH Security Audit
    ssh_secure = audit_ssh_security()

    # 2. JWT Token Analysis (example token)
    example_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiYXVkIjoiYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxOTAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDB9.fake_signature"

    if len(sys.argv) > 1:
        example_token = sys.argv[1]

    token_valid = analyze_jwt_token(example_token)

    # 3. Zero Trust Validation
    zero_trust_ok = zero_trust_validation()

    # 4. Key Rotation Recommendations
    demonstrate_key_rotation()

    # Final Report
    print("\n" + "=" * 80)
    print("FINAL SECURITY REPORT")
    print("=" * 80)
    print()

    print("Security Checks:")
    print(f"  {'✓' if ssh_secure else '❌'} SSH Security")
    print(f"  {'✓' if token_valid else '❌'} JWT Validation")
    print(f"  {'✓' if zero_trust_ok else '❌'} Zero Trust Posture")
    print()

    all_secure = ssh_secure and token_valid and zero_trust_ok

    if all_secure:
        print("✓ Security posture is STRONG")
        return 0
    else:
        print("⚠  Security improvements needed")
        print("\nRecommended actions:")
        if not ssh_secure:
            print("  1. Address SSH key security issues")
        if not token_valid:
            print("  2. Review JWT token security")
        if not zero_trust_ok:
            print("  3. Implement zero trust policies")

        return 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
