#!/usr/bin/env python3
"""
SSH Key Manager
Manages SSH keys with automated rotation, auditing, and security policies
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import stat


class SSHKeyInfo:
    """Information about an SSH key"""

    def __init__(self, path: Path):
        self.path = path
        self.public_key_path = Path(str(path) + '.pub') if not path.name.endswith('.pub') else path
        self.private_key_path = Path(str(path).replace('.pub', '')) if path.name.endswith('.pub') else path
        self.fingerprint = None
        self.key_type = None
        self.key_size = None
        self.comment = None
        self.created = None
        self.modified = None
        self.age_days = None
        self.has_passphrase = None
        self.permissions = None
        self.errors = []
        self.warnings = []

        self._analyze_key()

    def _analyze_key(self):
        """Analyze SSH key and extract information"""
        try:
            # Get file stats
            if self.private_key_path.exists():
                stat_info = self.private_key_path.stat()
                self.modified = datetime.fromtimestamp(stat_info.st_mtime)
                self.age_days = (datetime.now() - self.modified).days
                self.permissions = oct(stat_info.st_mode)[-3:]

                # Check permissions
                if self.permissions != '600':
                    self.warnings.append(f"Insecure permissions: {self.permissions} (should be 600)")

            # Get key info using ssh-keygen
            if self.public_key_path.exists():
                try:
                    result = subprocess.run(
                        ['ssh-keygen', '-l', '-f', str(self.public_key_path)],
                        capture_output=True,
                        text=True,
                        check=True
                    )

                    # Parse output: "2048 SHA256:... comment (RSA)"
                    parts = result.stdout.strip().split()
                    if len(parts) >= 2:
                        self.key_size = int(parts[0])
                        self.fingerprint = parts[1]

                        if len(parts) >= 3:
                            self.comment = ' '.join(parts[2:-1]) if len(parts) > 3 else parts[2]

                        if parts[-1].startswith('(') and parts[-1].endswith(')'):
                            self.key_type = parts[-1][1:-1]

                    # Read public key directly
                    with open(self.public_key_path, 'r') as f:
                        pub_key_content = f.read().strip()
                        if pub_key_content.startswith('ssh-rsa'):
                            self.key_type = 'RSA'
                        elif pub_key_content.startswith('ssh-ed25519'):
                            self.key_type = 'ED25519'
                        elif pub_key_content.startswith('ecdsa-sha2'):
                            self.key_type = 'ECDSA'

                except subprocess.CalledProcessError as e:
                    self.errors.append(f"Failed to read key info: {e}")

            # Check if private key has passphrase
            if self.private_key_path.exists():
                self.has_passphrase = self._check_passphrase()

            # Security checks
            if self.key_type == 'RSA' and self.key_size and self.key_size < 2048:
                self.errors.append(f"Key size {self.key_size} is below minimum recommended (2048)")

            if self.key_type == 'DSA':
                self.errors.append("DSA keys are deprecated and should not be used")

            if self.age_days and self.age_days > 365:
                self.warnings.append(f"Key is {self.age_days} days old (consider rotation)")

            if self.has_passphrase is False:
                self.warnings.append("Private key has no passphrase")

        except Exception as e:
            self.errors.append(f"Analysis failed: {str(e)}")

    def _check_passphrase(self) -> Optional[bool]:
        """Check if private key has a passphrase"""
        try:
            with open(self.private_key_path, 'r') as f:
                content = f.read()
                # Encrypted keys have "ENCRYPTED" in the header
                if 'ENCRYPTED' in content:
                    return True
                # OpenSSH format check
                if 'BEGIN OPENSSH PRIVATE KEY' in content:
                    # If it has no encryption, it will say "none" in the header
                    if 'none' in content[:200]:
                        return False
                    return True
                return False
        except Exception:
            return None

    def to_dict(self) -> Dict:
        """Convert key info to dictionary"""
        return {
            'path': str(self.path),
            'fingerprint': self.fingerprint,
            'key_type': self.key_type,
            'key_size': self.key_size,
            'comment': self.comment,
            'age_days': self.age_days,
            'has_passphrase': self.has_passphrase,
            'permissions': self.permissions,
            'errors': self.errors,
            'warnings': self.warnings
        }


class SSHKeyManager:
    """SSH Key Manager"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.ssh_dir = Path.home() / '.ssh'
        self.max_key_age_days = self.config.get('max_key_age_days', 365)
        self.min_key_size = self.config.get('min_key_size', 2048)
        self.require_passphrase = self.config.get('require_passphrase', True)
        self.backup_dir = Path(self.config.get('backup_dir', self.ssh_dir / 'backups'))

    def audit_keys(self) -> List[SSHKeyInfo]:
        """Audit all SSH keys in ~/.ssh"""
        print(f"Auditing SSH keys in {self.ssh_dir}\n")

        keys = []
        key_files = []

        # Find all private key files (exclude .pub files)
        for item in self.ssh_dir.glob('*'):
            if item.is_file() and not item.name.endswith('.pub'):
                # Skip known_hosts and other non-key files
                if item.name not in ['known_hosts', 'authorized_keys', 'config']:
                    # Check if it looks like a key file
                    try:
                        with open(item, 'r') as f:
                            first_line = f.readline()
                            if 'PRIVATE KEY' in first_line:
                                key_files.append(item)
                    except Exception:
                        pass

        for key_file in key_files:
            key_info = SSHKeyInfo(key_file)
            keys.append(key_info)

        self._print_audit_report(keys)
        return keys

    def _print_audit_report(self, keys: List[SSHKeyInfo]):
        """Print audit report"""
        print(f"{'='*80}")
        print(f"SSH KEY AUDIT REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")

        print(f"Total keys found: {len(keys)}\n")

        for i, key in enumerate(keys, 1):
            print(f"{i}. {key.path.name}")
            print(f"   Path: {key.path}")
            print(f"   Type: {key.key_type or 'Unknown'}")
            if key.key_size:
                print(f"   Size: {key.key_size} bits")
            if key.fingerprint:
                print(f"   Fingerprint: {key.fingerprint}")
            if key.comment:
                print(f"   Comment: {key.comment}")
            if key.age_days is not None:
                print(f"   Age: {key.age_days} days")
            if key.has_passphrase is not None:
                status = "Yes" if key.has_passphrase else "No"
                print(f"   Passphrase: {status}")
            print(f"   Permissions: {key.permissions}")

            if key.errors:
                print("   Errors:")
                for error in key.errors:
                    print(f"     ✗ {error}")

            if key.warnings:
                print("   Warnings:")
                for warning in key.warnings:
                    print(f"     ⚠ {warning}")

            print()

        # Summary
        error_count = sum(len(key.errors) for key in keys)
        warning_count = sum(len(key.warnings) for key in keys)

        print(f"{'='*80}")
        print(f"SUMMARY: {error_count} errors, {warning_count} warnings")
        print(f"{'='*80}\n")

    def rotate_key(self, key_path: Path, key_type: str = 'ed25519', bits: int = 4096, comment: Optional[str] = None):
        """Rotate an SSH key"""
        key_path = Path(key_path)

        print(f"Rotating SSH key: {key_path}\n")

        # Backup existing key
        if key_path.exists():
            backup_path = self._backup_key(key_path)
            print(f"✓ Backed up existing key to: {backup_path}")

        # Generate new key
        new_key_path = key_path
        cmd = ['ssh-keygen', '-t', key_type, '-f', str(new_key_path)]

        if key_type == 'rsa':
            cmd.extend(['-b', str(bits)])

        if comment:
            cmd.extend(['-C', comment])
        else:
            cmd.extend(['-C', f'Generated by SSHKeyManager on {datetime.now().isoformat()}'])

        print(f"\nGenerating new {key_type} key...")
        print(f"Command: {' '.join(cmd)}")
        print("\nYou will be prompted for a passphrase (recommended)")

        try:
            subprocess.run(cmd, check=True)
            print(f"\n✓ New key generated: {new_key_path}")
            print(f"✓ Public key: {new_key_path}.pub")

            # Set proper permissions
            os.chmod(new_key_path, 0o600)
            os.chmod(f"{new_key_path}.pub", 0o644)

            print("\n⚠ IMPORTANT: You need to:")
            print("  1. Add the new public key to authorized servers")
            print("  2. Test the new key before removing the old one")
            print("  3. Update any automation/scripts using this key")

        except subprocess.CalledProcessError as e:
            print(f"\n✗ Key generation failed: {e}", file=sys.stderr)
            sys.exit(1)

    def _backup_key(self, key_path: Path) -> Path:
        """Backup an existing key"""
        self.backup_dir.mkdir(exist_ok=True, parents=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{key_path.name}.{timestamp}"
        backup_path = self.backup_dir / backup_name

        # Copy private key
        subprocess.run(['cp', str(key_path), str(backup_path)], check=True)

        # Copy public key if exists
        pub_key_path = Path(str(key_path) + '.pub')
        if pub_key_path.exists():
            subprocess.run(['cp', str(pub_key_path), str(backup_path) + '.pub'], check=True)

        return backup_path

    def check_authorized_keys(self) -> List[Dict]:
        """Check and audit authorized_keys file"""
        authorized_keys_path = self.ssh_dir / 'authorized_keys'

        if not authorized_keys_path.exists():
            print(f"No authorized_keys file found at {authorized_keys_path}")
            return []

        print(f"Auditing: {authorized_keys_path}\n")

        keys = []
        with open(authorized_keys_path, 'r') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                key_info = self._parse_authorized_key(line, line_no)
                keys.append(key_info)

        self._print_authorized_keys_report(keys)
        return keys

    def _parse_authorized_key(self, line: str, line_no: int) -> Dict:
        """Parse an authorized_keys line"""
        info = {
            'line_no': line_no,
            'raw': line,
            'options': [],
            'key_type': None,
            'key': None,
            'comment': None,
            'warnings': []
        }

        parts = line.split()

        # Check for options (before key type)
        idx = 0
        if parts and not parts[0].startswith('ssh-') and not parts[0].startswith('ecdsa-'):
            # Has options
            info['options'] = parts[0].split(',')
            idx = 1

        if len(parts) > idx:
            info['key_type'] = parts[idx]
            idx += 1

        if len(parts) > idx:
            info['key'] = parts[idx]
            idx += 1

        if len(parts) > idx:
            info['comment'] = ' '.join(parts[idx:])

        # Security checks
        if not info['options']:
            info['warnings'].append("No restrictions configured (consider adding from=, command=, etc.)")

        if info['key_type'] == 'ssh-dss':
            info['warnings'].append("DSA key detected (deprecated)")

        return info

    def _print_authorized_keys_report(self, keys: List[Dict]):
        """Print authorized_keys audit report"""
        print(f"{'='*80}")
        print(f"AUTHORIZED_KEYS AUDIT REPORT")
        print(f"{'='*80}\n")

        print(f"Total authorized keys: {len(keys)}\n")

        for key in keys:
            print(f"Line {key['line_no']}: {key['key_type'] or 'Unknown'}")
            if key['comment']:
                print(f"  Comment: {key['comment']}")
            if key['options']:
                print(f"  Options: {', '.join(key['options'])}")

            if key['warnings']:
                for warning in key['warnings']:
                    print(f"  ⚠ {warning}")

            print()

    def generate_ssh_config(self, hosts: List[Dict], output_path: Optional[Path] = None):
        """Generate SSH config file"""
        if output_path is None:
            output_path = self.ssh_dir / 'config.new'

        print(f"Generating SSH config: {output_path}\n")

        with open(output_path, 'w') as f:
            f.write("# SSH Config generated by SSHKeyManager\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")

            for host in hosts:
                f.write(f"Host {host['name']}\n")
                f.write(f"    HostName {host['hostname']}\n")

                if 'user' in host:
                    f.write(f"    User {host['user']}\n")
                if 'port' in host:
                    f.write(f"    Port {host['port']}\n")
                if 'identity_file' in host:
                    f.write(f"    IdentityFile {host['identity_file']}\n")

                # Security defaults
                f.write("    IdentitiesOnly yes\n")
                f.write("    ServerAliveInterval 60\n")
                f.write("    ServerAliveCountMax 3\n")

                f.write("\n")

        print(f"✓ Config generated: {output_path}")
        print("  Review and rename to 'config' to use it")


def main():
    parser = argparse.ArgumentParser(
        description='SSH Key Manager - Manage SSH keys with security policies'
    )

    parser.add_argument('--audit', action='store_true',
                       help='Audit all SSH keys')
    parser.add_argument('--rotate', metavar='KEY_PATH',
                       help='Rotate an SSH key')
    parser.add_argument('--key-type', default='ed25519',
                       choices=['rsa', 'ed25519', 'ecdsa'],
                       help='Key type for new key (default: ed25519)')
    parser.add_argument('--bits', type=int, default=4096,
                       help='Key size for RSA keys (default: 4096)')
    parser.add_argument('--comment',
                       help='Comment for new key')
    parser.add_argument('--check-authorized-keys', action='store_true',
                       help='Audit authorized_keys file')
    parser.add_argument('--config',
                       help='Configuration file (JSON)')

    args = parser.parse_args()

    # Load configuration
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load config: {e}", file=sys.stderr)

    manager = SSHKeyManager(config)

    if args.audit:
        manager.audit_keys()
    elif args.rotate:
        manager.rotate_key(Path(args.rotate), args.key_type, args.bits, args.comment)
    elif args.check_authorized_keys:
        manager.check_authorized_keys()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
