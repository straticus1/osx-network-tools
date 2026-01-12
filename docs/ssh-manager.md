# SSH Key Manager

A Python-based tool for managing SSH keys with automated rotation, security auditing, and policy enforcement.

## Features

- **Key Auditing**: Scan and analyze all SSH keys
- **Automated Rotation**: Rotate keys with backup
- **Security Policies**: Enforce key size, type, and age requirements
- **Passphrase Detection**: Identify unprotected private keys
- **Authorized Keys Management**: Audit and manage authorized_keys
- **Permission Validation**: Check file permissions
- **Usage Tracking**: Monitor key usage and age

## Installation

```bash
# Install dependencies
pip install -r python/requirements.txt

# Make script executable
chmod +x python/ssh_manager/manager.py
```

## Usage

### Audit All SSH Keys

```bash
python3 python/ssh_manager/manager.py --audit
```

Example output:
```
Auditing SSH keys in /Users/ryan/.ssh

================================================================================
SSH KEY AUDIT REPORT - 2024-01-01 12:00:00
================================================================================

Total keys found: 3

1. id_rsa
   Path: /Users/ryan/.ssh/id_rsa
   Type: RSA
   Size: 2048 bits
   Fingerprint: SHA256:abc123...
   Age: 456 days
   Passphrase: No
   Permissions: 600
   Warnings:
     ⚠ Key is 456 days old (consider rotation)
     ⚠ Private key has no passphrase

2. id_ed25519
   Path: /Users/ryan/.ssh/id_ed25519
   Type: ED25519
   Fingerprint: SHA256:def456...
   Age: 30 days
   Passphrase: Yes
   Permissions: 600

================================================================================
SUMMARY: 0 errors, 2 warnings
================================================================================
```

### Rotate an SSH Key

```bash
# Rotate with default type (ed25519)
python3 python/ssh_manager/manager.py --rotate ~/.ssh/id_rsa

# Rotate with specific type
python3 python/ssh_manager/manager.py \
  --rotate ~/.ssh/id_rsa \
  --key-type rsa \
  --bits 4096 \
  --comment "work-laptop-2024"
```

The rotation process:
1. Backs up existing key to `~/.ssh/backups/`
2. Generates new key with specified parameters
3. Prompts for passphrase
4. Sets correct permissions (600)
5. Provides instructions for deployment

### Check Authorized Keys

```bash
python3 python/ssh_manager/manager.py --check-authorized-keys
```

Example output:
```
Auditing: /Users/ryan/.ssh/authorized_keys

================================================================================
AUTHORIZED_KEYS AUDIT REPORT
================================================================================

Total authorized keys: 5

Line 1: ssh-rsa
  Comment: admin@workstation
  ⚠ No restrictions configured (consider adding from=, command=, etc.)

Line 2: ssh-ed25519
  Comment: deploy-bot
  Options: command="/usr/bin/deploy", no-port-forwarding

Line 3: ssh-dss
  Comment: old-key
  ⚠ DSA key detected (deprecated)
  ⚠ No restrictions configured
```

### Use Configuration File

```bash
python3 python/ssh_manager/manager.py --audit --config configs/ssh-policies.yaml
```

## Configuration

Edit `configs/ssh-policies.yaml`:

```yaml
rotation:
  max_key_age_days: 365
  warn_key_age_days: 330
  backup_enabled: true

generation:
  default_key_type: "ed25519"
  min_key_sizes:
    rsa: 2048
  require_passphrase: true

blocked_key_types:
  - "dsa"
  - "ssh-dss"
```

## Key Types

### Recommended: Ed25519

```bash
python3 python/ssh_manager/manager.py \
  --rotate ~/.ssh/id_ed25519 \
  --key-type ed25519
```

**Advantages**:
- Fast (signing/verification)
- Secure (elliptic curve)
- Small keys (256 bits)
- Modern and recommended

### Compatible: RSA

```bash
python3 python/ssh_manager/manager.py \
  --rotate ~/.ssh/id_rsa \
  --key-type rsa \
  --bits 4096
```

**Minimum**: 2048 bits
**Recommended**: 4096 bits

**Use when**:
- Legacy systems require RSA
- Maximum compatibility needed

### Alternative: ECDSA

```bash
python3 python/ssh_manager/manager.py \
  --rotate ~/.ssh/id_ecdsa \
  --key-type ecdsa
```

**Sizes**: 256, 384, or 521 bits

**Note**: Some concerns about NIST curve parameters

### Deprecated: DSA

**DO NOT USE** - Limited to 1024 bits, considered insecure.

## Security Policies

### Key Age

Keys older than policy maximum trigger warnings:
- Default: 365 days
- Warning: 330 days

Rotation recommendations:
- **Critical systems**: 90 days
- **General use**: 365 days
- **Service accounts**: Based on risk assessment

### Key Size Requirements

**Minimum sizes**:
- RSA: 2048 bits
- ECDSA: 256 bits

**Recommended sizes**:
- RSA: 4096 bits
- ECDSA: 521 bits
- Ed25519: 256 bits (fixed)

### Passphrase Protection

Best practices:
- **Always use passphrases** on private keys
- Use strong passphrases (16+ characters)
- Store in secure keychain/agent
- Never commit unencrypted keys

Exception: Automated systems may use unencrypted keys with:
- Strong file permissions (600)
- Restricted authorized_keys options
- Regular rotation
- Monitoring

### File Permissions

**Private keys**: Must be 600 (read/write owner only)
```bash
chmod 600 ~/.ssh/id_rsa
```

**Public keys**: Should be 644 (readable by all)
```bash
chmod 644 ~/.ssh/id_rsa.pub
```

**authorized_keys**: Should be 600
```bash
chmod 600 ~/.ssh/authorized_keys
```

## Authorized Keys Security

### Restricting Keys

Always use restrictions in `authorized_keys`:

```bash
# Restrict by source IP
from="192.168.1.100" ssh-rsa AAAAB3...

# Restrict to specific command
command="/usr/bin/backup.sh" ssh-rsa AAAAB3...

# Multiple restrictions
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,command="..." ssh-rsa AAAAB3...
```

### Common Restrictions

- `from="pattern"`: Restrict source IP/hostname
- `command="cmd"`: Force specific command
- `no-port-forwarding`: Disable SSH tunneling
- `no-X11-forwarding`: Disable X11 forwarding
- `no-agent-forwarding`: Disable agent forwarding
- `no-pty`: Disable PTY allocation

### Audit authorized_keys

```bash
python3 python/ssh_manager/manager.py --check-authorized-keys
```

Checks for:
- Unrestricted keys
- Deprecated key types (DSA)
- Weak keys
- Duplicates

## Key Rotation Process

### 1. Audit Current Keys

```bash
python3 python/ssh_manager/manager.py --audit
```

### 2. Rotate Key

```bash
python3 python/ssh_manager/manager.py --rotate ~/.ssh/id_rsa
```

### 3. Deploy New Public Key

```bash
# Copy new public key to servers
ssh-copy-id -i ~/.ssh/id_rsa.pub user@server

# Or manually
cat ~/.ssh/id_rsa.pub | ssh user@server "cat >> ~/.ssh/authorized_keys"
```

### 4. Test New Key

```bash
# Test connection with new key
ssh -i ~/.ssh/id_rsa user@server

# Test all configured hosts
for host in $(grep "^Host " ~/.ssh/config | awk '{print $2}'); do
  echo "Testing $host..."
  ssh -o ConnectTimeout=5 $host "echo OK"
done
```

### 5. Remove Old Key

Once new key is confirmed working:
```bash
# Remove from servers
ssh user@server "sed -i.bak '/old-key-comment/d' ~/.ssh/authorized_keys"

# Old key is backed up in ~/.ssh/backups/
```

## Integration

### As a Library

```python
from ssh_manager import SSHKeyManager

# Create manager with policies
manager = SSHKeyManager(config={
    'max_key_age_days': 365,
    'min_key_size': 2048
})

# Audit keys
keys = manager.audit_keys()

# Check for issues
for key in keys:
    if key.errors:
        print(f"ERRORS in {key.path}:")
        for error in key.errors:
            print(f"  - {error}")

    if key.warnings:
        print(f"WARNINGS in {key.path}:")
        for warning in key.warnings:
            print(f"  - {warning}")
```

### Automated Rotation

```python
from ssh_manager import SSHKeyManager
from pathlib import Path
from datetime import datetime, timedelta

manager = SSHKeyManager()
keys = manager.audit_keys()

# Rotate keys older than 1 year
for key in keys:
    if key.age_days and key.age_days > 365:
        print(f"Rotating {key.path}...")
        manager.rotate_key(
            key.path,
            key_type='ed25519',
            comment=f'rotated-{datetime.now().isoformat()}'
        )
```

### Scheduled Audits

```bash
#!/bin/bash
# Add to cron: 0 9 * * 1 /path/to/audit-ssh-keys.sh

LOG_FILE="/var/log/ssh-key-audit.log"
ALERT_EMAIL="security@example.com"

python3 python/ssh_manager/manager.py --audit > "$LOG_FILE" 2>&1

# Alert if warnings/errors found
if grep -q "SUMMARY.*[1-9]" "$LOG_FILE"; then
    mail -s "SSH Key Audit Warnings" "$ALERT_EMAIL" < "$LOG_FILE"
fi
```

## Examples

### Generate New Key for Service

```bash
# Generate ed25519 key for CI/CD
python3 python/ssh_manager/manager.py \
  --rotate ~/.ssh/deploy_key \
  --key-type ed25519 \
  --comment "github-actions-deploy"

# Add to server with restrictions
echo "command=\"/usr/bin/deploy.sh\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding $(cat ~/.ssh/deploy_key.pub)" | \
  ssh user@server "cat >> ~/.ssh/authorized_keys"
```

### Audit All Users (Root Required)

```bash
#!/bin/bash
# Audit SSH keys for all users

for home in /home/*; do
    user=$(basename "$home")
    if [ -d "$home/.ssh" ]; then
        echo "=== $user ==="
        sudo -u "$user" python3 python/ssh_manager/manager.py --audit
    fi
done
```

### Generate SSH Config

```python
from ssh_manager import SSHKeyManager

manager = SSHKeyManager()

hosts = [
    {
        'name': 'prod-server',
        'hostname': 'prod.example.com',
        'user': 'deploy',
        'identity_file': '~/.ssh/id_ed25519'
    },
    {
        'name': 'staging',
        'hostname': 'staging.example.com',
        'user': 'deploy',
        'port': 2222,
        'identity_file': '~/.ssh/id_ed25519'
    }
]

manager.generate_ssh_config(hosts)
```

## Best Practices

1. **Use Ed25519**: Default to ed25519 for new keys
2. **Always Use Passphrases**: Protect private keys with strong passphrases
3. **Regular Rotation**: Rotate keys annually (or more frequently for sensitive systems)
4. **Restrict authorized_keys**: Always use `from=` and `command=` restrictions
5. **Audit Regularly**: Run audits monthly
6. **Backup Keys**: Keep secure backups before rotation
7. **Test Before Removing**: Always test new keys before removing old ones
8. **Monitor Usage**: Track which keys are actually used
9. **Remove Unused Keys**: Delete old/unused authorized keys
10. **Use SSH Certificates**: Consider SSH certificates for large deployments

## Troubleshooting

### Permission Denied Errors

```bash
# Fix private key permissions
chmod 600 ~/.ssh/id_rsa

# Fix directory permissions
chmod 700 ~/.ssh

# Fix authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### ssh-keygen Not Found

Ensure OpenSSH is installed:
```bash
# macOS (should be pre-installed)
which ssh-keygen

# Linux
sudo apt-get install openssh-client  # Debian/Ubuntu
sudo yum install openssh-clients      # RHEL/CentOS
```

### Key Rotation Fails

If rotation fails:
1. Old key is safe (backed up)
2. Check backup: `ls ~/.ssh/backups/`
3. Restore if needed: `cp ~/.ssh/backups/id_rsa.* ~/.ssh/`

## See Also

- [mTLS Validator](mtls-validator.md)
- [JWT Inspector](jwt-inspector.md)
- [Zero Trust Policies](zero-trust-policies.md)
- [SSH Best Practices](https://www.ssh.com/academy/ssh/keygen)
