#!/bin/bash
# Complete Security Audit Script
# Runs all zero trust validation tools and generates a report

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="${PROJECT_ROOT}/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/security-audit-${TIMESTAMP}.txt"

# Create reports directory
mkdir -p "$REPORT_DIR"

echo "========================================"
echo "Zero Trust Security Audit"
echo "========================================"
echo "Date: $(date)"
echo "Report: $REPORT_FILE"
echo ""

# Initialize report
{
    echo "========================================"
    echo "ZERO TRUST SECURITY AUDIT REPORT"
    echo "========================================"
    echo "Generated: $(date)"
    echo "System: $(uname -s) $(uname -r)"
    echo "Hostname: $(hostname)"
    echo ""
} > "$REPORT_FILE"

# Function to add section to report
add_section() {
    local title="$1"
    {
        echo ""
        echo "========================================"
        echo "$title"
        echo "========================================"
        echo ""
    } >> "$REPORT_FILE"
}

# Function to run command and add output to report
run_check() {
    local description="$1"
    shift
    echo "Running: $description..."
    {
        echo "Command: $*"
        echo ""
        "$@" 2>&1 || echo "❌ Check failed with exit code $?"
        echo ""
    } >> "$REPORT_FILE"
}

# 1. SSH Key Audit
add_section "1. SSH KEY SECURITY AUDIT"
run_check "SSH key audit" \
    python3 "${PROJECT_ROOT}/python/ssh_manager/manager.py" --audit

# 2. Authorized Keys Check
add_section "2. AUTHORIZED KEYS AUDIT"
run_check "Authorized keys check" \
    python3 "${PROJECT_ROOT}/python/ssh_manager/manager.py" --check-authorized-keys

# 3. Certificate Validation (if certificates exist)
add_section "3. CERTIFICATE VALIDATION"
if [ -d "${HOME}/.certs" ] || [ -d "/etc/ssl/certs" ]; then
    echo "Checking for certificates to validate..."

    # Example: validate a certificate if it exists
    if [ -f "${HOME}/.certs/client.pem" ]; then
        run_check "Client certificate validation" \
            "${PROJECT_ROOT}/bin/zt-validator" validate --cert "${HOME}/.certs/client.pem"
    fi

    # Check system certificates (example)
    if command -v openssl &> /dev/null; then
        echo "System has OpenSSL installed" >> "$REPORT_FILE"
    fi
else
    echo "No certificate directories found" >> "$REPORT_FILE"
fi

# 4. JWT Token Analysis (if any tokens provided)
add_section "4. JWT TOKEN ANALYSIS"
if [ -n "$JWT_TOKEN" ]; then
    run_check "JWT token validation" \
        python3 "${PROJECT_ROOT}/python/jwt_inspector/inspector.py" --token "$JWT_TOKEN"
else
    echo "No JWT token provided for analysis" >> "$REPORT_FILE"
    echo "Set JWT_TOKEN environment variable to analyze a token" >> "$REPORT_FILE"
fi

# 5. System Security Checks
add_section "5. SYSTEM SECURITY CHECKS"

{
    echo "Firewall Status:"
    if command -v /usr/libexec/ApplicationFirewall/socketfilterfw &> /dev/null; then
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate || echo "Unable to check firewall"
    else
        echo "Firewall check not available on this system"
    fi
    echo ""

    echo "SSH Configuration:"
    if [ -f "${HOME}/.ssh/config" ]; then
        echo "SSH config file exists"
        grep -E "^(Host |IdentitiesOnly|StrictHostKeyChecking)" "${HOME}/.ssh/config" 2>/dev/null || echo "No security directives found"
    else
        echo "No SSH config file found"
    fi
    echo ""

    echo "Open SSH Connections:"
    netstat -an | grep "\.22 " | grep ESTABLISHED || echo "No active SSH connections"
    echo ""

} >> "$REPORT_FILE"

# 6. Network Security
add_section "6. NETWORK SECURITY"

{
    echo "Active Network Interfaces:"
    ifconfig | grep "^[a-z]" | awk '{print $1}'
    echo ""

    echo "Listening Services:"
    if command -v lsof &> /dev/null; then
        sudo lsof -i -P | grep LISTEN | head -20
    else
        echo "lsof not available"
    fi
    echo ""

} >> "$REPORT_FILE"

# 7. File Permissions Audit
add_section "7. SENSITIVE FILE PERMISSIONS"

{
    echo "SSH Directory Permissions:"
    ls -la "${HOME}/.ssh" 2>/dev/null || echo "No .ssh directory"
    echo ""

    echo "Certificate Directory Permissions:"
    ls -la "${HOME}/.certs" 2>/dev/null || echo "No .certs directory"
    echo ""

} >> "$REPORT_FILE"

# Generate summary
add_section "8. AUDIT SUMMARY"

{
    echo "Audit completed at: $(date)"
    echo ""

    # Count issues
    ERROR_COUNT=$(grep -c "❌\|ERROR\|CRITICAL" "$REPORT_FILE" || echo "0")
    WARNING_COUNT=$(grep -c "⚠\|WARNING" "$REPORT_FILE" || echo "0")

    echo "Issues Found:"
    echo "  - Errors: $ERROR_COUNT"
    echo "  - Warnings: $WARNING_COUNT"
    echo ""

    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "❌ CRITICAL ISSUES DETECTED - Immediate attention required"
        echo ""
        echo "Critical Issues:"
        grep "❌\|ERROR\|CRITICAL" "$REPORT_FILE" | head -10
    elif [ "$WARNING_COUNT" -gt 0 ]; then
        echo "⚠  Warnings detected - Review recommended"
    else
        echo "✓ No critical issues detected"
    fi
    echo ""

    echo "Recommendations:"
    echo "  1. Review all warnings and errors above"
    echo "  2. Rotate SSH keys older than 365 days"
    echo "  3. Add passphrases to unprotected SSH keys"
    echo "  4. Enable firewall if disabled"
    echo "  5. Review and restrict authorized_keys"
    echo "  6. Validate all certificates before expiration"
    echo "  7. Review listening services and close unnecessary ports"
    echo ""

} >> "$REPORT_FILE"

# Display summary to console
echo ""
echo "========================================"
echo "Audit Complete!"
echo "========================================"
echo ""
grep "Issues Found:" -A 10 "$REPORT_FILE"
echo ""
echo "Full report: $REPORT_FILE"
echo ""

# Optionally view the report
if [ -t 1 ]; then
    read -p "View full report now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        less "$REPORT_FILE"
    fi
fi
