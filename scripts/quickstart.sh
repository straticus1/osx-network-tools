#!/bin/bash
# Quick Start Script for OSX Network Security Tools

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "OSX Network Security Tools - Quick Start"
echo "========================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

# Check Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed"
    echo "   Install with: brew install go"
    exit 1
else
    GO_VERSION=$(go version | awk '{print $3}')
    echo "✓ Go installed: $GO_VERSION"
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    echo "   Install with: brew install python@3.10"
    exit 1
else
    PYTHON_VERSION=$(python3 --version)
    echo "✓ Python installed: $PYTHON_VERSION"
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed"
    exit 1
else
    echo "✓ pip3 installed"
fi

echo ""
echo "Installing dependencies..."

# Install Go dependencies
cd "$PROJECT_ROOT"
echo "  - Installing Go modules..."
go mod download
echo "  ✓ Go dependencies installed"

# Install Python dependencies
echo "  - Installing Python packages..."
pip3 install -r python/requirements.txt > /dev/null 2>&1
echo "  ✓ Python dependencies installed"

echo ""
echo "Building tools..."

# Create bin directory
mkdir -p bin

# Build Go tools
echo "  - Building mTLS validator..."
cd cmd/zt-validator
go build -o ../../bin/zt-validator
cd ../..
echo "  ✓ Built bin/zt-validator"

# Make Python scripts executable
chmod +x python/jwt_inspector/inspector.py
chmod +x python/ssh_manager/manager.py

echo ""
echo "========================================"
echo "✓ Setup Complete!"
echo "========================================"
echo ""
echo "Available tools:"
echo ""
echo "1. mTLS Certificate Validator (Go)"
echo "   ./bin/zt-validator --help"
echo "   Example: ./bin/zt-validator validate --cert /path/to/cert.pem"
echo ""
echo "2. JWT/OAuth Inspector (Python)"
echo "   python3 python/jwt_inspector/inspector.py --help"
echo "   Example: python3 python/jwt_inspector/inspector.py --token 'eyJ...'"
echo ""
echo "3. SSH Key Manager (Python)"
echo "   python3 python/ssh_manager/manager.py --help"
echo "   Example: python3 python/ssh_manager/manager.py --audit"
echo ""
echo "Quick tests:"
echo "  - Test mTLS validator: ./bin/zt-validator --help"
echo "  - Test JWT inspector:  python3 python/jwt_inspector/inspector.py --help"
echo "  - Test SSH manager:    python3 python/ssh_manager/manager.py --help"
echo ""
echo "Configuration files:"
echo "  - configs/mtls-policies.yaml"
echo "  - configs/jwt-validation.yaml"
echo "  - configs/ssh-policies.yaml"
echo "  - configs/zero-trust-policies.yaml"
echo ""
echo "Documentation:"
echo "  - README.md"
echo "  - docs/mtls-validator.md"
echo "  - docs/jwt-inspector.md"
echo "  - docs/ssh-manager.md"
echo ""
echo "To install system-wide (optional):"
echo "  sudo make install"
echo ""
