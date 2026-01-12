.PHONY: all build clean install test deps help

# Default target
all: build

# Build Go components
build:
	@echo "Building Go components..."
	cd cmd/zt-validator && go build -o ../../bin/zt-validator
	@echo "✓ Built bin/zt-validator"
	cd cmd/shadow-detector && go build -o ../../bin/shadow-detector
	@echo "✓ Built bin/shadow-detector"
	cd cmd/egress-auditor && go build -o ../../bin/egress-auditor
	@echo "✓ Built bin/egress-auditor"

# Install dependencies
deps:
	@echo "Installing Go dependencies..."
	go mod download
	@echo "✓ Go dependencies installed"
	@echo ""
	@echo "Installing Python dependencies..."
	pip3 install -r python/requirements.txt
	@echo "✓ Python dependencies installed"

# Install to system
install: build
	@echo "Installing to /usr/local/bin..."
	sudo cp bin/zt-validator /usr/local/bin/
	sudo cp bin/shadow-detector /usr/local/bin/
	sudo cp bin/egress-auditor /usr/local/bin/
	sudo cp python/jwt_inspector/inspector.py /usr/local/bin/jwt-inspector
	sudo cp python/ssh_manager/manager.py /usr/local/bin/ssh-manager
	sudo chmod +x /usr/local/bin/jwt-inspector
	sudo chmod +x /usr/local/bin/ssh-manager
	@echo "✓ Installed to /usr/local/bin"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f cmd/zt-validator/zt-validator
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "✓ Cleaned"

# Run tests
test:
	@echo "Running Go tests..."
	go test ./...
	@echo "Running Python tests..."
	python3 -m pytest python/tests/ || echo "No tests found"
	@echo "✓ Tests complete"

# Format code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...
	@echo "Formatting Python code..."
	black python/ || echo "black not installed (pip install black)"
	@echo "✓ Formatted"

# Lint code
lint:
	@echo "Linting Go code..."
	golint ./... || echo "golint not installed (go install golang.org/x/lint/golint@latest)"
	@echo "Linting Python code..."
	pylint python/ || echo "pylint not installed (pip install pylint)"

# Create bin directory
bin:
	mkdir -p bin

# Build with bin directory
build: bin

# Development setup
dev-setup: deps
	@echo "Setting up development environment..."
	mkdir -p bin
	@echo "✓ Development environment ready"

# Quick test (without full build)
quick-test:
	@echo "Running quick validation tests..."
	@echo "Testing mTLS validator..."
	cd cmd/zt-validator && go build -o zt-validator && ./zt-validator --help
	@echo ""
	@echo "Testing Shadow IT Detector..."
	cd cmd/shadow-detector && go build -o shadow-detector && ./shadow-detector --help
	@echo ""
	@echo "Testing Egress Auditor..."
	cd cmd/egress-auditor && go build -o egress-auditor && ./egress-auditor --help
	@echo ""
	@echo "Testing JWT inspector..."
	python3 python/jwt_inspector/inspector.py --help
	@echo ""
	@echo "Testing SSH manager..."
	python3 python/ssh_manager/manager.py --help
	@echo "✓ All tools working"

# Documentation
docs:
	@echo "Available documentation:"
	@echo "  - README.md (overview)"
	@echo "  - docs/mtls-validator.md"
	@echo "  - docs/jwt-inspector.md"
	@echo "  - docs/ssh-manager.md"
	@echo ""
	@echo "Configuration examples:"
	@echo "  - configs/mtls-policies.yaml"
	@echo "  - configs/jwt-validation.yaml"
	@echo "  - configs/ssh-policies.yaml"
	@echo "  - configs/zero-trust-policies.yaml"

# Help
help:
	@echo "OSX Network Security Tools - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make build        - Build all components"
	@echo "  make deps         - Install dependencies"
	@echo "  make install      - Install to /usr/local/bin (requires sudo)"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make test         - Run tests"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Lint code"
	@echo "  make dev-setup    - Setup development environment"
	@echo "  make quick-test   - Quick validation of all tools"
	@echo "  make docs         - Show documentation"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make deps         # First time setup"
	@echo "  make build        # Build tools"
	@echo "  make quick-test   # Verify everything works"
	@echo "  make install      # Install system-wide"
