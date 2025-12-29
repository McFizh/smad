# SMAD Makefile
# Provides common tasks for building, testing, and development

# Default target
.PHONY: help
help:
	@echo "SMAD Makefile - Available targets:"
	@echo ""
	@echo "  build          - Build the SMAD application"
	@echo "  test           - Run all tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  test-coverage  - Run tests with coverage analysis"
	@echo "  test-all       - Run all tests (verbose + coverage)"
	@echo "  clean          - Remove build artifacts"
	@echo "  run            - Build and run the application"
	@echo "  help           - Show this help message"
	@echo ""

# Build the application
.PHONY: build
build:
	@echo "Building SMAD..."
	@go build -o smad .
	@echo "Build complete: ./smad"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test ./...

# Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "Running tests with verbose output..."
	@go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage analysis..."
	@go test -cover ./...

# Run all tests (verbose + coverage)
.PHONY: test-all
test-all:
	@echo "Running comprehensive tests..."
	@echo "================================"
	@echo "Verbose output:"
	@go test -v ./...
	@echo ""
	@echo "Coverage analysis:"
	@go test -cover ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -f smad
	@echo "Clean complete"

# Build and run the application
.PHONY: run
run:
	@echo "Building and running SMAD..."
	@go build -o smad .
	@./smad

# Shortcut for running connection handler tests specifically
.PHONY: test-handler
test-handler:
	@echo "Running connection handler tests..."
	@go test -v -run TestHandlePacket

# Shortcut for running mock tests
.PHONY: test-mocks
test-mocks:
	@echo "Running mock tests..."
	@go test -v ./internal/mocks/...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting Go code..."
	@gofmt -w .
	@echo "Code formatting complete"

# Check for formatting issues
.PHONY: fmt-check
fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
	    echo "Code needs formatting:"; \
	    gofmt -l .; \
	    exit 1; \
	fi
	@echo "Code is properly formatted"

# Vet code for potential issues
.PHONY: vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "Vetting complete"

# Run all quality checks
.PHONY: check
check: fmt-check vet
	@echo "All quality checks passed"

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@echo "Dependencies updated"

# Show Go environment info
.PHONY: env
env:
	@echo "Go environment information:"
	@go version
	@go env GOPATH
	@go env GOOS
	@go env GOARCH
