# Makefile for tyrshield project

# Binary name (fixed to tyrshield)
BINARY_NAME=tyrshield

# Default target (when no target is specified)
all: build

# Build the binary for the current OS and architecture
build:
	@echo "Building for OS=linux, ARCH=$(GOARCH)..."
	GOOS=linux GOARCH=$(GOARCH) go build -o $(BINARY_NAME) .

# Clean up the binary
clean:
	rm -f $(BINARY_NAME)
	@echo "Cleaned up binary $(BINARY_NAME)"

# Cross-compile for Linux x86_64
x86_64:
	@echo "Building for Linux (x86_64)..."
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) .

# Cross-compile for Linux arm64
arm64:
	@echo "Building for Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_NAME) .

# Use 'make' to build the default architecture.
# Use 'make x86_64' for x86_64 or 'make arm64' for arm64.
