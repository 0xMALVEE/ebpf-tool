# Makefile for the eBPF program tracker

.PHONY: all build clean generate

# Default target
all: build

# Generate Go code from eBPF C code
generate:
	cd pkg/ebpf && go generate

# Build the program
build: generate
	go build -o execve-tracker

# Install dependencies
deps:
	go mod tidy

# Clean build artifacts
clean:
	rm -f execve-tracker
	rm -f pkg/ebpf/bpf_*

# Run the program (requires root)
run: build
	sudo ./execve-tracker

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Default target, builds the program"
	@echo "  generate   - Generate Go code from eBPF C code"
	@echo "  build      - Build the execve-tracker binary"
	@echo "  deps       - Install dependencies"
	@echo "  clean      - Remove build artifacts"
	@echo "  run        - Run the program (requires root)"
	@echo "  help       - Show this help message"
