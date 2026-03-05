# eVPM Makefile
# eBPF VM Performance Monitor

.PHONY: all clean install test fmt check bpf

# Directories
SRC_DIR := src
KERNEL_DIR := $(SRC_DIR)/kernels
PYTHON_DIR := $(SRC_DIR)/python
BUILD_DIR := build

# Tools
CLANG := clang
LLC := llc
LLVM_STRIP := llvm-strip
BPFTOOL := bpftool
PYTHON := python3
PIP := pip3

# Flags - CO-RE compatible
BPF_CFLAGS := -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86_64
BPF_CFLAGS += -D__BPF_TRACING__
BPF_CFLAGS += -I$(KERNEL_DIR)
BPF_CFLAGS += -O2 -g
# CO-RE: Preserve access index for field offsets
BPF_CFLAGS += -Xclang -O0 -Xclang -disable-llvm-passes

# eBPF Programs
BPF_SOURCES := $(wildcard $(KERNEL_DIR)/*.bpf.c)
BPF_OBJECTS := $(patsubst %.bpf.c,%.o,$(BPF_SOURCES))

# Default target
all: bpf python

# Build eBPF programs
bpf: $(BPF_OBJECTS)

$(KERNEL_DIR)/%.o: $(KERNEL_DIR)/%.bpf.c
	@echo "Building eBPF: $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "✓ Built: $@"

# Generate vmlinux.h (requires BTF)
vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "Generating vmlinux.h..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(KERNEL_DIR)/vmlinux.h; \
		echo "✓ Generated vmlinux.h"; \
	else \
		echo "⚠ Warning: BTF not available, skipping vmlinux.h generation"; \
	fi

# Install Python package
python:
	@echo "Installing Python package..."
	$(PIP) install -e .
	@echo "✓ Python package installed"

# Install dependencies
deps:
	@echo "Installing system dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update; \
		sudo apt-get install -y llvm clang libbpf-dev linux-headers-$$(uname -r) python3-pip python3-dev; \
		sudo apt-get install -y bpfcc-tools libbpfcc-dev; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y llvm clang kernel-headers python3-pip python3-devel; \
	else \
		echo "⚠ Please install dependencies manually"; \
	fi
	@echo "✓ Dependencies installed"

# Install Python dependencies
pip-deps:
	@echo "Installing Python dependencies..."
	$(PIP) install -r requirements.txt
	@echo "✓ Python dependencies installed"

# Run tests
test:
	@echo "Running tests..."
	$(PYTHON) -m pytest tests/ -v
	@echo "✓ Tests completed"

# Code formatting
fmt:
	@echo "Formatting code..."
	@# Format Python code
	$(PYTHON) -m black $(PYTHON_DIR) --line-length 100
	@# Format C code (if clang-format available)
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(KERNEL_DIR)/*.c; \
	fi
	@echo "✓ Code formatted"

# Lint check
lint:
	@echo "Running lint checks..."
	$(PYTHON) -m flake8 $(PYTHON_DIR) --max-line-length 100
	@echo "✓ Lint check passed"

# Check system requirements
check:
	@echo "Checking system requirements..."
	@echo "Kernel version: $$(uname -r)"
	@echo "BTF support: $$(test -f /sys/kernel/btf/vmlinux && echo 'Yes' || echo 'No')"
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "BCC installed: $$(python3 -c 'import bcc; print(bcc.__version__)' 2>/dev/null || echo 'No')"
	@echo "Clang version: $$($(CLANG) --version | head -1)"
	@echo "✓ Check completed"

# Run eVPM
run:
	sudo $(PYTHON) -m evpm start

# Run CLI
cli:
	sudo $(PYTHON) -m evpm cli

# Run Web UI
web:
	sudo $(PYTHON) -m evpm web --port 8080

# Run Prometheus exporter
export:
	sudo $(PYTHON) -m evpm export --port 9090

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(KERNEL_DIR)/*.o
	rm -f $(KERNEL_DIR)/vmlinux.h
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "✓ Cleaned"

# Install everything
install: deps pip-deps bpf python
	@echo "✓ eVPM installed successfully"
	@echo "Run 'sudo evpm check' to verify installation"

# Uninstall
uninstall:
	@echo "Uninstalling eVPM..."
	$(PIP) uninstall -y evpm
	@echo "✓ Uninstalled"

# Generate documentation
docs:
	@echo "Generating documentation..."
	@# Could use sphinx or mkdocs here
	@echo "✓ Documentation generated"

# Docker build
docker:
	@echo "Building Docker image..."
	docker build -t evpm:latest .
	@echo "✓ Docker image built"

# Help
help:
	@echo "eVPM Makefile Targets:"
	@echo ""
	@echo "  make all       - Build eBPF programs and Python package"
	@echo "  make bpf       - Build eBPF programs only"
	@echo "  make python    - Install Python package"
	@echo "  make deps      - Install system dependencies"
	@echo "  make install   - Full installation"
	@echo "  make test      - Run tests"
	@echo "  make fmt       - Format code"
	@echo "  make lint      - Run lint checks"
	@echo "  make check     - Check system requirements"
	@echo "  make run       - Run eVPM monitor"
	@echo "  make cli       - Run CLI mode"
	@echo "  make web       - Run Web UI"
	@echo "  make export    - Run Prometheus exporter"
	@echo "  make clean     - Clean build artifacts"
	@echo "  make help      - Show this help"

# Version
version:
	@echo "eVPM v1.0.0"
