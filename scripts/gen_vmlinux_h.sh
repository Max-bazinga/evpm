#!/bin/bash
# Generate vmlinux.h for CO-RE BPF programs

set -e

KERNEL_DIR="$(dirname "$0")/../src/kernels"
VMLINUX="$KERNEL_DIR/vmlinux.h"

echo "Generating vmlinux.h for CO-RE BPF programs..."

# Check for bpftool
if ! command -v bpftool &> /dev/null; then
    echo "❌ Error: bpftool not found"
    echo "   Install: sudo apt-get install linux-tools-common linux-tools-generic"
    exit 1
fi

# Check for BTF support
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "❌ Error: Kernel BTF not available"
    echo "   Your kernel needs CONFIG_DEBUG_INFO_BTF=y"
    echo "   Check: zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz 2>/dev/null || \
           cat /boot/config-$(uname -r) 2>/dev/null | grep CONFIG_DEBUG_INFO_BTF"
    exit 1
fi

echo "✓ Found BTF at /sys/kernel/btf/vmlinux"

# Generate vmlinux.h
echo "Generating vmlinux.h..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"

echo "✓ Generated: $VMLINUX"
echo ""
echo "You can now build CO-RE BPF programs:"
echo "  make bpf"
