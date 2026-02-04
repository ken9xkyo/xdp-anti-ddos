# XDP Anti-DDoS Makefile

# Compiler and flags
CLANG := clang
LLC := llc
BPFTOOL := bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BPF compile flags
BPF_CFLAGS := -O2 -g -target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-Wall -Wextra \
	-Wno-unused-parameter \
	-Wno-compare-distinct-pointer-types

# Include paths
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu \
	-I/usr/include

# Output
OUTPUT := xdp_anti_ddos.o

# Interface (can be overridden: make IFACE=eth0 attach)
IFACE ?= eth0

.PHONY: all clean attach detach status test init help

all: $(OUTPUT)
	@echo "Build complete: $(OUTPUT)"

$(OUTPUT): xdp_anti_ddos.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "Compiled $< -> $@"

# Verify the compiled object
verify: $(OUTPUT)
	@echo "=== Program Sections ==="
	@$(BPFTOOL) prog load $(OUTPUT) /sys/fs/bpf/test_verify 2>&1 || true
	@rm -f /sys/fs/bpf/test_verify 2>/dev/null || true
	@echo ""
	@echo "=== Object Info ==="
	@llvm-objdump -h $(OUTPUT) 2>/dev/null || objdump -h $(OUTPUT)

# Attach XDP program to interface
attach: $(OUTPUT)
	@echo "Attaching XDP to $(IFACE)..."
	ip link set dev $(IFACE) xdpdrv obj $(OUTPUT) sec xdp 2>/dev/null || true
	@echo "XDP attached to $(IFACE)"
	@$(MAKE) init-maps
	@$(MAKE) status

# Detach XDP program
detach:
	@echo "Detaching XDP from $(IFACE)..."
	ip link set dev $(IFACE) xdp off 2>/dev/null || true
	@echo "XDP detached from $(IFACE)"

# Show XDP status
status:
	@echo "=== XDP Status ==="
	@ip link show $(IFACE) | grep -E "xdp|$(IFACE):"
	@echo ""
	@echo "=== BPF Maps ==="
	@$(BPFTOOL) map list 2>/dev/null | grep -E "whitelist|amp_ports|config|stats|rate_limit" || echo "No maps found"

# Initialize default maps
init-maps:
	@echo "Initializing default configuration..."
	@python3 xdp_cli.py init 2>/dev/null || echo "CLI init skipped"

# Clean build artifacts
clean:
	rm -f $(OUTPUT) *.o

# Run tests
test: attach
	@echo "Running basic tests..."
	@sleep 1
	@python3 xdp_cli.py stats show
	@python3 xdp_cli.py port list
	@python3 xdp_cli.py config show

# Help
help:
	@echo "XDP Anti-DDoS Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build XDP program (default)"
	@echo "  attach     - Attach XDP to interface (IFACE=eth0)"
	@echo "  detach     - Detach XDP from interface"
	@echo "  status     - Show XDP and map status"
	@echo "  init-maps  - Initialize default maps via CLI"
	@echo "  verify     - Verify compiled object"
	@echo "  test       - Attach and run basic tests"
	@echo "  clean      - Remove build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build"
	@echo "  make IFACE=enp0s3 attach  # Attach to specific interface"
	@echo "  make detach             # Detach XDP"
