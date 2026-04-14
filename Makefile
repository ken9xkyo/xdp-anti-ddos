# XDP Anti-DDoS Makefile
# ============================================================================
# Hỗ trợ kiến trúc Out-of-Band Scrubbing (2 cổng: IN / OUT)
#
#   Internet → [IN_IFACE] → XDP Filter → [OUT_IFACE] → Backend Server
#
# Ví dụ:
#   make build
#   make IFACE=enp94s0f0 load        # Load + pin chương trình và maps
#   make IFACE=enp94s0f0 attach      # Attach XDP vào interface IN
#   make OUT_IFACE=ens3 init    # Khởi tạo tất cả maps (DEVMAP, redirect, ports, config)
# ============================================================================

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

# Interface IN — nhận traffic cần lọc (can be overridden: make IFACE=enp94s0f0)
IFACE ?= enp94s0f0

# Interface OUT — cổng xuất traffic đã lọc sang backend (make OUT_IFACE=ens3)
OUT_IFACE ?= ens3

# BPF pin paths
BPF_PIN_DIR := /sys/fs/bpf
PROG_PIN := $(BPF_PIN_DIR)/xdp_anti_ddos
MAP_PIN_TX := $(BPF_PIN_DIR)/tx_port_map
MAP_PIN_VM := $(BPF_PIN_DIR)/vm_redirect_map

.PHONY: all build clean load unload attach detach status init init-maps init-devmap init-jmp init-ports init-config init-redirect test test-redirect help

# ============================================================================
# BUILD
# ============================================================================

all: build

build: $(OUTPUT)
	@echo "✓ Build complete: $(OUTPUT)"

$(OUTPUT): xdp_anti_ddos.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "  Compiled $< -> $@"

# Verify the compiled object
verify: $(OUTPUT)
	@echo "=== Program Sections ==="
	@$(BPFTOOL) prog load $(OUTPUT) $(BPF_PIN_DIR)/test_verify 2>&1 || true
	@rm -f $(BPF_PIN_DIR)/test_verify 2>/dev/null || true
	@echo ""
	@echo "=== Object Info ==="
	@llvm-objdump -h $(OUTPUT) 2>/dev/null || objdump -h $(OUTPUT)

# ============================================================================
# LOAD / UNLOAD — Load chương trình vào kernel và pin maps
# ============================================================================

# Mount BPF filesystem (nếu chưa mount)
mount-bpf:
	@mountpoint -q $(BPF_PIN_DIR) || mount -t bpf bpf $(BPF_PIN_DIR)
	@echo "✓ BPF filesystem mounted"

# Load program + Pin tất cả maps vào /sys/fs/bpf
load: $(OUTPUT) mount-bpf
	@echo "Loading XDP program và pin maps..."
	$(BPFTOOL) prog loadall $(OUTPUT) $(PROG_PIN) type xdp pinmaps $(BPF_PIN_DIR)
	@echo "✓ Program loaded và pinned tại $(PROG_PIN)"
	@echo "✓ Maps pinned tại $(BPF_PIN_DIR)/"

# Unload — xóa pinned program và maps
unload:
	@echo "Unloading XDP program..."
	@rm -rf $(PROG_PIN) 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/acl_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/acl_map_v6 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/amp_ports_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/config_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/rate_limit_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/rate_limit_syn_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/rate_limit_icmp_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/global_stats_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/temp_block_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/stats_scratch 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/jmp_table 2>/dev/null || true
	@rm -f $(MAP_PIN_TX) 2>/dev/null || true
	@rm -f $(MAP_PIN_VM) 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/ip_stats_map 2>/dev/null || true
	@rm -f $(BPF_PIN_DIR)/vip_redirect_map 2>/dev/null || true
	@echo "✓ Đã xóa tất cả pinned program và maps"

# ============================================================================
# ATTACH / DETACH — Gắn/tháo XDP khỏi interface
# ============================================================================

# Attach XDP program từ pinned path
attach:
	@echo "Attaching XDP to $(IFACE)..."
	@if [ -e $(PROG_PIN)/xdp_anti_ddos ]; then \
		ip link set dev $(IFACE) xdpgeneric pinned $(PROG_PIN)/xdp_anti_ddos 2>/dev/null \
		|| ip link set dev $(IFACE) xdpdrv pinned $(PROG_PIN)/xdp_anti_ddos 2>/dev/null \
		|| echo "⚠ Không thể attach. Thử: ip link set dev $(IFACE) xdpgeneric pinned $(PROG_PIN)/xdp_anti_ddos"; \
	else \
		echo "⚠ Program chưa load. Chạy: make load"; \
	fi
	@echo "✓ XDP attached to $(IFACE)"

# Detach XDP program
detach:
	@echo "Detaching XDP from $(IFACE)..."
	@ip link set dev $(IFACE) xdp off 2>/dev/null || true
	@ip link set dev $(IFACE) xdpgeneric off 2>/dev/null || true
	@echo "✓ XDP detached from $(IFACE)"

# ============================================================================
# INIT — Khởi tạo tất cả tham số cần thiết
# ============================================================================

# Init tất cả (DEVMAP + redirect + ports + config)
# Sử dụng: make OUT_IFACE=ens3 init
init: init-devmap init-jmp init-ports init-config
	@echo ""
	@echo "✓ Khởi tạo hoàn tất!"
	@echo "  → DEVMAP (tx_port_map): $(OUT_IFACE) ready"
	@echo "  → Amplification ports: 53, 123, 1900, 11211"
	@echo "  → Config defaults: UDP 10k pps, 1024B max, ICMP 100 pps, SYN 10k pps"
	@echo "  → Jump table (jmp_table): xdp_stats_prog linked"
	@echo ""
	@echo "Bước tiếp theo:"
	@echo "  → Thêm IP backend: python3 control_tool.py  (rồi gõ: add <IP>)"
	@echo "  → Hoặc: make REDIRECT_IP=118.107.78.137 init-redirect"

# --- Init Jump Table (jmp_table) — BẮT BUỘC cho stats tracking ---
# jmp_table là PROG_ARRAY dùng cho bpf_tail_call().
# Entry 0 (PROG_STATS) phải trỏ tới xdp_stats_prog để track_stats() hoạt động.
# Nếu thiếu, emit_verdict() sẽ fallback trực tiếp → global_stats_map luôn = 0.
init-jmp:
	@echo "Initializing jmp_table (PROG_ARRAY) cho tail call..."
	@STATS_PROG_ID=$$(bpftool prog show pinned $(PROG_PIN)/xdp_stats_prog -j 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null); \
	JMP_MAP_ID=$$(bpftool map show pinned $(BPF_PIN_DIR)/jmp_table -j 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null); \
	if [ -z "$$STATS_PROG_ID" ] || [ -z "$$JMP_MAP_ID" ]; then \
		echo "✗ Không tìm thấy xdp_stats_prog hoặc jmp_table. Chạy: make load"; \
		exit 1; \
	fi; \
	$(BPFTOOL) map update id $$JMP_MAP_ID key 0 0 0 0 value id $$STATS_PROG_ID 2>/dev/null; \
	echo "✓ jmp_table[0] = xdp_stats_prog (prog id=$$STATS_PROG_ID, map id=$$JMP_MAP_ID)"

# --- Init DEVMAP (tx_port_map) — BẮT BUỘC cho redirect ---
# tx_port_map cần có ifindex của cổng OUT để bpf_redirect_map() hoạt động.
# Nếu thiếu, tất cả redirect sẽ trả về XDP_ABORTED!
init-devmap:
	@echo "Initializing tx_port_map (DEVMAP) cho $(OUT_IFACE)..."
	@OUT_IFINDEX=$$(cat /sys/class/net/$(OUT_IFACE)/ifindex 2>/dev/null); \
	if [ -z "$$OUT_IFINDEX" ]; then \
		echo "✗ Interface $(OUT_IFACE) không tồn tại!"; \
		exit 1; \
	fi; \
	OUT_HEX=$$(printf '%02x %02x %02x %02x' $$(($$OUT_IFINDEX & 0xff)) $$((($$OUT_IFINDEX >> 8) & 0xff)) $$((($$OUT_IFINDEX >> 16) & 0xff)) $$((($$OUT_IFINDEX >> 24) & 0xff))); \
	MAP_ID=$$(python3 -c "import subprocess,json; \
p=json.loads(subprocess.run(['bpftool','prog','show','pinned','$(PROG_PIN)/xdp_anti_ddos','-j'],capture_output=True,text=True).stdout); \
pids=p.get('map_ids',[]); \
ms=json.loads(subprocess.run(['bpftool','map','show','-j'],capture_output=True,text=True).stdout); \
r=[m['id'] for m in ms if m.get('name','').startswith('tx_port_map') and m.get('id') in pids]; \
print(r[0] if r else '')" 2>/dev/null); \
	if [ -n "$$MAP_ID" ]; then \
		$(BPFTOOL) map update id $$MAP_ID key hex $$OUT_HEX value hex $$OUT_HEX 2>/dev/null; \
		echo "✓ tx_port_map: ifindex=$$OUT_IFINDEX ($(OUT_IFACE)) [map id=$$MAP_ID]"; \
	else \
		$(BPFTOOL) map update pinned $(MAP_PIN_TX) key hex $$OUT_HEX value hex $$OUT_HEX 2>/dev/null; \
		echo "✓ tx_port_map: ifindex=$$OUT_IFINDEX ($(OUT_IFACE)) [pinned fallback]"; \
	fi

# --- Init amplification ports ---
init-ports:
	@echo "Initializing amplification ports..."
	@python3 xdp_cli.py port init 2>/dev/null || echo "⚠ CLI port init skipped"

# --- Init config defaults ---
init-config:
	@echo "Initializing default configuration..."
	@python3 xdp_cli.py config init 2>/dev/null || echo "⚠ CLI config init skipped"

# --- Init VM redirect cho 1 IP cụ thể ---
# Sử dụng: make REDIRECT_IP=118.107.78.137 init-redirect
REDIRECT_IP ?=
init-redirect:
	@if [ -z "$(REDIRECT_IP)" ]; then \
		echo "Usage: make REDIRECT_IP=<IP> init-redirect"; \
		echo "  Hoặc dùng interactive tool: python3 control_tool.py"; \
		exit 1; \
	fi
	@echo "Adding redirect entry for $(REDIRECT_IP)..."
	@echo "add $(REDIRECT_IP)" | python3 control_tool.py 2>/dev/null || \
		echo "⚠ Không thể thêm. Dùng: python3 control_tool.py rồi gõ: add $(REDIRECT_IP)"

# ============================================================================
# STATUS / TEST
# ============================================================================

# Show XDP status
status:
	@echo "=== XDP Status ==="
	@ip link show $(IFACE) 2>/dev/null | grep -E "xdp|$(IFACE):" || echo "Interface $(IFACE) not found"
	@echo ""
	@echo "=== BPF Program ==="
	@$(BPFTOOL) prog show pinned $(PROG_PIN)/xdp_anti_ddos 2>/dev/null || echo "Program not loaded"
	@echo ""
	@echo "=== BPF Maps ==="
	@$(BPFTOOL) map list 2>/dev/null | grep -E "whitelist|blacklist|amp_ports|config|stats|rate_limit|redirect|tx_port" || echo "No maps found"
	@echo ""
	@echo "=== VM Redirect Map ==="
	@$(BPFTOOL) map list 2>/dev/null | grep -E "vm_redirect_map" || echo "No redirect entries"
	@echo ""
	@echo "=== TX Port Map (DEVMAP) ==="
	@$(BPFTOOL) map dump pinned $(MAP_PIN_TX) 2>/dev/null | grep -v "no entry" | head -5 || echo "Empty"

# Run basic tests
test:
	@echo "Running basic tests..."
	@python3 xdp_cli.py stats show 2>/dev/null || echo "Stats unavailable"
	@echo ""
	@python3 xdp_cli.py port list 2>/dev/null || echo "Ports unavailable"
	@echo ""
	@python3 xdp_cli.py config show 2>/dev/null || echo "Config unavailable"

# Run redirect test suite
test-redirect:
	@echo "Running redirect test suite..."
	@python3 test_redirect.py

# ============================================================================
# QUICK DEPLOY — Build → Load → Attach → Init (1 lệnh)
# ============================================================================

# Deploy hoàn chỉnh: make IFACE=enp94s0f0 OUT_IFACE=ens3 deploy
deploy: build unload load attach init
	@echo ""
	@echo "════════════════════════════════════════════════"
	@echo "✓ XDP Anti-DDoS deployed thành công!"
	@echo "  IN:  $(IFACE)"
	@echo "  OUT: $(OUT_IFACE)"
	@echo "════════════════════════════════════════════════"

# Clean build artifacts
clean:
	rm -f $(OUTPUT) *.o

# ============================================================================
# HELP
# ============================================================================

help:
	@echo "XDP Anti-DDoS Makefile"
	@echo ""
	@echo "═══ Build ═══"
	@echo "  build / all    - Build XDP program"
	@echo "  clean          - Remove build artifacts"
	@echo "  verify         - Verify compiled object"
	@echo ""
	@echo "═══ Load / Attach ═══"
	@echo "  load           - Load program + pin maps vào /sys/fs/bpf"
	@echo "  unload         - Xóa pinned program và maps"
	@echo "  attach         - Attach XDP vào interface (IFACE=enp94s0f0)"
	@echo "  detach         - Detach XDP khỏi interface"
	@echo ""
	@echo "═══ Init ═══"
	@echo "  init           - Init tất cả: DEVMAP + ports + config"
	@echo "  init-devmap    - Init tx_port_map cho OUT_IFACE (BẮT BUỘC cho redirect)"
	@echo "  init-ports     - Init amplification ports (53,123,1900,11211)"
	@echo "  init-config    - Init config defaults (PPS, max-size...)"
	@echo "  init-redirect  - Thêm redirect IP (REDIRECT_IP=x.x.x.x)"
	@echo ""
	@echo "═══ Quick Deploy ═══"
	@echo "  deploy         - Build + Load + Attach + Init (1 lệnh)"
	@echo ""
	@echo "═══ Status / Test ═══"
	@echo "  status         - Hiển thị trạng thái XDP, maps, redirect"
	@echo "  test           - Kiểm tra stats, ports, config"
	@echo "  test-redirect  - Chạy redirect test suite (scapy)"
	@echo ""
	@echo "═══ Variables ═══"
	@echo "  IFACE          - Interface IN (default: enp94s0f0)"
	@echo "  OUT_IFACE      - Interface OUT (default: ens3)"
	@echo "  REDIRECT_IP    - IP backend cho init-redirect"
	@echo ""
	@echo "═══ Ví dụ ═══"
	@echo "  make build"
	@echo "  make IFACE=enp94s0f0 load"
	@echo "  make IFACE=enp94s0f0 attach"
	@echo "  make OUT_IFACE=ens3 init"
	@echo "  make REDIRECT_IP=118.107.78.137 init-redirect"
	@echo "  make IFACE=enp94s0f0 OUT_IFACE=ens3 deploy    # Tất cả trong 1 lệnh"
	@echo "  make test-redirect                        # Chạy test redirect"

