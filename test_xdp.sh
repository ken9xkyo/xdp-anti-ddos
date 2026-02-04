#!/bin/bash
# XDP Anti-DDoS Test Script
# Generates test traffic to verify XDP filtering

set -e

IFACE="${1:-enp134s0f1}"
TARGET_IP="${2:-117.103.204.126}"

echo "=========================================="
echo "XDP Anti-DDoS Test Script"
echo "=========================================="
echo "Interface: $IFACE"
echo "Target IP: $TARGET_IP"
echo ""

# Check if XDP is loaded
if ! ip link show $IFACE | grep -q "xdp"; then
    echo "ERROR: XDP not attached to $IFACE"
    echo "Run: make IFACE=$IFACE attach"
    exit 1
fi

echo "✓ XDP is attached to $IFACE"
echo ""

# Show current stats
echo "Initial Statistics:"
python3 xdp_cli.py stats show
echo ""

# Test 1: Normal traffic
echo "=========================================="
echo "Test 1: Normal ICMP traffic (should pass)"
echo "=========================================="
ping -c 5 $TARGET_IP -q &
sleep 2
echo ""

# Test 2: UDP amplification simulation (from localhost - won't be blocked as it's local)
echo "=========================================="
echo "Test 2: Checking blocked amplification ports"
echo "=========================================="
python3 xdp_cli.py port list
echo ""

# Show final stats
echo "=========================================="
echo "Current Statistics After Test:"
echo "=========================================="
python3 xdp_cli.py stats show
echo ""

echo "=========================================="
echo "Live Monitor (Ctrl+C to stop):"
echo "=========================================="
echo "Watching stats for 10 seconds..."
for i in {1..5}; do
    sleep 2
    python3 xdp_cli.py stats show | grep -E "Passed|Dropped|Drop Rate"
    echo "---"
done

echo ""
echo "Test complete!"
