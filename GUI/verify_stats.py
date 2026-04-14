#!/usr/bin/env python3
import sys
import os
import json

# Add directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import xdp_wrapper

print("=" * 50)
print("XDP Anti-DDoS GUI Verification")
print("=" * 50)

print("\n[1] Retrieving stats from global_stats_map...")
map_id = xdp_wrapper.get_map_id('global_stats_map')
print(f"  Global Stats Map ID: {map_id}")

stats = xdp_wrapper.get_stats()
if 'error' in stats:
    print(f"  ERROR: {stats['error']}")
else:
    print(f"  Passed: {stats['packets_passed']:,} pkts / {stats['bytes_passed']:,} bytes")
    print(f"  Dropped: {stats['packets_dropped']:,} pkts / {stats['bytes_dropped']:,} bytes")
    print(f"  Redirected: {stats['packets_redirected']:,} pkts")
    print(f"  Protocols: {json.dumps(stats['protocols'])}")
    print(f"  Pkt Size Buckets: {stats['pkt_size_buckets']}")
    print(f"  Reflection Ports: {json.dumps(stats['reflection_ports'])}")
    print(f"  Drop Reasons: {json.dumps(stats['drop_reasons'], indent=2)}")

print("\n[2] Retrieving whitelist...")
whitelist = xdp_wrapper.get_whitelist()
print(f"  {len(whitelist)} entries: {whitelist}")

print("\n[3] Retrieving blocked ports...")
ports = xdp_wrapper.get_ports()
print(f"  {len(ports)} entries: {ports}")

print("\n[4] Retrieving config...")
config = xdp_wrapper.get_config()
print(f"  {json.dumps(config, indent=2)}")

print("\n[5] Retrieving VM redirect entries...")
entries, err = xdp_wrapper.get_vm_redirects()
if err:
    print(f"  Warning: {err}")
print(f"  {len(entries)} entries:")
for e in entries:
    print(f"    {e['ip']} -> ifindex={e['ifindex']} src={e['src_mac']} dst={e['dst_mac']}")

print("\n" + "=" * 50)
print("Verification complete.")
