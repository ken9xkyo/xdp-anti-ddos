#!/usr/bin/env python3
import sys
import os

# Add directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import xdp_wrapper
import json

print("Retrieving stats...")
# Debug: Dump raw stats map
map_id = xdp_wrapper.get_map_id('stats_map')
print(f"Stats Map ID: {map_id}")
if map_id:
    output, err, rc = xdp_wrapper.run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    print(f"Raw Output Length: {len(output)}")
    print(f"Raw Output Sample: {output[:500]}...")
    
stats = xdp_wrapper.get_stats()

print(json.dumps(stats, indent=2))

print("\nRetrieving whitelist...")
whitelist = xdp_wrapper.get_whitelist()
print(whitelist)

print("\nRetrieving ports...")
ports = xdp_wrapper.get_ports()
print(ports)

print("\nRetrieving config...")
config = xdp_wrapper.get_config()
print(config)
