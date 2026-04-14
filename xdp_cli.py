#!/usr/bin/env python3
"""
XDP Anti-DDoS CLI Tool
Manage whitelist, blacklist, ports, configuration, and statistics via BPF maps.

Supports CIDR notation for IP ranges (e.g. 10.0.0.0/8, 192.168.1.0/24).
Bare IPs without prefix are automatically treated as /32 (IPv4) or /128 (IPv6).

Usage:
    xdp_cli.py whitelist add <IP/CIDR>   # Add IP or CIDR range to whitelist
    xdp_cli.py whitelist remove <IP/CIDR># Remove IP/CIDR from whitelist
    xdp_cli.py whitelist list            # List whitelisted IPs/CIDRs

    xdp_cli.py blacklist add <IP/CIDR>   # Add IP or CIDR range to blacklist
    xdp_cli.py blacklist remove <IP/CIDR># Remove IP/CIDR from blacklist
    xdp_cli.py blacklist list            # List blacklisted IPs/CIDRs
    
    xdp_cli.py port add <PORT>           # Add amplification port to block
    xdp_cli.py port remove <PORT>        # Remove port from block list
    xdp_cli.py port list                 # List blocked ports
    xdp_cli.py port init                 # Initialize default ports (53,123,1900,11211)
    
    xdp_cli.py config set pps-limit <N>      # Set UDP PPS limit
    xdp_cli.py config set max-size <N>       # Set max UDP payload size
    xdp_cli.py config set icmp-limit <N>     # Set ICMP PPS limit
    xdp_cli.py config set syn-limit <N>      # Set SYN PPS limit
    xdp_cli.py config show                   # Show current config
    xdp_cli.py config init                   # Initialize default config
    
    xdp_cli.py stats show                # Show statistics
    xdp_cli.py stats top                 # Show top IPs
"""

import subprocess
import json
import sys
import socket
import struct
import argparse
import os
import ctypes
import ipaddress

# Config map indices (must match xdp_anti_ddos.c)
CONFIG_UDP_PPS_LIMIT = 0
CONFIG_UDP_MAX_SIZE = 1
CONFIG_ICMP_PPS_LIMIT = 2
CONFIG_SYN_PPS_LIMIT = 3

# Default values
DEFAULT_UDP_PPS_LIMIT = 10000
DEFAULT_UDP_MAX_SIZE = 1024
DEFAULT_ICMP_PPS_LIMIT = 100
DEFAULT_SYN_PPS_LIMIT = 10000

# Default amplification ports
DEFAULT_AMP_PORTS = [53, 123, 1900, 11211]

# Drop reason names
DROP_REASONS = {
    0: "Unknown Protocol",
    1: "Fragmented Packet",
    2: "UDP Rate Limit",
    3: "UDP Amplification",
    4: "UDP Payload Size",
    5: "Invalid TCP Flags",
    6: "ICMP Rate Limit",
    7: "SYN Rate Limit",
    8: "Blacklisted IP",
    9: "Parse Error",
    10: "Temp Block"
}

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def run_bpftool(args, check=True):
    """Run bpftool command and return output"""
    cmd = ['bpftool'] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if check and result.returncode != 0:
            return None, result.stderr.strip()
        return result.stdout, None
    except Exception as e:
        return None, str(e)

def get_active_xdp_map_ids():
    """Get map IDs from the currently active (attached) XDP program.
    When multiple XDP programs are loaded, picks the one with highest ID
    (most recently loaded = currently attached)."""
    output, err = run_bpftool(['prog', 'show', '-j'])
    if err:
        return []
    try:
        progs = json.loads(output)
        # Find all XDP programs named xdp_anti_ddos, pick the last one (highest id)
        xdp_progs = [p for p in progs
                     if p.get('type') == 'xdp' and 'xdp_anti_ddos' in p.get('name', '')]
        if xdp_progs:
            # Sort by id descending, return the newest (attached) one
            xdp_progs.sort(key=lambda p: p.get('id', 0), reverse=True)
            return xdp_progs[0].get('map_ids', [])
        # Fallback: any XDP program (pick the newest)
        xdp_any = [p for p in progs if p.get('type') == 'xdp']
        if xdp_any:
            xdp_any.sort(key=lambda p: p.get('id', 0), reverse=True)
            return xdp_any[0].get('map_ids', [])
    except json.JSONDecodeError:
        pass
    return []

def get_map_id(map_name):
    """Get BPF map ID by name from the active XDP program.
    Uses prefix matching because BPF truncates map names to 15 chars
    (e.g., 'global_stats_map' → 'global_stats_ma')."""
    # First get the map IDs from the active XDP program
    active_map_ids = get_active_xdp_map_ids()
    
    output, err = run_bpftool(['map', 'show', '-j'])
    if err:
        return None
    try:
        maps = json.loads(output)
        
        def name_matches(bpf_name, search_name):
            """Match considering BPF 15-char name truncation"""
            return (bpf_name == search_name or
                    search_name.startswith(bpf_name) or
                    bpf_name.startswith(search_name))
        
        # If we have active map IDs, prefer maps from active program
        if active_map_ids:
            for m in maps:
                if name_matches(m.get('name', ''), map_name) and m.get('id') in active_map_ids:
                    return m.get('id')
        
        # Fallback: find the highest ID (most recently created)
        matching_maps = [m for m in maps if name_matches(m.get('name', ''), map_name)]
        if matching_maps:
            # Sort by ID descending to get the newest
            matching_maps.sort(key=lambda x: x.get('id', 0), reverse=True)
            return matching_maps[0].get('id')
    except json.JSONDecodeError:
        pass
    return None

def ip_to_hex(ip_str):
    """Convert IP string to hex bytes (little-endian for x86)"""
    try:
        packed = socket.inet_aton(ip_str)
        # Return as space-separated hex bytes
        return ' '.join(f'0x{b:02x}' for b in packed)
    except socket.error:
        return None

def hex_to_ip(hex_bytes):
    """Convert hex bytes to IP string"""
    try:
        if isinstance(hex_bytes, list):
            bytes_val = bytes(int(h, 16) for h in hex_bytes)
            return socket.inet_ntoa(bytes_val)
        return None
    except:
        return None

# ============================================================================
# LPM TRIE KEY HELPERS - Hỗ trợ CIDR notation cho whitelist/blacklist
#
# LPM key format (IPv4): [prefixlen: 4 bytes LE] [addr: 4 bytes network order]
# LPM key format (IPv6): [prefixlen: 4 bytes LE] [addr: 16 bytes network order]
# ============================================================================

def is_ipv6(addr_str):
    """Check if an address string is IPv6"""
    return ':' in addr_str.split('/')[0]

def cidr_to_lpm_hex(cidr_str):
    """Convert IP/CIDR string to LPM trie key hex.
    
    Supports:
      - IPv4: '10.0.0.0/8', '192.168.1.0/24', '8.8.8.8' (auto /32)
      - IPv6: '2001:db8::/32', 'fe80::1' (auto /128)
    
    Returns: (hex_string, normalized_cidr, is_v6) or (None, None, None)
    """
    try:
        # Detect IPv4 vs IPv6
        v6 = is_ipv6(cidr_str)
        
        if v6:
            if '/' not in cidr_str:
                cidr_str += '/128'
            network = ipaddress.ip_network(cidr_str, strict=False)
            prefixlen = network.prefixlen
            addr_bytes = network.network_address.packed  # 16 bytes
        else:
            if '/' not in cidr_str:
                cidr_str += '/32'
            network = ipaddress.ip_network(cidr_str, strict=False)
            prefixlen = network.prefixlen
            addr_bytes = network.network_address.packed  # 4 bytes
        
        # prefixlen: 4 bytes little-endian
        prefix_hex = ' '.join(f'0x{b:02x}' for b in prefixlen.to_bytes(4, 'little'))
        # addr: network byte order (as-is from packed)
        addr_hex = ' '.join(f'0x{b:02x}' for b in addr_bytes)
        
        return f'{prefix_hex} {addr_hex}', str(network), v6
    except (ValueError, TypeError):
        return None, None, None

def lpm_hex_to_cidr(hex_bytes, is_v6=False):
    """Convert LPM trie key hex bytes back to CIDR string.
    
    IPv4 key: 8 hex bytes (4 prefixlen + 4 addr)
    IPv6 key: 20 hex bytes (4 prefixlen + 16 addr)
    """
    try:
        if not isinstance(hex_bytes, list):
            return None
        
        # First 4 bytes: prefixlen (little-endian)
        prefixlen = int(hex_bytes[0], 16) | (int(hex_bytes[1], 16) << 8) | \
                   (int(hex_bytes[2], 16) << 16) | (int(hex_bytes[3], 16) << 24)
        
        if is_v6:
            if len(hex_bytes) < 20:
                return None
            addr_bytes = bytes(int(h, 16) for h in hex_bytes[4:20])
            ip = str(ipaddress.IPv6Address(addr_bytes))
        else:
            if len(hex_bytes) < 8:
                return None
            addr_bytes = bytes(int(h, 16) for h in hex_bytes[4:8])
            ip = socket.inet_ntoa(addr_bytes)
        
        return f"{ip}/{prefixlen}"
    except:
        return None

def port_to_hex(port):
    """Convert port to hex bytes (little-endian)"""
    # Port is stored as __u16 in little-endian
    return f'0x{port & 0xff:02x} 0x{(port >> 8) & 0xff:02x}'

def hex_to_port(hex_bytes):
    """Convert hex bytes to port number"""
    try:
        if isinstance(hex_bytes, list) and len(hex_bytes) >= 2:
            low = int(hex_bytes[0], 16)
            high = int(hex_bytes[1], 16)
            return low | (high << 8)
        return None
    except:
        return None

def u64_to_hex(val):
    """Convert u64 to hex bytes (little-endian)"""
    return ' '.join(f'0x{(val >> (i*8)) & 0xff:02x}' for i in range(8))

def hex_to_u64(hex_bytes):
    """Convert hex bytes to u64"""
    try:
        if isinstance(hex_bytes, list):
            val = 0
            for i, h in enumerate(hex_bytes[:8]):
                val |= int(h, 16) << (i * 8)
            return val
        return 0
    except:
        return 0

def u32_to_hex(val):
    """Convert u32 to hex bytes (little-endian)"""
    return ' '.join(f'0x{(val >> (i*8)) & 0xff:02x}' for i in range(4))

# ============================================================================
# WHITELIST COMMANDS (LPM Trie - hỗ trợ CIDR notation)
# ============================================================================

def _lpm_add(map_name, ip_or_cidr, list_name, value_hex='0x01'):
    """Generic add for LPM Trie based maps (whitelist/blacklist).
    
    Supports IPv4 and IPv6. Auto-detects version and selects the correct map.
    IPv6 addresses use the _v6 variant of the map.
    """
    key_hex, normalized, v6 = cidr_to_lpm_hex(ip_or_cidr)
    if not key_hex:
        print(f"{Colors.RED}Error: Invalid IP/CIDR: {ip_or_cidr}{Colors.END}")
        return 1
    
    actual_map = f"{map_name}_v6" if v6 else map_name
    map_id = get_map_id(actual_map)
    if not map_id:
        print(f"{Colors.RED}Error: {actual_map} not found. Is XDP program loaded?{Colors.END}")
        return 1
    
    cmd = ['map', 'update', 'id', str(map_id), 'key', *key_hex.split(), 'value', value_hex]
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    v_label = "IPv6" if v6 else "IPv4"
    print(f"{Colors.GREEN}✓ Added {normalized} ({v_label}) to {list_name}{Colors.END}")
    return 0

def _lpm_remove(map_name, ip_or_cidr, list_name):
    """Generic remove for LPM Trie based maps."""
    key_hex, normalized, v6 = cidr_to_lpm_hex(ip_or_cidr)
    if not key_hex:
        print(f"{Colors.RED}Error: Invalid IP/CIDR: {ip_or_cidr}{Colors.END}")
        return 1
    
    actual_map = f"{map_name}_v6" if v6 else map_name
    map_id = get_map_id(actual_map)
    if not map_id:
        print(f"{Colors.RED}Error: {actual_map} not found{Colors.END}")
        return 1
    
    cmd = ['map', 'delete', 'id', str(map_id), 'key', *key_hex.split()]
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    v_label = "IPv6" if v6 else "IPv4"
    print(f"{Colors.GREEN}✓ Removed {normalized} ({v_label}) from {list_name}{Colors.END}")
    return 0

def _lpm_list(map_name, list_name, is_v6=False, filter_value=None):
    """Generic list for LPM Trie based maps. Optionally filter by value."""
    map_id = get_map_id(map_name)
    if not map_id:
        print(f"{Colors.RED}Error: {map_name} not found{Colors.END}")
        return [], 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return [], 1
    
    cidrs = []
    try:
        entries = json.loads(output) if output.strip() else []
        for entry in entries:
            key = entry.get('key')
            val = entry.get('value')
            if key:
                # Filter by value if specified (ACL_ALLOW=1, ACL_DENY=2)
                if filter_value is not None and val is not None:
                    actual_val = val if isinstance(val, int) else (val[0] if isinstance(val, list) else None)
                    if actual_val != filter_value:
                        continue
                cidr = lpm_hex_to_cidr(key, is_v6=is_v6)
                if cidr:
                    cidrs.append(cidr)
    except json.JSONDecodeError:
        pass
    return cidrs, 0

def whitelist_add(ip_or_cidr):
    """Add IP or CIDR range to whitelist (ACL_ALLOW=1)"""
    return _lpm_add('acl_map', ip_or_cidr, 'whitelist', value_hex='0x01')

def whitelist_remove(ip_or_cidr):
    """Remove IP or CIDR range from whitelist"""
    return _lpm_remove('acl_map', ip_or_cidr, 'whitelist')

def whitelist_list():
    """List all whitelisted IPs/CIDRs (IPv4 + IPv6)"""
    print(f"{Colors.BOLD}Whitelisted IPs/CIDRs:{Colors.END}")
    print("=" * 50)
    
    total = 0
    
    # IPv4 whitelist (filter value==1 = ACL_ALLOW)
    cidrs_v4, err4 = _lpm_list('acl_map', 'whitelist', is_v6=False, filter_value=1)
    if cidrs_v4:
        print(f"  {Colors.CYAN}── IPv4 ──{Colors.END}")
        for cidr in sorted(cidrs_v4):
            print(f"  {Colors.GREEN}✓{Colors.END} {cidr}")
        total += len(cidrs_v4)
    
    # IPv6 whitelist
    cidrs_v6, err6 = _lpm_list('acl_map_v6', 'whitelist', is_v6=True, filter_value=1)
    if cidrs_v6:
        print(f"  {Colors.CYAN}── IPv6 ──{Colors.END}")
        for cidr in sorted(cidrs_v6):
            print(f"  {Colors.GREEN}✓{Colors.END} {cidr}")
        total += len(cidrs_v6)
    
    if total == 0:
        print("  (empty)")
    
    print("=" * 50)
    print(f"Total: {total} entries")
    return 0

# ============================================================================
# BLACKLIST COMMANDS (LPM Trie - hỗ trợ CIDR notation)
# ============================================================================

def blacklist_add(ip_or_cidr):
    """Add IP or CIDR range to blacklist (ACL_DENY=2)"""
    return _lpm_add('acl_map', ip_or_cidr, 'blacklist', value_hex='0x02')

def blacklist_remove(ip_or_cidr):
    """Remove IP or CIDR range from blacklist"""
    return _lpm_remove('acl_map', ip_or_cidr, 'blacklist')

def blacklist_list():
    """List all blacklisted IPs/CIDRs (IPv4 + IPv6)"""
    print(f"{Colors.BOLD}Blacklisted IPs/CIDRs:{Colors.END}")
    print("=" * 50)
    
    total = 0
    
    # IPv4 blacklist (filter value==2 = ACL_DENY)
    cidrs_v4, err4 = _lpm_list('acl_map', 'blacklist', is_v6=False, filter_value=2)
    if cidrs_v4:
        print(f"  {Colors.CYAN}── IPv4 ──{Colors.END}")
        for cidr in sorted(cidrs_v4):
            print(f"  {Colors.RED}✗{Colors.END} {cidr}")
        total += len(cidrs_v4)
    
    # IPv6 blacklist
    cidrs_v6, err6 = _lpm_list('acl_map_v6', 'blacklist', is_v6=True, filter_value=2)
    if cidrs_v6:
        print(f"  {Colors.CYAN}── IPv6 ──{Colors.END}")
        for cidr in sorted(cidrs_v6):
            print(f"  {Colors.RED}✗{Colors.END} {cidr}")
        total += len(cidrs_v6)
    
    if total == 0:
        print("  (empty)")
    
    print("=" * 50)
    print(f"Total: {total} entries")
    return 0

# ============================================================================
# PORT COMMANDS
# ============================================================================

def port_add(port):
    """Add amplification port to block"""
    map_id = get_map_id('amp_ports_map')
    if not map_id:
        print(f"{Colors.RED}Error: amp_ports_map not found{Colors.END}")
        return 1
    
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            raise ValueError()
    except ValueError:
        print(f"{Colors.RED}Error: Invalid port: {port}{Colors.END}")
        return 1
    
    port_hex = port_to_hex(port_num)
    cmd = ['map', 'update', 'id', str(map_id), 'key', *port_hex.split(), 'value', '0x01']
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    print(f"{Colors.GREEN}✓ Added port {port_num} to block list{Colors.END}")
    return 0

def port_remove(port):
    """Remove port from block list"""
    map_id = get_map_id('amp_ports_map')
    if not map_id:
        print(f"{Colors.RED}Error: amp_ports_map not found{Colors.END}")
        return 1
    
    try:
        port_num = int(port)
    except ValueError:
        print(f"{Colors.RED}Error: Invalid port: {port}{Colors.END}")
        return 1
    
    port_hex = port_to_hex(port_num)
    cmd = ['map', 'delete', 'id', str(map_id), 'key', *port_hex.split()]
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    print(f"{Colors.GREEN}✓ Removed port {port_num} from block list{Colors.END}")
    return 0

def port_list():
    """List all blocked ports"""
    map_id = get_map_id('amp_ports_map')
    if not map_id:
        print(f"{Colors.RED}Error: amp_ports_map not found{Colors.END}")
        return 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    try:
        entries = json.loads(output) if output.strip() else []
        print(f"{Colors.BOLD}Blocked Amplification Ports:{Colors.END}")
        print("=" * 40)
        
        ports = []
        for entry in entries:
            key = entry.get('key')
            if key:
                port = hex_to_port(key)
                if port:
                    ports.append(port)
        
        if not ports:
            print("  (empty - run 'xdp_cli.py port init' to add defaults)")
        else:
            for port in sorted(ports):
                service = get_service_name(port)
                print(f"  {Colors.RED}✗{Colors.END} Port {port:5d}  ({service})")
        
        print("=" * 40)
        print(f"Total: {len(ports)} ports")
        return 0
    except json.JSONDecodeError:
        print(f"{Colors.RED}Error: Failed to parse response{Colors.END}")
        return 1

def port_init():
    """Initialize default amplification ports"""
    print(f"{Colors.CYAN}Initializing default amplification ports...{Colors.END}")
    for port in DEFAULT_AMP_PORTS:
        port_add(port)
    print(f"{Colors.GREEN}✓ Default ports initialized{Colors.END}")
    return 0

def get_service_name(port):
    """Get service name for known ports"""
    services = {
        53: "DNS",
        123: "NTP",
        1900: "SSDP",
        11211: "Memcached",
        19: "Chargen",
        17: "QOTD",
        161: "SNMP",
        389: "LDAP",
        27015: "Steam"
    }
    return services.get(port, "Unknown")

# ============================================================================
# CONFIG COMMANDS
# ============================================================================

def config_set(key, value):
    """Set configuration value"""
    map_id = get_map_id('config_map')
    if not map_id:
        print(f"{Colors.RED}Error: config_map not found{Colors.END}")
        return 1
    
    config_keys = {
        'pps-limit': CONFIG_UDP_PPS_LIMIT,
        'max-size': CONFIG_UDP_MAX_SIZE,
        'icmp-limit': CONFIG_ICMP_PPS_LIMIT,
        'syn-limit': CONFIG_SYN_PPS_LIMIT,
        'ip-stats': 4  # CONFIG_ENABLE_IP_STATS: 0=disabled, 1=enabled
    }
    
    if key not in config_keys:
        print(f"{Colors.RED}Error: Unknown config key: {key}{Colors.END}")
        print(f"Valid keys: {', '.join(config_keys.keys())}")
        return 1
    
    try:
        val = int(value)
        if val < 0:
            raise ValueError()
    except ValueError:
        print(f"{Colors.RED}Error: Invalid value: {value}{Colors.END}")
        return 1
    
    key_idx = config_keys[key]
    key_hex = u32_to_hex(key_idx)
    val_hex = u64_to_hex(val)
    
    cmd = ['map', 'update', 'id', str(map_id), 'key', *key_hex.split(), 'value', *val_hex.split()]
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    print(f"{Colors.GREEN}✓ Set {key} = {val}{Colors.END}")
    return 0

def config_show():
    """Show current configuration"""
    map_id = get_map_id('config_map')
    if not map_id:
        print(f"{Colors.RED}Error: config_map not found{Colors.END}")
        return 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    config_names = {
        CONFIG_UDP_PPS_LIMIT: ('UDP PPS Limit', DEFAULT_UDP_PPS_LIMIT),
        CONFIG_UDP_MAX_SIZE: ('UDP Max Size', DEFAULT_UDP_MAX_SIZE),
        CONFIG_ICMP_PPS_LIMIT: ('ICMP PPS Limit', DEFAULT_ICMP_PPS_LIMIT),
        CONFIG_SYN_PPS_LIMIT: ('SYN PPS Limit', DEFAULT_SYN_PPS_LIMIT)
    }
    
    try:
        entries = json.loads(output) if output.strip() else []
        values = {}
        
        for entry in entries:
            key = entry.get('key')
            value = entry.get('value')
            if key is not None and value is not None:
                if isinstance(key, list):
                    key_idx = hex_to_u64(key)
                else:
                    key_idx = int(key)
                if isinstance(value, list):
                    val = hex_to_u64(value)
                else:
                    val = int(value)
                values[key_idx] = val
        
        print(f"{Colors.BOLD}Current Configuration:{Colors.END}")
        print("=" * 50)
        
        for idx, (name, default) in config_names.items():
            val = values.get(idx, 0)
            if val == 0:
                val = default
                status = f"{Colors.YELLOW}(default){Colors.END}"
            else:
                status = ""
            print(f"  {name:20s}: {val:>10d} {status}")
        
        print("=" * 50)
        return 0
    except json.JSONDecodeError:
        print(f"{Colors.RED}Error: Failed to parse response{Colors.END}")
        return 1

def config_init():
    """Initialize default configuration"""
    print(f"{Colors.CYAN}Initializing default configuration...{Colors.END}")
    config_set('pps-limit', str(DEFAULT_UDP_PPS_LIMIT))
    config_set('max-size', str(DEFAULT_UDP_MAX_SIZE))
    config_set('icmp-limit', str(DEFAULT_ICMP_PPS_LIMIT))
    config_set('syn-limit', str(DEFAULT_SYN_PPS_LIMIT))
    print(f"{Colors.GREEN}✓ Default configuration initialized{Colors.END}")
    return 0

# ============================================================================
# STATS COMMANDS
# ============================================================================

def format_number(num):
    """Format number with K/M/B suffix"""
    if num < 1000:
        return str(int(num))
    elif num < 1000000:
        return f"{num/1000:.1f}K"
    elif num < 1000000000:
        return f"{num/1000000:.1f}M"
    else:
        return f"{num/1000000000:.1f}B"

def format_bytes(b):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"

def stats_show():
    """Show statistics"""
    map_id = get_map_id('global_stats_map')
    if not map_id:
        print(f"{Colors.RED}Error: global_stats_map not found{Colors.END}")
        return 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    try:
        entries = json.loads(output) if output.strip() else []
        
        total = {
            'packets_passed': 0, 'bytes_passed': 0,
            'packets_dropped': 0, 'bytes_dropped': 0,
            'packets_redirected': 0, 'bytes_redirected': 0,
            'drop_reasons': [0] * 11
        }
        
        for entry in entries:
            values = entry.get('values', [])
            for cpu_entry in values:
                if isinstance(cpu_entry, dict) and 'value' in cpu_entry:
                    ext = cpu_entry['value']
                    
                    if isinstance(ext, list):
                        try:
                            data = bytes([int(x, 16) for x in ext])
                            if len(data) >= 264:
                                fields = struct.unpack('<33Q', data[:264])
                                total['packets_passed'] += fields[0]
                                total['bytes_passed'] += fields[1]
                                total['packets_dropped'] += fields[2]
                                total['bytes_dropped'] += fields[3]
                                total['packets_redirected'] += fields[4]
                                total['bytes_redirected'] += fields[5]
                                for j in range(11):
                                    total['drop_reasons'][j] += fields[6+j]
                        except:
                            pass
                    elif isinstance(ext, dict):
                        total['packets_passed'] += ext.get('packets_passed', 0)
                        total['bytes_passed'] += ext.get('bytes_passed', 0)
                        total['packets_dropped'] += ext.get('packets_dropped', 0)
                        total['bytes_dropped'] += ext.get('bytes_dropped', 0)
                        total['packets_redirected'] += ext.get('packets_redirected', 0)
                        total['bytes_redirected'] += ext.get('bytes_redirected', 0)
                        reasons = ext.get('drop_reasons', [])
                        if isinstance(reasons, list):
                            for j, r in enumerate(reasons[:11]):
                                total['drop_reasons'][j] += int(r)
        
        total_pkts = total['packets_passed'] + total['packets_dropped'] + total['packets_redirected']
        drop_rate = (total['packets_dropped'] / total_pkts * 100) if total_pkts > 0 else 0
        
        print(f"{Colors.BOLD}XDP Anti-DDoS Statistics:{Colors.END}")
        print("=" * 60)
        print(f"  {Colors.GREEN}Passed:{Colors.END}    {format_number(total['packets_passed']):>12} pkts | {format_bytes(total['bytes_passed']):>12}")
        print(f"  {Colors.RED}Dropped:{Colors.END}   {format_number(total['packets_dropped']):>12} pkts | {format_bytes(total['bytes_dropped']):>12}")
        print(f"  {Colors.CYAN}Redirected:{Colors.END} {format_number(total['packets_redirected']):>12} pkts | {format_bytes(total['bytes_redirected']):>12}")
        print(f"  {Colors.YELLOW}Drop Rate:{Colors.END} {drop_rate:>10.2f}%")
        print()
        print(f"{Colors.BOLD}Drop Reasons:{Colors.END}")
        print("-" * 60)
        
        for i, count in enumerate(total['drop_reasons']):
            if count > 0:
                reason = DROP_REASONS.get(i, f"Reason {i}")
                pct = (count / total['packets_dropped'] * 100) if total['packets_dropped'] > 0 else 0
                print(f"  {reason:25s}: {format_number(count):>10} ({pct:5.1f}%)")
        
        print("=" * 60)
        return 0
    except json.JSONDecodeError:
        print(f"{Colors.RED}Error: Failed to parse response{Colors.END}")
        return 1

def stats_top(limit=10):
    """Show top IPs by traffic"""
    print(f"{Colors.YELLOW}Note: Per-IP statistics (ip_stats_map) have been removed from the kernel \nto optimize performance under DDoS conditions.{Colors.END}")
    return 0

def stats_clear():
    """Clear all statistics from global_stats_map"""
    map_id = get_map_id('global_stats_map')
    if not map_id:
        print(f"{Colors.RED}Error: global_stats_map not found{Colors.END}")
        return 1

    try:
        libc = ctypes.CDLL("libc.so.6")

        class bpf_attr_get_fd(ctypes.Structure):
            _fields_ = [("map_id", ctypes.c_uint32), ("next_id", ctypes.c_uint32), ("open_flags", ctypes.c_uint32)]

        class bpf_attr_update(ctypes.Structure):
            _fields_ = [("map_fd", ctypes.c_uint32), ("key", ctypes.c_uint64), ("value", ctypes.c_uint64), ("flags", ctypes.c_uint64)]

        # BPF_MAP_GET_FD_BY_ID = 14
        attr1 = bpf_attr_get_fd(map_id=int(map_id))
        fd = libc.syscall(321, 14, ctypes.byref(attr1), ctypes.sizeof(attr1))
        if fd < 0:
            print(f"{Colors.RED}Error: Failed to get fd for map_id {map_id}{Colors.END}")
            return 1
        
        num_cpus = os.cpu_count() or 1
        key = ctypes.c_uint32(0)
        value = (ctypes.c_uint8 * (256 * num_cpus))()
        
        # BPF_MAP_UPDATE_ELEM = 2
        attr2 = bpf_attr_update(map_fd=fd, key=ctypes.addressof(key), value=ctypes.addressof(value), flags=0)
        res = libc.syscall(321, 2, ctypes.byref(attr2), ctypes.sizeof(attr2))
        
        if res == 0:
            print(f"{Colors.GREEN}✓ Statistics cleared successfully{Colors.END}")
            return 0
        else:
            print(f"{Colors.RED}Error: Failed to clear stats, syscall returned {res}{Colors.END}")
            return 1
    except Exception as e:
        print(f"{Colors.RED}Error clearing statistics: {e}{Colors.END}")
        return 1
# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='XDP Anti-DDoS CLI Tool (LPM Trie - CIDR support)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s whitelist add 8.8.8.8           # Add single IP (auto /32)
  %(prog)s whitelist add 10.0.0.0/8        # Add entire /8 subnet
  %(prog)s whitelist add 2001:db8::/32      # Add IPv6 subnet
  %(prog)s blacklist add 192.168.0.0/16     # Block entire /16 subnet
  %(prog)s blacklist add fe80::1            # Block single IPv6 (auto /128)
  %(prog)s port init                       # Initialize default blocked ports
  %(prog)s config set pps-limit 20000      # Set UDP rate limit to 20k pps
  %(prog)s stats show                      # Show statistics
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Whitelist commands
    wl_parser = subparsers.add_parser('whitelist', help='Manage IP/CIDR whitelist')
    wl_sub = wl_parser.add_subparsers(dest='action')
    wl_add = wl_sub.add_parser('add', help='Add IP/CIDR to whitelist')
    wl_add.add_argument('ip', help='IP address or CIDR range (e.g. 10.0.0.0/8, 8.8.8.8, 2001:db8::/32)')
    wl_rm = wl_sub.add_parser('remove', help='Remove IP/CIDR from whitelist')
    wl_rm.add_argument('ip', help='IP address or CIDR range to remove')
    wl_sub.add_parser('list', help='List whitelisted IPs/CIDRs')
    
    # Blacklist commands
    bl_parser = subparsers.add_parser('blacklist', help='Manage IP/CIDR blacklist')
    bl_sub = bl_parser.add_subparsers(dest='action')
    bl_add = bl_sub.add_parser('add', help='Add IP/CIDR to blacklist')
    bl_add.add_argument('ip', help='IP address or CIDR range (e.g. 10.0.0.0/8, 1.2.3.4, fe80::/10)')
    bl_rm = bl_sub.add_parser('remove', help='Remove IP/CIDR from blacklist')
    bl_rm.add_argument('ip', help='IP address or CIDR range to remove')
    bl_sub.add_parser('list', help='List blacklisted IPs/CIDRs')
    
    # Port commands
    port_parser = subparsers.add_parser('port', help='Manage blocked ports')
    port_sub = port_parser.add_subparsers(dest='action')
    port_add_p = port_sub.add_parser('add', help='Add port to block')
    port_add_p.add_argument('port', help='Port number')
    port_rm = port_sub.add_parser('remove', help='Remove port from block list')
    port_rm.add_argument('port', help='Port number')
    port_sub.add_parser('list', help='List blocked ports')
    port_sub.add_parser('init', help='Initialize default ports')
    
    # Config commands
    cfg_parser = subparsers.add_parser('config', help='Manage configuration')
    cfg_sub = cfg_parser.add_subparsers(dest='action')
    cfg_set = cfg_sub.add_parser('set', help='Set config value')
    cfg_set.add_argument('key', help='Config key (pps-limit, max-size, icmp-limit, syn-limit)')
    cfg_set.add_argument('value', help='Config value')
    cfg_sub.add_parser('show', help='Show current configuration')
    cfg_sub.add_parser('init', help='Initialize default configuration')
    
    # Stats commands
    stats_parser = subparsers.add_parser('stats', help='View statistics')
    stats_sub = stats_parser.add_subparsers(dest='action')
    stats_sub.add_parser('show', help='Show statistics')
    stats_sub.add_parser('clear', help='Clear statistics')
    stats_top_p = stats_sub.add_parser('top', help='Show top IPs')
    stats_top_p.add_argument('-n', '--limit', type=int, default=10, help='Number of IPs to show')
    
    # Init all
    subparsers.add_parser('init', help='Initialize all default values')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Handle commands
    if args.command == 'whitelist':
        if args.action == 'add':
            return whitelist_add(args.ip)
        elif args.action == 'remove':
            return whitelist_remove(args.ip)
        elif args.action == 'list':
            return whitelist_list()
        else:
            wl_parser.print_help()
            return 1
    
    elif args.command == 'blacklist':
        if args.action == 'add':
            return blacklist_add(args.ip)
        elif args.action == 'remove':
            return blacklist_remove(args.ip)
        elif args.action == 'list':
            return blacklist_list()
        else:
            bl_parser.print_help()
            return 1
    
    elif args.command == 'port':
        if args.action == 'add':
            return port_add(args.port)
        elif args.action == 'remove':
            return port_remove(args.port)
        elif args.action == 'list':
            return port_list()
        elif args.action == 'init':
            return port_init()
        else:
            port_parser.print_help()
            return 1
    
    elif args.command == 'config':
        if args.action == 'set':
            return config_set(args.key, args.value)
        elif args.action == 'show':
            return config_show()
        elif args.action == 'init':
            return config_init()
        else:
            cfg_parser.print_help()
            return 1
    
    elif args.command == 'stats':
        if args.action == 'show':
            return stats_show()
        elif args.action == 'clear':
            return stats_clear()
        elif args.action == 'top':
            return stats_top(args.limit)
        else:
            stats_parser.print_help()
            return 1
    
    elif args.command == 'init':
        print(f"{Colors.CYAN}Initializing XDP Anti-DDoS...{Colors.END}")
        port_init()
        config_init()
        print(f"{Colors.GREEN}✓ Initialization complete{Colors.END}")
        return 0
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
