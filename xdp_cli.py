#!/usr/bin/env python3
"""
XDP Anti-DDoS CLI Tool
Manage whitelist, ports, configuration, and statistics via BPF maps.

Usage:
    xdp_cli.py whitelist add <IP>        # Add IP to whitelist
    xdp_cli.py whitelist remove <IP>     # Remove IP from whitelist
    xdp_cli.py whitelist list            # List whitelisted IPs
    
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
    9: "Parse Error"
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
    """Get map IDs from the currently active XDP program"""
    output, err = run_bpftool(['prog', 'show', '-j'])
    if err:
        return []
    try:
        progs = json.loads(output)
        # Find XDP programs
        for prog in progs:
            if prog.get('type') == 'xdp' and 'xdp_anti_ddos' in prog.get('name', ''):
                return prog.get('map_ids', [])
        # Fallback: any XDP program
        for prog in progs:
            if prog.get('type') == 'xdp':
                return prog.get('map_ids', [])
    except json.JSONDecodeError:
        pass
    return []

def get_map_id(map_name):
    """Get BPF map ID by name from the active XDP program"""
    # First get the map IDs from the active XDP program
    active_map_ids = get_active_xdp_map_ids()
    
    output, err = run_bpftool(['map', 'show', '-j'])
    if err:
        return None
    try:
        maps = json.loads(output)
        
        # If we have active map IDs, prefer maps from active program
        if active_map_ids:
            for m in maps:
                if m.get('name') == map_name and m.get('id') in active_map_ids:
                    return m.get('id')
        
        # Fallback: find the highest ID (most recently created)
        matching_maps = [m for m in maps if m.get('name') == map_name]
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
# WHITELIST COMMANDS
# ============================================================================

def whitelist_add(ip):
    """Add IP to whitelist"""
    map_id = get_map_id('whitelist_map')
    if not map_id:
        print(f"{Colors.RED}Error: whitelist_map not found. Is XDP program loaded?{Colors.END}")
        return 1
    
    ip_hex = ip_to_hex(ip)
    if not ip_hex:
        print(f"{Colors.RED}Error: Invalid IP address: {ip}{Colors.END}")
        return 1
    
    # Value is __u8 = 1
    cmd = ['map', 'update', 'id', str(map_id), 'key', *ip_hex.split(), 'value', '0x01']
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    print(f"{Colors.GREEN}✓ Added {ip} to whitelist{Colors.END}")
    return 0

def whitelist_remove(ip):
    """Remove IP from whitelist"""
    map_id = get_map_id('whitelist_map')
    if not map_id:
        print(f"{Colors.RED}Error: whitelist_map not found{Colors.END}")
        return 1
    
    ip_hex = ip_to_hex(ip)
    if not ip_hex:
        print(f"{Colors.RED}Error: Invalid IP address: {ip}{Colors.END}")
        return 1
    
    cmd = ['map', 'delete', 'id', str(map_id), 'key', *ip_hex.split()]
    output, err = run_bpftool(cmd)
    
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    print(f"{Colors.GREEN}✓ Removed {ip} from whitelist{Colors.END}")
    return 0

def whitelist_list():
    """List all whitelisted IPs"""
    map_id = get_map_id('whitelist_map')
    if not map_id:
        print(f"{Colors.RED}Error: whitelist_map not found{Colors.END}")
        return 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    try:
        entries = json.loads(output) if output.strip() else []
        print(f"{Colors.BOLD}Whitelisted IPs:{Colors.END}")
        print("=" * 40)
        
        if not entries:
            print("  (empty)")
        else:
            for entry in entries:
                key = entry.get('key')
                if key:
                    ip = hex_to_ip(key)
                    if ip:
                        print(f"  {Colors.GREEN}✓{Colors.END} {ip}")
        
        print("=" * 40)
        print(f"Total: {len(entries)} IPs")
        return 0
    except json.JSONDecodeError:
        print(f"{Colors.RED}Error: Failed to parse response{Colors.END}")
        return 1

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
    map_id = get_map_id('stats_map')
    if not map_id:
        print(f"{Colors.RED}Error: stats_map not found{Colors.END}")
        return 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id)])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    try:
        entries = json.loads(output) if output.strip() else []
        
        total = {
            'packets_passed': 0,
            'bytes_passed': 0,
            'packets_dropped': 0,
            'bytes_dropped': 0,
            'drop_reasons': [0] * 10
        }
        
        for entry in entries:
            values = entry.get('values', [])
            for cpu_entry in values:
                if isinstance(cpu_entry, dict) and 'value' in cpu_entry:
                    stats = cpu_entry['value']
                    if isinstance(stats, dict):
                        total['packets_passed'] += stats.get('packets_passed', 0)
                        total['bytes_passed'] += stats.get('bytes_passed', 0)
                        total['packets_dropped'] += stats.get('packets_dropped', 0)
                        total['bytes_dropped'] += stats.get('bytes_dropped', 0)
                        
                        reasons = stats.get('drop_reasons', [])
                        if isinstance(reasons, list):
                            for i, r in enumerate(reasons[:10]):
                                total['drop_reasons'][i] += int(r)
        
        total_pkts = total['packets_passed'] + total['packets_dropped']
        drop_rate = (total['packets_dropped'] / total_pkts * 100) if total_pkts > 0 else 0
        
        print(f"{Colors.BOLD}XDP Anti-DDoS Statistics:{Colors.END}")
        print("=" * 60)
        print(f"  {Colors.GREEN}Passed:{Colors.END}  {format_number(total['packets_passed']):>12} pkts | {format_bytes(total['bytes_passed']):>12}")
        print(f"  {Colors.RED}Dropped:{Colors.END} {format_number(total['packets_dropped']):>12} pkts | {format_bytes(total['bytes_dropped']):>12}")
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
    map_id = get_map_id('ip_stats_map')
    if not map_id:
        print(f"{Colors.RED}Error: ip_stats_map not found{Colors.END}")
        return 1
    
    output, err = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if err:
        print(f"{Colors.RED}Error: {err}{Colors.END}")
        return 1
    
    try:
        entries = json.loads(output) if output.strip() else []
        
        ip_data = []
        for entry in entries:
            key = entry.get('key')
            value = entry.get('value')
            
            if key and value:
                ip = hex_to_ip(key)
                if ip and isinstance(value, dict):
                    ip_data.append({
                        'ip': ip,
                        'passed': value.get('packets_passed', 0),
                        'dropped': value.get('packets_dropped', 0),
                        'bytes_passed': value.get('bytes_passed', 0),
                        'bytes_dropped': value.get('bytes_dropped', 0)
                    })
        
        # Top dropped
        print(f"{Colors.BOLD}Top {limit} Blocked IPs:{Colors.END}")
        print("=" * 70)
        top_dropped = sorted(ip_data, key=lambda x: x['dropped'], reverse=True)[:limit]
        for i, ip in enumerate(top_dropped, 1):
            if ip['dropped'] > 0:
                print(f"  {i:2d}. {ip['ip']:15s} | {Colors.RED}Dropped:{Colors.END} {format_number(ip['dropped']):>10} pkts")
        if not top_dropped or all(ip['dropped'] == 0 for ip in top_dropped):
            print("  (no blocked IPs)")
        
        print()
        
        # Top passed
        print(f"{Colors.BOLD}Top {limit} Passed IPs:{Colors.END}")
        print("=" * 70)
        top_passed = sorted(ip_data, key=lambda x: x['passed'], reverse=True)[:limit]
        for i, ip in enumerate(top_passed, 1):
            if ip['passed'] > 0:
                print(f"  {i:2d}. {ip['ip']:15s} | {Colors.GREEN}Passed:{Colors.END}  {format_number(ip['passed']):>10} pkts")
        if not top_passed or all(ip['passed'] == 0 for ip in top_passed):
            print("  (no passed IPs)")
        
        print("=" * 70)
        return 0
    except json.JSONDecodeError:
        print(f"{Colors.RED}Error: Failed to parse response{Colors.END}")
        return 1

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='XDP Anti-DDoS CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s whitelist add 8.8.8.8       # Add Google DNS to whitelist
  %(prog)s port init                   # Initialize default blocked ports
  %(prog)s config set pps-limit 20000  # Set UDP rate limit to 20k pps
  %(prog)s stats show                  # Show statistics
  %(prog)s stats top                   # Show top IPs
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Whitelist commands
    wl_parser = subparsers.add_parser('whitelist', help='Manage IP whitelist')
    wl_sub = wl_parser.add_subparsers(dest='action')
    wl_add = wl_sub.add_parser('add', help='Add IP to whitelist')
    wl_add.add_argument('ip', help='IP address to add')
    wl_rm = wl_sub.add_parser('remove', help='Remove IP from whitelist')
    wl_rm.add_argument('ip', help='IP address to remove')
    wl_sub.add_parser('list', help='List whitelisted IPs')
    
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
