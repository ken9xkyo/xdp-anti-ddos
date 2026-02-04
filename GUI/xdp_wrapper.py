#!/usr/bin/env python3
import subprocess
import json
import socket
import traceback


# Config constants
CONFIG_UDP_PPS_LIMIT = 0
CONFIG_UDP_MAX_SIZE = 1
CONFIG_ICMP_PPS_LIMIT = 2
CONFIG_SYN_PPS_LIMIT = 3

DEFAULT_UDP_PPS_LIMIT = 10000
DEFAULT_UDP_MAX_SIZE = 1024
DEFAULT_ICMP_PPS_LIMIT = 100
DEFAULT_SYN_PPS_LIMIT = 10000

# Drop reasons
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

def run_bpftool(args):
    """Run bpftool command and return output"""
    cmd = ['bpftool'] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return None, str(e), -1

def get_active_xdp_map_ids():
    """Get map IDs from the currently active XDP program"""
    output, err, rc = run_bpftool(['prog', 'show', '-j'])
    if rc != 0:
        return []
    try:
        progs = json.loads(output)
        for prog in progs:
            if prog.get('type') == 'xdp' and 'xdp_anti_ddos' in prog.get('name', ''):
                return prog.get('map_ids', [])
        # Fallback
        for prog in progs:
            if prog.get('type') == 'xdp':
                return prog.get('map_ids', [])
    except:
        pass
    return []

def get_map_id(map_name):
    """Get BPF map ID by name"""
    active_map_ids = get_active_xdp_map_ids()
    output, err, rc = run_bpftool(['map', 'show', '-j'])
    if rc != 0:
        return None
    try:
        maps = json.loads(output)
        if active_map_ids:
            for m in maps:
                if m.get('name') == map_name and m.get('id') in active_map_ids:
                    return m.get('id')
        matching_maps = [m for m in maps if m.get('name') == map_name]
        if matching_maps:
            matching_maps.sort(key=lambda x: x.get('id', 0), reverse=True)
            return matching_maps[0].get('id')
    except:
        pass
    return None

def ip_to_hex(ip_str):
    try:
        packed = socket.inet_aton(ip_str)
        return ' '.join(f'0x{b:02x}' for b in packed)
    except:
        return None

def hex_to_ip(hex_bytes):
    try:
        if isinstance(hex_bytes, list):
            bytes_val = bytes(int(h, 16) for h in hex_bytes)
            return socket.inet_ntoa(bytes_val)
        return None
    except:
        return None

def port_to_hex(port):
    return f'0x{port & 0xff:02x} 0x{(port >> 8) & 0xff:02x}'

def hex_to_port(hex_bytes):
    try:
        if isinstance(hex_bytes, list) and len(hex_bytes) >= 2:
            low = int(hex_bytes[0], 16)
            high = int(hex_bytes[1], 16)
            return low | (high << 8)
        return None
    except:
        return None

def u32_to_hex(val):
    return ' '.join(f'0x{(val >> (i*8)) & 0xff:02x}' for i in range(4))

def u64_to_hex(val):
    return ' '.join(f'0x{(val >> (i*8)) & 0xff:02x}' for i in range(8))

def hex_to_u64(hex_bytes):
    try:
        if isinstance(hex_bytes, list):
            val = 0
            for i, h in enumerate(hex_bytes[:8]):
                val |= int(h, 16) << (i * 8)
            return val
        return 0
    except:
        return 0

# ================= Public API =================

def get_stats():
    """Get statistics summary"""
    map_id = get_map_id('stats_map')
    if not map_id:
        return {'error': 'Map not found'}
    
    output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if rc != 0:
        return {'error': err}
    
    total = {
        'packets_passed': 0, 'bytes_passed': 0,
        'packets_dropped': 0, 'bytes_dropped': 0,
        'drop_reasons': {}
    }
    
    try:
        entries = json.loads(output)
        raw_reasons = [0] * 10
        for entry in entries:
            for cpu_entry in entry.get('values', []):
                stats = cpu_entry.get('value', {})
                # BPF map dump represented as empty list or raw bytes for some CPUs
                if isinstance(stats, list):
                    # Check if it's a list of hex strings (raw bytes)
                    if not stats: continue
                    
                    try:
                        # Convert hex strings to bytes
                        # Each element is like "0x00"
                        byte_data = bytes(int(x, 16) for x in stats)
                        
                        # Struct layout: 4 u64 counters + 10 u64 drop reasons
                        # 4 + 10 = 14 u64s = 14 * 8 = 112 bytes
                        # The map value size is 128 bytes (padding at end)
                        
                        import struct
                        # < = little endian, 14Q = 14 unsigned long longs
                        values = struct.unpack('<14Q', byte_data[:112])
                        
                        stats = {
                            'packets_passed': values[0],
                            'bytes_passed': values[1],
                            'packets_dropped': values[2],
                            'bytes_dropped': values[3],
                            'drop_reasons': values[4:]
                        }
                    except Exception as e:
                        # print(f"DEBUG: Failed to parse raw stats: {e}", file=sys.stderr)
                        continue

                total['packets_passed'] += stats.get('packets_passed', 0)
                total['bytes_passed'] += stats.get('bytes_passed', 0)
                total['packets_dropped'] += stats.get('packets_dropped', 0)
                total['bytes_dropped'] += stats.get('bytes_dropped', 0)
                
                reasons = stats.get('drop_reasons', [])
                if isinstance(reasons, list) or isinstance(reasons, tuple):
                    for i, r in enumerate(reasons[:10]):
                        raw_reasons[i] += int(r)
        
        for i, count in enumerate(raw_reasons):
            total['drop_reasons'][DROP_REASONS.get(i, f"Reason {i}")] = count
            
        return total
    except Exception as e:
        return {'error': f"{str(e)}\n{traceback.format_exc()}"}

def get_whitelist():
    """Get list of whitelisted IPs"""
    map_id = get_map_id('whitelist_map')
    if not map_id:
        return []
    
    output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if rc != 0:
        return []
    
    ips = []
    try:
        entries = json.loads(output)
        for entry in entries:
            key = entry.get('key')
            if key:
                ip = hex_to_ip(key)
                if ip:
                    ips.append(ip)
    except:
        pass
    return ips

def add_whitelist(ip):
    map_id = get_map_id('whitelist_map')
    if not map_id: return "Map not found"
    ip_hex = ip_to_hex(ip)
    if not ip_hex: return "Invalid IP"
    
    output, err, rc = run_bpftool(['map', 'update', 'id', str(map_id), 'key', *ip_hex.split(), 'value', '0x01'])
    return err if rc != 0 else None

def remove_whitelist(ip):
    map_id = get_map_id('whitelist_map')
    if not map_id: return "Map not found"
    ip_hex = ip_to_hex(ip)
    if not ip_hex: return "Invalid IP"
    
    output, err, rc = run_bpftool(['map', 'delete', 'id', str(map_id), 'key', *ip_hex.split()])
    return err if rc != 0 else None

def get_ports():
    """Get list of blocked ports"""
    map_id = get_map_id('amp_ports_map')
    if not map_id:
        return []
    
    output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if rc != 0:
        return []
    
    ports = []
    try:
        entries = json.loads(output)
        for entry in entries:
            key = entry.get('key')
            if key:
                port = hex_to_port(key)
                if port:
                    ports.append(port)
    except:
        pass
    return sorted(ports)

def add_port(port):
    map_id = get_map_id('amp_ports_map')
    if not map_id: return "Map not found"
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535: raise ValueError()
    except:
        return "Invalid port"
        
    port_hex = port_to_hex(port_num)
    output, err, rc = run_bpftool(['map', 'update', 'id', str(map_id), 'key', *port_hex.split(), 'value', '0x01'])
    return err if rc != 0 else None

def remove_port(port):
    map_id = get_map_id('amp_ports_map')
    if not map_id: return "Map not found"
    try:
        port_num = int(port)
    except:
        return "Invalid port"
        
    port_hex = port_to_hex(port_num)
    output, err, rc = run_bpftool(['map', 'delete', 'id', str(map_id), 'key', *port_hex.split()])
    return err if rc != 0 else None

def get_config():
    """Get current configuration"""
    map_id = get_map_id('config_map')
    if not map_id:
        return {}
    
    output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if rc != 0:
        return {}
        
    config = {
        'pps_limit': DEFAULT_UDP_PPS_LIMIT,
        'max_size': DEFAULT_UDP_MAX_SIZE,
        'icmp_limit': DEFAULT_ICMP_PPS_LIMIT,
        'syn_limit': DEFAULT_SYN_PPS_LIMIT
    }
    
    try:
        entries = json.loads(output)
        mapping = {
            CONFIG_UDP_PPS_LIMIT: 'pps_limit',
            CONFIG_UDP_MAX_SIZE: 'max_size',
            CONFIG_ICMP_PPS_LIMIT: 'icmp_limit',
            CONFIG_SYN_PPS_LIMIT: 'syn_limit'
        }
        
        for entry in entries:
            key = entry.get('key')
            value = entry.get('value')
            if key is not None and value is not None:
                if isinstance(key, list): key_idx = hex_to_u64(key)
                else: key_idx = int(key)
                
                if isinstance(value, list): val = hex_to_u64(value)
                else: val = int(value)
                
                if key_idx in mapping:
                    config[mapping[key_idx]] = val if val > 0 else config[mapping[key_idx]]
    except:
        pass
    return config

def set_config(key, value):
    map_id = get_map_id('config_map')
    if not map_id: return "Map not found"
    
    keys = {
        'pps_limit': CONFIG_UDP_PPS_LIMIT,
        'max_size': CONFIG_UDP_MAX_SIZE,
        'icmp_limit': CONFIG_ICMP_PPS_LIMIT,
        'syn_limit': CONFIG_SYN_PPS_LIMIT
    }
    
    if key not in keys: return "Invalid key"
    try:
        val = int(value)
    except:
        return "Invalid value"
        
    key_idx = keys[key]
    key_hex = u32_to_hex(key_idx)
    val_hex = u64_to_hex(val)
    
    output, err, rc = run_bpftool(['map', 'update', 'id', str(map_id), 'key', *key_hex.split(), 'value', *val_hex.split()])
    return err if rc != 0 else None
