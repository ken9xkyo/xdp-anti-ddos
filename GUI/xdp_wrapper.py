#!/usr/bin/env python3
import subprocess
import json
import socket
import struct
import traceback
import os
import ipaddress


# Config constants - match xdp_anti_ddos.c
CONFIG_UDP_PPS_LIMIT = 0
CONFIG_UDP_MAX_SIZE = 1
CONFIG_ICMP_PPS_LIMIT = 2
CONFIG_SYN_PPS_LIMIT = 3
CONFIG_MAX_ENTRIES = 8

DEFAULT_UDP_PPS_LIMIT = 10000
DEFAULT_UDP_MAX_SIZE = 1024
DEFAULT_ICMP_PPS_LIMIT = 100
DEFAULT_SYN_PPS_LIMIT = 10000

# Drop reasons - match xdp_anti_ddos.c
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

# Pinned map paths
PINNED_MAP = "/sys/fs/bpf/vm_redirect_map"
PINNED_TX_PORT_MAP = "/sys/fs/bpf/tx_port_map"

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
        # Handle truncated names (kernel limits to ~15 chars)
        name_prefix = map_name[:15] if len(map_name) > 15 else map_name

        if active_map_ids:
            for m in maps:
                mn = m.get('name', '')
                if (mn == map_name or mn.startswith(name_prefix)) and m.get('id') in active_map_ids:
                    return m.get('id')
        matching_maps = [m for m in maps if m.get('name', '') == map_name or m.get('name', '').startswith(name_prefix)]
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

# ================= LPM Trie Helpers =================

def is_ipv6(addr_str):
    """Check if an address string is IPv6"""
    return ':' in addr_str.split('/')[0]

def cidr_to_lpm_hex(cidr_str):
    """Convert IP/CIDR string to LPM trie key hex.
    
    Supports IPv4 and IPv6. Auto-adds /32 or /128 for bare IPs.
    Returns: (hex_string, normalized_cidr, is_v6) or (None, None, None)
    """
    try:
        v6 = is_ipv6(cidr_str)
        if v6:
            if '/' not in cidr_str:
                cidr_str += '/128'
            network = ipaddress.ip_network(cidr_str, strict=False)
        else:
            if '/' not in cidr_str:
                cidr_str += '/32'
            network = ipaddress.ip_network(cidr_str, strict=False)
        
        prefixlen = network.prefixlen
        addr_bytes = network.network_address.packed
        
        prefix_hex = ' '.join(f'0x{b:02x}' for b in prefixlen.to_bytes(4, 'little'))
        addr_hex = ' '.join(f'0x{b:02x}' for b in addr_bytes)
        
        return f'{prefix_hex} {addr_hex}', str(network), v6
    except (ValueError, TypeError):
        return None, None, None

def lpm_hex_to_cidr(hex_bytes, is_v6=False):
    """Convert LPM trie key hex bytes back to CIDR string."""
    try:
        if not isinstance(hex_bytes, list):
            return None
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

# ================= Public API =================

def get_stats():
    """Get statistics from global_stats_map.

    Struct layout (xdp_global_stats) - 32 x u64 = 256 bytes:
      [0]  packets_passed
      [1]  bytes_passed
      [2]  packets_dropped
      [3]  bytes_dropped
      [4]  packets_redirected
      [5]  bytes_redirected
      [6-15]  drop_reasons[10]
      [16] proto_udp
      [17] proto_tcp
      [18] proto_icmp
      [19] proto_other
      [20-25] pkt_size_buckets[6]  (0-64, 65-128, 129-256, 257-512, 513-1024, 1025+)
      [26] sport_dns
      [27] sport_ntp
      [28] sport_ssdp
      [29] sport_memcached
      [30] sport_chargen
      [31] sport_other_reflection
    """
    map_id = get_map_id('global_stats_map')
    if not map_id:
        return {'error': 'Map not found. Is the XDP program loaded?'}

    output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if rc != 0:
        return {'error': err}

    total = {
        'packets_passed': 0, 'bytes_passed': 0,
        'packets_dropped': 0, 'bytes_dropped': 0,
        'packets_redirected': 0, 'bytes_redirected': 0,
        'drop_reasons': {},
        'protocols': {'UDP': 0, 'TCP': 0, 'ICMP': 0, 'Other': 0},
        'pkt_size_buckets': [0] * 6,
        'reflection_ports': {
            'DNS (53)': 0, 'NTP (123)': 0, 'SSDP (1900)': 0,
            'Memcached (11211)': 0, 'Chargen (19)': 0, 'Other (<1024)': 0
        }
    }

    raw_reasons = [0] * 11
    raw_protos = [0, 0, 0, 0]
    raw_buckets = [0] * 6
    raw_sports = [0, 0, 0, 0, 0, 0]

    try:
        entries = json.loads(output)
        for entry in entries:
            for cpu_entry in entry.get('values', []):
                ext = cpu_entry.get('value', {})

                if isinstance(ext, list):
                    if not ext:
                        continue
                    try:
                        data = bytes(int(x, 16) for x in ext)
                        if len(data) >= 264:
                            fields = struct.unpack('<33Q', data[:264])

                            total['packets_passed'] += fields[0]
                            total['bytes_passed'] += fields[1]
                            total['packets_dropped'] += fields[2]
                            total['bytes_dropped'] += fields[3]
                            total['packets_redirected'] += fields[4]
                            total['bytes_redirected'] += fields[5]

                            for j in range(11):
                                raw_reasons[j] += fields[6 + j]

                            for j in range(4):
                                raw_protos[j] += fields[17 + j]

                            for j in range(6):
                                raw_buckets[j] += fields[21 + j]

                            for j in range(6):
                                raw_sports[j] += fields[27 + j]
                    except Exception:
                        continue

                elif isinstance(ext, dict):
                    total['packets_passed'] += ext.get('packets_passed', 0)
                    total['bytes_passed'] += ext.get('bytes_passed', 0)
                    total['packets_dropped'] += ext.get('packets_dropped', 0)
                    total['bytes_dropped'] += ext.get('bytes_dropped', 0)
                    total['packets_redirected'] += ext.get('packets_redirected', 0)
                    total['bytes_redirected'] += ext.get('bytes_redirected', 0)

                    reasons = ext.get('drop_reasons', [])
                    if isinstance(reasons, (list, tuple)):
                        for j, r in enumerate(reasons[:11]):
                            raw_reasons[j] += int(r)

                    raw_protos[0] += ext.get('proto_udp', 0)
                    raw_protos[1] += ext.get('proto_tcp', 0)
                    raw_protos[2] += ext.get('proto_icmp', 0)
                    raw_protos[3] += ext.get('proto_other', 0)

                    buckets = ext.get('pkt_size_buckets', [])
                    if isinstance(buckets, (list, tuple)):
                        for j, v in enumerate(buckets[:6]):
                            raw_buckets[j] += int(v)

                    raw_sports[0] += ext.get('sport_dns', 0)
                    raw_sports[1] += ext.get('sport_ntp', 0)
                    raw_sports[2] += ext.get('sport_ssdp', 0)
                    raw_sports[3] += ext.get('sport_memcached', 0)
                    raw_sports[4] += ext.get('sport_chargen', 0)
                    raw_sports[5] += ext.get('sport_other_reflection', 0)

        # Assemble drop reasons
        for i, count in enumerate(raw_reasons):
            total['drop_reasons'][DROP_REASONS.get(i, f"Reason {i}")] = count

        # Assemble protocols
        proto_names = ['UDP', 'TCP', 'ICMP', 'Other']
        for i, name in enumerate(proto_names):
            total['protocols'][name] = raw_protos[i]

        # Assemble packet size buckets
        total['pkt_size_buckets'] = raw_buckets

        # Assemble reflection ports
        sport_names = ['DNS (53)', 'NTP (123)', 'SSDP (1900)', 'Memcached (11211)', 'Chargen (19)', 'Other (<1024)']
        for i, name in enumerate(sport_names):
            total['reflection_ports'][name] = raw_sports[i]

        return total
    except Exception as e:
        return {'error': f"{str(e)}\n{traceback.format_exc()}"}

def get_whitelist():
    """Get list of whitelisted IPs/CIDRs (IPv4 + IPv6) from acl_map (value=1)"""
    return _get_acl_entries(filter_value=1)

def _get_acl_entries(filter_value=None):
    """Get ACL entries from merged acl_map, optionally filtered by value."""
    entries = []
    
    # IPv4
    map_id = get_map_id('acl_map')
    if map_id:
        output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
        if rc == 0 and output:
            try:
                for entry in json.loads(output):
                    key = entry.get('key')
                    val = entry.get('value')
                    if key:
                        if filter_value is not None and val is not None:
                            try:
                                actual_val = int(val[0], 16) if isinstance(val, list) and val else int(val)
                            except (ValueError, TypeError):
                                actual_val = None
                            if actual_val != filter_value:
                                continue
                        cidr = lpm_hex_to_cidr(key, is_v6=False)
                        if cidr:
                            entries.append(cidr)
            except:
                pass
    
    # IPv6
    map_id_v6 = get_map_id('acl_map_v6')
    if map_id_v6:
        output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id_v6), '-j'])
        if rc == 0 and output:
            try:
                for entry in json.loads(output):
                    key = entry.get('key')
                    val = entry.get('value')
                    if key:
                        if filter_value is not None and val is not None:
                            try:
                                actual_val = int(val[0], 16) if isinstance(val, list) and val else int(val)
                            except (ValueError, TypeError):
                                actual_val = None
                            if actual_val != filter_value:
                                continue
                        cidr = lpm_hex_to_cidr(key, is_v6=True)
                        if cidr:
                            entries.append(cidr)
            except:
                pass
    
    return entries

def add_whitelist(ip_or_cidr):
    """Add IP/CIDR to whitelist (ACL_ALLOW=0x01). Supports IPv4 and IPv6."""
    key_hex, normalized, v6 = cidr_to_lpm_hex(ip_or_cidr)
    if not key_hex:
        return "Invalid IP/CIDR"
    
    map_name = 'acl_map_v6' if v6 else 'acl_map'
    map_id = get_map_id(map_name)
    if not map_id:
        return f"Map {map_name} not found"
    
    output, err, rc = run_bpftool(['map', 'update', 'id', str(map_id), 'key', *key_hex.split(), 'value', '0x01'])
    return err if rc != 0 else None

def remove_whitelist(ip_or_cidr):
    """Remove IP/CIDR from whitelist."""
    key_hex, normalized, v6 = cidr_to_lpm_hex(ip_or_cidr)
    if not key_hex:
        return "Invalid IP/CIDR"
    
    map_name = 'acl_map_v6' if v6 else 'acl_map'
    map_id = get_map_id(map_name)
    if not map_id:
        return f"Map {map_name} not found"
    
    output, err, rc = run_bpftool(['map', 'delete', 'id', str(map_id), 'key', *key_hex.split()])
    return err if rc != 0 else None

def get_blacklist():
    """Get list of blacklisted IPs/CIDRs (IPv4 + IPv6) from acl_map (value=2)"""
    return _get_acl_entries(filter_value=2)

def add_blacklist(ip_or_cidr):
    """Add IP/CIDR to blacklist (ACL_DENY=0x02). Supports IPv4 and IPv6."""
    key_hex, normalized, v6 = cidr_to_lpm_hex(ip_or_cidr)
    if not key_hex:
        return "Invalid IP/CIDR"
    
    map_name = 'acl_map_v6' if v6 else 'acl_map'
    map_id = get_map_id(map_name)
    if not map_id:
        return f"Map {map_name} not found. Is the XDP program loaded?"
    
    output, err, rc = run_bpftool(['map', 'update', 'id', str(map_id), 'key', *key_hex.split(), 'value', '0x02'])
    return err if rc != 0 else None

def remove_blacklist(ip_or_cidr):
    """Remove IP/CIDR from blacklist."""
    key_hex, normalized, v6 = cidr_to_lpm_hex(ip_or_cidr)
    if not key_hex:
        return "Invalid IP/CIDR"
    
    map_name = 'acl_map_v6' if v6 else 'acl_map'
    map_id = get_map_id(map_name)
    if not map_id:
        return f"Map {map_name} not found"
    
    output, err, rc = run_bpftool(['map', 'delete', 'id', str(map_id), 'key', *key_hex.split()])
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


# ================= VM Redirect Management =================

def _ip_to_hex_key(ip_str):
    """Convert IP to hex byte string for bpftool (space-separated)"""
    b = socket.inet_aton(ip_str)
    return " ".join(f"{x:02x}" for x in b)

def _get_routing_info(target_ip):
    """Auto-detect route, ifindex, and ARP MAC for a destination IP"""
    try:
        route_out = subprocess.check_output(['ip', 'route', 'get', target_ip], timeout=5).decode()
        parts = route_out.split()
        dev_name = parts[parts.index('dev') + 1]
        next_hop_ip = parts[parts.index('via') + 1] if 'via' in parts else target_ip

        ifindex = socket.if_nametoindex(dev_name)

        # Source MAC
        with open(f'/sys/class/net/{dev_name}/address', 'r') as f:
            src_mac = f.read().strip()

        # Destination MAC (ping to populate ARP)
        subprocess.run(['ping', '-c', '1', '-W', '1', next_hop_ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        neigh_out = subprocess.check_output(['ip', 'neigh', 'show', next_hop_ip], timeout=5).decode()
        dst_mac = None
        for word in neigh_out.split():
            if len(word.split(':')) == 6:
                dst_mac = word
                break

        if not dst_mac:
            return None, f"Cannot resolve MAC for {next_hop_ip}"

        return {
            'dev_name': dev_name,
            'ifindex': ifindex,
            'src_mac': src_mac,
            'dst_mac': dst_mac
        }, None
    except Exception as e:
        return None, str(e)

def get_vm_redirects():
    """Get list of VM redirect entries from pinned map"""
    if not os.path.exists(PINNED_MAP):
        return [], "Pinned map not found at " + PINNED_MAP

    try:
        result = subprocess.run(
            ['bpftool', '-j', 'map', 'dump', 'pinned', PINNED_MAP],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return [], result.stderr

        if not result.stdout.strip():
            return [], None

        data = json.loads(result.stdout)
        entries = []
        for item in data:
            key_bytes = bytes([int(x, 16) for x in item['key']])
            ip_str = socket.inet_ntoa(key_bytes)

            val_bytes = bytes([int(x, 16) for x in item['value']])
            src_mac = ":".join(f"{b:02x}" for b in val_bytes[0:6])
            dst_mac = ":".join(f"{b:02x}" for b in val_bytes[6:12])
            ifindex = struct.unpack("=I", val_bytes[12:16])[0]

            entries.append({
                'ip': ip_str,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'ifindex': ifindex
            })
        return entries, None
    except Exception as e:
        return [], str(e)

def _update_tx_port_map(ifindex):
    """Add ifindex entry to tx_port_map (DEVMAP) so bpf_redirect_map works.

    tx_port_map is a BPF_MAP_TYPE_DEVMAP used by bpf_redirect_map().
    Each entry maps key=ifindex → value=ifindex.
    Without this entry, bpf_redirect_map() silently drops packets.
    """
    if not os.path.exists(PINNED_TX_PORT_MAP):
        return f"Pinned tx_port_map not found at {PINNED_TX_PORT_MAP}"

    key_hex = " ".join(f"{b:02x}" for b in struct.pack("=I", ifindex))
    val_hex = " ".join(f"{b:02x}" for b in struct.pack("=I", ifindex))

    cmd = f"bpftool map update pinned {PINNED_TX_PORT_MAP} key hex {key_hex} value hex {val_hex}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        return result.stderr
    return None

def _remove_tx_port_map_if_unused(ifindex):
    """Remove ifindex from tx_port_map only if no other VM redirect uses it."""
    if not os.path.exists(PINNED_TX_PORT_MAP):
        return

    # Check if any remaining VM redirect entry still uses this ifindex
    entries, _ = get_vm_redirects()
    for entry in entries:
        if entry.get('ifindex') == ifindex:
            return  # Still in use by another VM, don't remove

    key_hex = " ".join(f"{b:02x}" for b in struct.pack("=I", ifindex))
    cmd = f"bpftool map delete pinned {PINNED_TX_PORT_MAP} key hex {key_hex}"
    subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)

def add_vm_redirect(ip):
    """Add a VM redirect entry — auto-resolves route/MAC/ifindex.
    Also updates tx_port_map (DEVMAP) so bpf_redirect_map() works."""
    if not os.path.exists(PINNED_MAP):
        return "Pinned map not found at " + PINNED_MAP

    info, err = _get_routing_info(ip)
    if not info:
        return err or "Failed to resolve routing info"

    src_bytes = bytes.fromhex(info['src_mac'].replace(':', ''))
    dst_bytes = bytes.fromhex(info['dst_mac'].replace(':', ''))
    if_bytes = struct.pack("=I", info['ifindex'])

    val_bytes = src_bytes + dst_bytes + if_bytes
    val_hex = " ".join(f"{b:02x}" for b in val_bytes)
    key_hex = _ip_to_hex_key(ip)

    # Step 1: Update tx_port_map (DEVMAP) with ifindex
    tx_err = _update_tx_port_map(info['ifindex'])
    if tx_err:
        return f"Failed to update tx_port_map: {tx_err}"

    # Step 2: Update vm_redirect_map with VM entry
    cmd = f"bpftool map update pinned {PINNED_MAP} key hex {key_hex} value hex {val_hex}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        return result.stderr
    return None

def get_temp_blocked():
    """Get list of temporarily blocked IPs from temp_block_map.
    
    Returns list of dicts with keys: ip, blocked_at_ns, remaining_seconds.
    temp_block_map: key=__u32 (IP), value=__u64 (timestamp in nanoseconds).
    Block duration = 10 minutes.
    """
    map_id = get_map_id('temp_block_map')
    if not map_id:
        return []

    output, err, rc = run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
    if rc != 0:
        return []

    # Get current kernel time (ktime_get_coarse_ns equivalent)
    try:
        with open('/proc/timer_list', 'r') as f:
            for line in f:
                if 'now at' in line:
                    # Parse "now at XXXX nsecs"
                    parts = line.strip().split()
                    now_ns = int(parts[2])
                    break
            else:
                now_ns = 0
    except Exception:
        now_ns = 0

    block_duration_ns = 10 * 60 * 1_000_000_000  # 10 minutes in nanoseconds
    entries = []

    try:
        data = json.loads(output)
        for entry in data:
            key_hex = entry.get('key')
            val_hex = entry.get('value')
            if not key_hex or not val_hex:
                continue

            # Parse IP (u32 key, 4 bytes)
            ip = hex_to_ip(key_hex)
            if not ip:
                continue

            # Parse timestamp (u64 value, 8 bytes)
            blocked_at = hex_to_u64(val_hex)

            # Calculate remaining time
            if now_ns > 0 and blocked_at > 0:
                elapsed = now_ns - blocked_at
                remaining_ns = block_duration_ns - elapsed
                if remaining_ns <= 0:
                    continue  # Expired, skip
                remaining_seconds = int(remaining_ns / 1_000_000_000)
            else:
                remaining_seconds = -1  # Unknown

            entries.append({
                'ip': ip,
                'blocked_at_ns': blocked_at,
                'remaining_seconds': remaining_seconds
            })
    except Exception:
        pass

    return entries


def remove_temp_blocked(ip_str):
    """Remove an IP from the temp_block_map (unblock early)."""
    map_id = get_map_id('temp_block_map')
    if not map_id:
        return "Map not found. Is the XDP program loaded?"

    key_hex = ip_to_hex(ip_str)
    if not key_hex:
        return "Invalid IP address"

    output, err, rc = run_bpftool(['map', 'delete', 'id', str(map_id), 'key', *key_hex.split()])
    return err if rc != 0 else None


def remove_vm_redirect(ip):
    """Remove a VM redirect entry.
    Also cleans up tx_port_map if no other VM uses the same ifindex."""
    if not os.path.exists(PINNED_MAP):
        return "Pinned map not found at " + PINNED_MAP

    # Get the ifindex before removing, so we can clean up tx_port_map
    removed_ifindex = None
    entries, _ = get_vm_redirects()
    for entry in entries:
        if entry.get('ip') == ip:
            removed_ifindex = entry.get('ifindex')
            break

    key_hex = _ip_to_hex_key(ip)
    cmd = f"bpftool map delete pinned {PINNED_MAP} key hex {key_hex}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        return result.stderr or f"IP {ip} may not exist in map"

    # Clean up tx_port_map if this ifindex is no longer used
    if removed_ifindex is not None:
        _remove_tx_port_map_if_unused(removed_ifindex)

    return None
