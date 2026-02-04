#!/usr/bin/env python3
"""
XDP Anti-DDoS Prometheus Exporter - Enhanced Edition
Exposes comprehensive XDP statistics as Prometheus metrics.

Metrics:
  - XDP Actions (pass/drop/tx/redirect)
  - Drop reasons
  - Protocol breakdown (UDP/TCP/ICMP)
  - Packet size distribution
  - Reflection port detection
  - Top IPs by PPS
  - System stats (softirq, CPU)

Usage:
  python3 prometheus_exporter.py [--port 9101] [--interval 1]
"""

import subprocess
import json
import time
import argparse
import socket
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Lock

# Drop reason names
DROP_REASONS = {
    0: "unknown_protocol",
    1: "fragmented_packet",
    2: "udp_ratelimit",
    3: "udp_amplification",
    4: "udp_payload_size",
    5: "tcp_invalid_flags",
    6: "icmp_ratelimit",
    7: "syn_ratelimit",
    8: "blacklisted_ip",
    9: "reserved"
}

# Packet size bucket labels
PKT_SIZE_BUCKETS = ["64", "128", "256", "512", "1024", "inf"]

class MetricsCollector:
    def __init__(self):
        self.lock = Lock()
        self.stats = {
            'packets_passed': 0,
            'bytes_passed': 0,
            'packets_dropped': 0,
            'bytes_dropped': 0,
            'drop_reasons': {},
            'top_blocked': [],
            'top_passed': [],
            'top_pps': [],
            'pps_passed': 0,
            'pps_dropped': 0,
            'bps_passed': 0,
            'bps_dropped': 0,
            # Extended stats
            'xdp_actions': {'pass': 0, 'drop': 0, 'tx': 0, 'redirect': 0},
            'protocols': {'udp': 0, 'tcp': 0, 'icmp': 0, 'other': 0},
            'pkt_size_buckets': [0] * 6,
            'reflection_ports': {'dns': 0, 'ntp': 0, 'ssdp': 0, 'memcached': 0, 'chargen': 0, 'other': 0},
            # System stats
            'softirq_net_rx': 0,
            'softirq_net_tx': 0,
            'map_entries': {}
        }
        self.prev_stats = None
        self.prev_softirq = None
        self.last_update = time.time()
    
    def run_bpftool(self, args):
        """Run bpftool command"""
        try:
            cmd = ['bpftool'] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout, None
            return None, result.stderr
        except Exception as e:
            return None, str(e)
    
    def get_active_xdp_map_ids(self):
        """Get map IDs from the currently active XDP program"""
        output, _ = self.run_bpftool(['prog', 'show', '-j'])
        if not output:
            return []
        try:
            progs = json.loads(output)
            for prog in progs:
                if prog.get('type') == 'xdp' and 'xdp_anti_ddos' in prog.get('name', ''):
                    return prog.get('map_ids', [])
            for prog in progs:
                if prog.get('type') == 'xdp':
                    return prog.get('map_ids', [])
        except:
            pass
        return []
    
    def get_map_id(self, name):
        """Get BPF map ID by name from the active XDP program"""
        active_map_ids = self.get_active_xdp_map_ids()
        output, _ = self.run_bpftool(['map', 'show', '-j'])
        if not output:
            return None
        try:
            maps = json.loads(output)
            # Handle truncated names (kernel limits to ~15 chars)
            name_prefix = name[:15] if len(name) > 15 else name
            
            if active_map_ids:
                for m in maps:
                    map_name = m.get('name', '')
                    # Match full name or truncated prefix
                    if (map_name == name or map_name.startswith(name_prefix)) and m.get('id') in active_map_ids:
                        return m.get('id')
            
            # Fallback: find matching map with highest ID
            matching_maps = [m for m in maps if m.get('name', '').startswith(name_prefix)]
            if matching_maps:
                matching_maps.sort(key=lambda x: x.get('id', 0), reverse=True)
                return matching_maps[0].get('id')
        except:
            pass
        return None
    
    def hex_to_ip(self, hex_bytes):
        """Convert hex bytes to IP string"""
        try:
            if isinstance(hex_bytes, list):
                bytes_val = bytes(int(h, 16) for h in hex_bytes)
                return socket.inet_ntoa(bytes_val)
        except:
            pass
        return None
    
    def collect_stats(self):
        """Collect stats from BPF maps"""
        self.collect_basic_stats()
        self.collect_extended_stats()
        self.collect_top_ips()
        self.collect_system_stats()
        self.collect_map_entries()
    
    def collect_basic_stats(self):
        """Collect basic stats from stats_map"""
        map_id = self.get_map_id('stats_map')
        if not map_id:
            return
        
        output, _ = self.run_bpftool(['map', 'dump', 'id', str(map_id)])
        if not output:
            return
        
        try:
            entries = json.loads(output)
            total = {
                'packets_passed': 0, 'bytes_passed': 0,
                'packets_dropped': 0, 'bytes_dropped': 0,
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
            
            now = time.time()
            interval = now - self.last_update
            
            with self.lock:
                if self.prev_stats and interval > 0:
                    self.stats['pps_passed'] = max(0, (total['packets_passed'] - self.prev_stats['packets_passed']) / interval)
                    self.stats['pps_dropped'] = max(0, (total['packets_dropped'] - self.prev_stats['packets_dropped']) / interval)
                    self.stats['bps_passed'] = max(0, (total['bytes_passed'] - self.prev_stats['bytes_passed']) * 8 / interval)
                    self.stats['bps_dropped'] = max(0, (total['bytes_dropped'] - self.prev_stats['bytes_dropped']) * 8 / interval)
                
                self.stats['packets_passed'] = total['packets_passed']
                self.stats['bytes_passed'] = total['bytes_passed']
                self.stats['packets_dropped'] = total['packets_dropped']
                self.stats['bytes_dropped'] = total['bytes_dropped']
                
                self.stats['drop_reasons'] = {}
                for i, count in enumerate(total['drop_reasons']):
                    if count > 0:
                        reason = DROP_REASONS.get(i, f"reason_{i}")
                        self.stats['drop_reasons'][reason] = count
                
                self.prev_stats = total.copy()
                self.last_update = now
        except:
            pass
    
    def collect_extended_stats(self):
        """Collect extended stats from extended_stats_map"""
        map_id = self.get_map_id('extended_stats_map')
        if not map_id:
            return
        
        output, _ = self.run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
        if not output:
            return
        
        try:
            entries = json.loads(output)
            total = {
                'xdp_pass': 0, 'xdp_drop': 0, 'xdp_tx': 0, 'xdp_redirect': 0,
                'proto_udp': 0, 'proto_tcp': 0, 'proto_icmp': 0, 'proto_other': 0,
                'pkt_size_buckets': [0] * 6,
                'sport_dns': 0, 'sport_ntp': 0, 'sport_ssdp': 0,
                'sport_memcached': 0, 'sport_chargen': 0, 'sport_other_reflection': 0
            }
            
            for entry in entries:
                values = entry.get('values', [])
                for cpu_entry in values:
                    if isinstance(cpu_entry, dict) and 'value' in cpu_entry:
                        ext = cpu_entry['value']
                        
                        # Handle raw hex list (missing BTF)
                        if isinstance(ext, list):
                            try:
                                # Convert hex strings to bytes
                                import struct
                                data = bytes([int(x, 16) for x in ext])
                                # Struct layout: 4 u64 (actions), 4 u64 (protos), 6 u64 (buckets), 6 u64 (sports)
                                # Total 20 u64s = 160 bytes. Wait, struct size is 256?
                                # Let's unpack first 20 Qs (160 bytes)
                                # The struct has padding/failed lookup?
                                # struct extended_stats is 256 bytes (max_entries=1 percpu often padded to cacheline or power of 2)
                                # But we only care about the fields we defined.
                                # Definition:
                                # u64 xdp_pass, xdp_drop, xdp_tx, xdp_redirect; (4)
                                # u64 proto_udp, tcp, icmp, other; (4)
                                # u64 pkt_size_buckets[6]; (6)
                                # u64 sport_dns, ntp, ssdp, memcached, chargen, other; (6)
                                # Total fields: 4+4+6+6 = 20 fields. 20 * 8 = 160 bytes.
                                
                                if len(data) >= 160:
                                    fields = struct.unpack('<20Q', data[:160])
                                    total['xdp_pass'] += fields[0]
                                    total['xdp_drop'] += fields[1]
                                    total['xdp_tx'] += fields[2]
                                    total['xdp_redirect'] += fields[3]
                                    
                                    total['proto_udp'] += fields[4]
                                    total['proto_tcp'] += fields[5]
                                    total['proto_icmp'] += fields[6]
                                    total['proto_other'] += fields[7]
                                    
                                    for i in range(6):
                                        total['pkt_size_buckets'][i] += fields[8+i]
                                        
                                    total['sport_dns'] += fields[14]
                                    total['sport_ntp'] += fields[15]
                                    total['sport_ssdp'] += fields[16]
                                    total['sport_memcached'] += fields[17]
                                    total['sport_chargen'] += fields[18]
                                    total['sport_other_reflection'] += fields[19]
                            except Exception as e:
                                print(f"Hex parse error: {e}")

                        elif isinstance(ext, dict):
                            total['xdp_pass'] += ext.get('xdp_pass', 0)
                            total['xdp_drop'] += ext.get('xdp_drop', 0)
                            total['xdp_tx'] += ext.get('xdp_tx', 0)
                            total['xdp_redirect'] += ext.get('xdp_redirect', 0)
                            total['proto_udp'] += ext.get('proto_udp', 0)
                            total['proto_tcp'] += ext.get('proto_tcp', 0)
                            total['proto_icmp'] += ext.get('proto_icmp', 0)
                            total['proto_other'] += ext.get('proto_other', 0)
                            total['sport_dns'] += ext.get('sport_dns', 0)
                            total['sport_ntp'] += ext.get('sport_ntp', 0)
                            total['sport_ssdp'] += ext.get('sport_ssdp', 0)
                            total['sport_memcached'] += ext.get('sport_memcached', 0)
                            total['sport_chargen'] += ext.get('sport_chargen', 0)
                            total['sport_other_reflection'] += ext.get('sport_other_reflection', 0)
                            buckets = ext.get('pkt_size_buckets', [])
                            if isinstance(buckets, list):
                                for i, v in enumerate(buckets[:6]):
                                    total['pkt_size_buckets'][i] += int(v)
            
            with self.lock:
                self.stats['xdp_actions'] = {
                    'pass': total['xdp_pass'],
                    'drop': total['xdp_drop'],
                    'tx': total['xdp_tx'],
                    'redirect': total['xdp_redirect']
                }
                self.stats['protocols'] = {
                    'udp': total['proto_udp'],
                    'tcp': total['proto_tcp'],
                    'icmp': total['proto_icmp'],
                    'other': total['proto_other']
                }
                self.stats['pkt_size_buckets'] = total['pkt_size_buckets']
                self.stats['reflection_ports'] = {
                    'dns': total['sport_dns'],
                    'ntp': total['sport_ntp'],
                    'ssdp': total['sport_ssdp'],
                    'memcached': total['sport_memcached'],
                    'chargen': total['sport_chargen'],
                    'other': total['sport_other_reflection']
                }
        except Exception as e:
            print(f"Error collecting extended stats: {e}")
            import traceback
            traceback.print_exc()
            pass
    
    def collect_top_ips(self):
        """Collect top IPs from ip_stats_map"""
        map_id = self.get_map_id('ip_stats_map')
        if not map_id:
            return
        
        # Don't use -j flag - the pretty-print format includes named struct fields
        output, _ = self.run_bpftool(['map', 'dump', 'id', str(map_id)])
        if not output:
            return
        
        try:
            # Parse the pretty-printed JSON output
            entries = json.loads(output)
            ip_data = []
            for entry in entries:
                key = entry.get('key')
                value = entry.get('value')
                
                if key is not None and value:
                    # Key can be integer (IP in network byte order) or list of hex bytes
                    if isinstance(key, int):
                        # Convert integer to IP - it's stored as u32 in little-endian
                        import struct
                        ip = socket.inet_ntoa(struct.pack('<I', key))
                    elif isinstance(key, list):
                        ip = self.hex_to_ip(key)
                    else:
                        continue
                    
                    if ip and isinstance(value, dict):
                        ip_data.append({
                            'ip': ip,
                            'passed': value.get('packets_passed', 0),
                            'dropped': value.get('packets_dropped', 0),
                            'pps': value.get('pps', 0)
                        })
            
            with self.lock:
                self.stats['top_blocked'] = sorted(
                    [x for x in ip_data if x['dropped'] > 0],
                    key=lambda x: x['dropped'], reverse=True
                )[:10]
                self.stats['top_passed'] = sorted(
                    [x for x in ip_data if x['passed'] > 0],
                    key=lambda x: x['passed'], reverse=True
                )[:10]
                self.stats['top_pps'] = sorted(
                    [x for x in ip_data if x['pps'] > 0],
                    key=lambda x: x['pps'], reverse=True
                )[:10]
        except:
            pass
    
    def collect_system_stats(self):
        """Collect system softirq stats"""
        try:
            with open('/proc/softirqs', 'r') as f:
                lines = f.readlines()
            
            net_rx_total = 0
            net_tx_total = 0
            for line in lines:
                parts = line.split()
                if len(parts) > 1:
                    if parts[0] == 'NET_RX:':
                        net_rx_total = sum(int(x) for x in parts[1:])
                    elif parts[0] == 'NET_TX:':
                        net_tx_total = sum(int(x) for x in parts[1:])
            
            with self.lock:
                self.stats['softirq_net_rx'] = net_rx_total
                self.stats['softirq_net_tx'] = net_tx_total
        except:
            pass
    
    def collect_map_entries(self):
        """Collect map entry counts"""
        maps_to_check = ['rate_limit_map', 'ip_stats_map', 'whitelist_map', 'amp_ports_map']
        entries = {}
        
        for map_name in maps_to_check:
            map_id = self.get_map_id(map_name)
            if map_id:
                output, _ = self.run_bpftool(['map', 'show', 'id', str(map_id), '-j'])
                if output:
                    try:
                        info = json.loads(output)
                        # For LRU maps, count entries by dumping
                        dump_output, _ = self.run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
                        if dump_output:
                            dump_data = json.loads(dump_output)
                            entries[map_name] = len(dump_data) if isinstance(dump_data, list) else 0
                    except:
                        entries[map_name] = 0
        
        with self.lock:
            self.stats['map_entries'] = entries
    
    def get_metrics(self):
        """Get current metrics"""
        with self.lock:
            return self.stats.copy()


class MetricsHandler(BaseHTTPRequestHandler):
    collector = None
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            metrics = self.collector.get_metrics()
            output = self.format_metrics(metrics)
            self.wfile.write(output.encode('utf-8'))
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()
    
    def format_metrics(self, metrics):
        lines = []
        
        # Basic counters
        lines.append('# HELP xdp_packets_passed_total Total packets passed')
        lines.append('# TYPE xdp_packets_passed_total counter')
        lines.append(f'xdp_packets_passed_total {metrics["packets_passed"]}')
        
        lines.append('# HELP xdp_packets_dropped_total Total packets dropped')
        lines.append('# TYPE xdp_packets_dropped_total counter')
        lines.append(f'xdp_packets_dropped_total {metrics["packets_dropped"]}')
        
        lines.append('# HELP xdp_bytes_passed_total Total bytes passed')
        lines.append('# TYPE xdp_bytes_passed_total counter')
        lines.append(f'xdp_bytes_passed_total {metrics["bytes_passed"]}')
        
        lines.append('# HELP xdp_bytes_dropped_total Total bytes dropped')
        lines.append('# TYPE xdp_bytes_dropped_total counter')
        lines.append(f'xdp_bytes_dropped_total {metrics["bytes_dropped"]}')
        
        # Rate gauges
        lines.append('# HELP xdp_pps_passed Packets per second passed')
        lines.append('# TYPE xdp_pps_passed gauge')
        lines.append(f'xdp_pps_passed {metrics["pps_passed"]:.2f}')
        
        lines.append('# HELP xdp_pps_dropped Packets per second dropped')
        lines.append('# TYPE xdp_pps_dropped gauge')
        lines.append(f'xdp_pps_dropped {metrics["pps_dropped"]:.2f}')
        
        lines.append('# HELP xdp_bps_passed Bits per second passed')
        lines.append('# TYPE xdp_bps_passed gauge')
        lines.append(f'xdp_bps_passed {metrics["bps_passed"]:.2f}')
        
        lines.append('# HELP xdp_bps_dropped Bits per second dropped')
        lines.append('# TYPE xdp_bps_dropped gauge')
        lines.append(f'xdp_bps_dropped {metrics["bps_dropped"]:.2f}')
        
        # Drop rate
        total = metrics["packets_passed"] + metrics["packets_dropped"]
        drop_rate = (metrics["packets_dropped"] / total * 100) if total > 0 else 0
        lines.append('# HELP xdp_drop_rate_percent Drop rate percentage')
        lines.append('# TYPE xdp_drop_rate_percent gauge')
        lines.append(f'xdp_drop_rate_percent {drop_rate:.2f}')
        
        # XDP Actions
        lines.append('# HELP xdp_action_total XDP actions taken')
        lines.append('# TYPE xdp_action_total counter')
        for action, count in metrics.get('xdp_actions', {}).items():
            lines.append(f'xdp_action_total{{action="{action}"}} {count}')
        
        # Protocol breakdown
        lines.append('# HELP xdp_protocol_total Packets by protocol')
        lines.append('# TYPE xdp_protocol_total counter')
        for proto, count in metrics.get('protocols', {}).items():
            lines.append(f'xdp_protocol_total{{protocol="{proto}"}} {count}')
        
        # Packet size distribution (histogram style)
        lines.append('# HELP xdp_packet_size_bucket Packet size distribution')
        lines.append('# TYPE xdp_packet_size_bucket counter')
        buckets = metrics.get('pkt_size_buckets', [0] * 6)
        cumulative = 0
        for i, count in enumerate(buckets):
            cumulative += count
            le = PKT_SIZE_BUCKETS[i]
            lines.append(f'xdp_packet_size_bucket{{le="{le}"}} {cumulative}')
        
        # Reflection port detection
        lines.append('# HELP xdp_reflection_port_total Reflection attack source ports')
        lines.append('# TYPE xdp_reflection_port_total counter')
        for port, count in metrics.get('reflection_ports', {}).items():
            lines.append(f'xdp_reflection_port_total{{port="{port}"}} {count}')
        
        # Drop reasons
        lines.append('# HELP xdp_drop_reason_total Packets dropped by reason')
        lines.append('# TYPE xdp_drop_reason_total counter')
        for reason, count in metrics.get('drop_reasons', {}).items():
            lines.append(f'xdp_drop_reason_total{{reason="{reason}"}} {count}')
        
        # Top blocked IPs
        lines.append('# HELP xdp_top_blocked_ip Packets dropped per IP')
        lines.append('# TYPE xdp_top_blocked_ip gauge')
        for ip_data in metrics.get('top_blocked', []):
            ip = ip_data['ip'].replace('"', '\\"')
            lines.append(f'xdp_top_blocked_ip{{ip="{ip}"}} {ip_data["dropped"]}')
        
        # Top passed IPs
        lines.append('# HELP xdp_top_passed_ip Packets passed per IP')
        lines.append('# TYPE xdp_top_passed_ip gauge')
        for ip_data in metrics.get('top_passed', []):
            ip = ip_data['ip'].replace('"', '\\"')
            lines.append(f'xdp_top_passed_ip{{ip="{ip}"}} {ip_data["passed"]}')
        
        # Top IPs by PPS
        lines.append('# HELP xdp_top_pps_ip Current PPS per IP')
        lines.append('# TYPE xdp_top_pps_ip gauge')
        for ip_data in metrics.get('top_pps', []):
            ip = ip_data['ip'].replace('"', '\\"')
            lines.append(f'xdp_top_pps_ip{{ip="{ip}"}} {ip_data["pps"]}')
        
        # System stats
        lines.append('# HELP node_softirq_total Softirq count')
        lines.append('# TYPE node_softirq_total counter')
        lines.append(f'node_softirq_total{{type="NET_RX"}} {metrics.get("softirq_net_rx", 0)}')
        lines.append(f'node_softirq_total{{type="NET_TX"}} {metrics.get("softirq_net_tx", 0)}')
        
        # Map entries
        lines.append('# HELP xdp_map_entries BPF map entry count')
        lines.append('# TYPE xdp_map_entries gauge')
        for map_name, count in metrics.get('map_entries', {}).items():
            lines.append(f'xdp_map_entries{{map="{map_name}"}} {count}')
        
        return '\n'.join(lines) + '\n'


def collector_loop(collector, interval):
    """Background thread to collect metrics"""
    while True:
        try:
            collector.collect_stats()
        except Exception as e:
            print(f"Collection error: {e}")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description='XDP Anti-DDoS Prometheus Exporter')
    parser.add_argument('--port', '-p', type=int, default=9101,
                        help='Port to listen on (default: 9101)')
    parser.add_argument('--interval', '-i', type=float, default=1.0,
                        help='Collection interval in seconds (default: 1.0)')
    parser.add_argument('--bind', '-b', default='0.0.0.0',
                        help='Address to bind to (default: 0.0.0.0)')
    args = parser.parse_args()
    
    collector = MetricsCollector()
    MetricsHandler.collector = collector
    
    thread = Thread(target=collector_loop, args=(collector, args.interval), daemon=True)
    thread.start()
    
    server = HTTPServer((args.bind, args.port), MetricsHandler)
    print(f"XDP Anti-DDoS Prometheus Exporter (Enhanced)")
    print(f"Listening on http://{args.bind}:{args.port}/metrics")
    print(f"Collection interval: {args.interval}s")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
        server.shutdown()


if __name__ == '__main__':
    main()
