# XDP Anti-DDoS

High-performance DDoS mitigation using Linux XDP (eXpress Data Path) technology.

## 🔥 Features

- **IP Whitelist**: Allow trusted IPs to pass without filtering
- **UDP Amplification Blocking**: Block DNS/NTP/SSDP/Memcached reflection attacks (ports 53/123/1900/11211)
- **UDP Rate Limiting**: Configurable PPS limit per source IP (default: 10000 pps)
- **UDP Payload Size Filtering**: Drop large UDP packets (default: >1024 bytes)
- **CLI Management**: Update whitelist, ports, thresholds at runtime
- **Web Interface**: Browser-based dashboard for stats and configuration
- **Grafana Monitoring**: Prometheus exporter with pre-built dashboard

## 📦 Quick Start

### Build

```bash
cd /root/xdp-anti-ddos
make
```

### Attach to Interface

```bash
# Attach to enp94s0f0 (default)
make IFACE=enp94s0f0 attach

# Or attach manually
ip link set dev enp94s0f0 xdpdrv obj xdp_anti_ddos.o sec xdp
```

### Initialize Default Configuration

```bash
python3 xdp_cli.py init
```

### Detach

```bash
make IFACE=enp94s0f0 detach
# or
ip link set dev enp94s0f0 xdp off
```

## 🛠️ CLI Usage

### Whitelist Management

```bash
# Add IP to whitelist (will pass all checks)
python3 xdp_cli.py whitelist add 8.8.8.8
python3 xdp_cli.py whitelist add 1.1.1.1

# Remove from whitelist
python3 xdp_cli.py whitelist remove 8.8.8.8

# List all whitelisted IPs
python3 xdp_cli.py whitelist list
```

### Port Management (Amplification Blocking)

```bash
# Initialize default ports (53/123/1900/11211)
python3 xdp_cli.py port init

# Add custom port
python3 xdp_cli.py port add 19      # Chargen
python3 xdp_cli.py port add 161     # SNMP

# Remove port
python3 xdp_cli.py port remove 53

# List blocked ports
python3 xdp_cli.py port list
```

### Configuration

```bash
# Show current config
python3 xdp_cli.py config show

# Set UDP PPS limit (packets per second per IP)
python3 xdp_cli.py config set pps-limit 20000

# Set max UDP payload size (bytes)
python3 xdp_cli.py config set max-size 512

# Set ICMP PPS limit
python3 xdp_cli.py config set icmp-limit 50

# Set SYN PPS limit
python3 xdp_cli.py config set syn-limit 5000

# Initialize all defaults
python3 xdp_cli.py config init
```

### Statistics

```bash
# Show overall statistics
python3 xdp_cli.py stats show

# Show top blocked/passed IPs
python3 xdp_cli.py stats top
python3 xdp_cli.py stats top -n 20  # Top 20
```

## 🌐 Web Interface

A Flask-based web dashboard is available for easier management.

### Features
- Real-time dashboard with drop reasons
- Whitelist management
- Blocked ports management
- System configuration adjustment

### Usage

```bash
# Start the web server (default port 5001)
nohup python3 web/app.py > web/app.log 2>&1 &
```

Access at `http://<your-server-ip>:5001/`

For full documentation, see [web/README.md](web/README.md).

## 📊 Grafana Monitoring

### Start Prometheus Exporter

```bash
# Start on port 9100 (default)
nohup python3 prometheus_exporter.py > prometheus_exporter.log 2>&1 &

# Custom port and interval
nohup python3 prometheus_exporter.py --port 9101 --interval 1 > prometheus_exporter.log 2>&1 &
```

### Prometheus Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'xdp-antiddos'
    static_configs:
      - targets: ['localhost:9101']
    scrape_interval: 1s
```

### Import Dashboard

1. Go to Grafana → Dashboards → Import
2. Upload `grafana_dashboard.json`
3. Select Prometheus data source
4. Click Import

### Dashboard Panels

- **Traffic Overview**: Packets/bytes passed/dropped
- **PPS Graph**: Real-time packets per second
- **Bandwidth Graph**: Real-time bandwidth (bps)
- **Drop Rate**: Current drop percentage
- **Drop Reasons**: Pie chart breakdown
- **Top 10 Blocked IPs**: Table with packet counts
- **Top 10 Passed IPs**: Table with packet counts

## ⚙️ Configuration Defaults

| Setting | Default | Description |
|---------|---------|-------------|
| UDP PPS Limit | 10000 | Max UDP packets/second per IP |
| UDP Max Size | 1024 | Max UDP payload bytes |
| ICMP PPS Limit | 100 | Max ICMP packets/second per IP |
| SYN PPS Limit | 10000 | Max SYN packets/second per IP |

### Blocked Amplification Ports (after init)

| Port | Service |
|------|---------|
| 53 | DNS |
| 123 | NTP |
| 1900 | SSDP |
| 11211 | Memcached |

## 🔍 Drop Reasons

| Code | Reason | Description |
|------|--------|-------------|
| 0 | Unknown Protocol | Non-TCP/UDP/ICMP (passed by default) |
| 1 | Fragmented Packet | IP fragment attack |
| 2 | UDP Rate Limit | Exceeded PPS limit |
| 3 | UDP Amplification | Source port in blocked list |
| 4 | UDP Payload Size | Payload exceeds max size |
| 5 | Invalid TCP Flags | NULL/SYN+FIN/SYN+RST |
| 6 | ICMP Rate Limit | ICMP flood protection |
| 7 | SYN Rate Limit | SYN flood protection |
| 8 | Blacklisted IP | IP on blacklist |
| 9 | Parse Error | Packet header parsing failed |

## 🚀 Production Deployment

### Systemd Service

Create `/etc/systemd/system/xdp-antiddos.service`:

```ini
[Unit]
Description=XDP Anti-DDoS Filter
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/root/xdp-anti-ddos
ExecStart=/sbin/ip link set dev enp94s0f0 xdpdrv obj /root/xdp-anti-ddos/xdp_anti_ddos.o sec xdp_anti_ddos_filter
ExecStartPost=/usr/bin/python3 /root/xdp-anti-ddos/xdp_cli.py init
ExecStop=/sbin/ip link set dev enp94s0f0 xdp off

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable xdp-antiddos
systemctl start xdp-antiddos
```

### Prometheus Exporter Service

Create `/etc/systemd/system/xdp-exporter.service`:

```ini
[Unit]
Description=XDP Anti-DDoS Prometheus Exporter
After=xdp-antiddos.service

[Service]
Type=simple
WorkingDirectory=/root/xdp-anti-ddos
ExecStart=/usr/bin/python3 /root/xdp-anti-ddos/prometheus_exporter.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Web Interface Service

Create `/etc/systemd/system/xdp-web.service`:

```ini
[Unit]
Description=XDP Anti-DDoS Web Interface
After=xdp-antiddos.service

[Service]
Type=simple
WorkingDirectory=/root/xdp-anti-ddos
ExecStart=/usr/bin/python3 /root/xdp-anti-ddos/web/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 📋 Requirements

- Linux kernel 5.x+ with XDP support
- clang, llvm, libbpf-dev
- bpftool
- Python 3.6+

```bash
# Ubuntu/Debian
apt-get install clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) bpftool python3
```

## ⚡ Performance Tuning

### Disable Per-IP Stats (High-PPS Environments)

For environments handling >1M pps, disable per-IP stats tracking to reduce overhead:

```bash
# Disable IP stats (reduces ~2-5μs per packet)
python3 xdp_cli.py config set ip-stats 0
```

### Recommended Settings for High-Traffic

| Setting | Low Traffic | High Traffic (>1M pps) |
|---------|-------------|------------------------|
| UDP PPS Limit | 10000 | 50000 |
| IP Stats | Enabled | Disabled |
| Max Rate Entries | 1M | 1M (default) |

## 🔧 Recent Optimizations (v1.1)

- **Timestamp Optimization**: Single `bpf_ktime_get_coarse_ns()` call per packet
- **Check Reordering**: Rate limiting checked first for faster fail path
- **Payload Validation**: Uses actual packet boundaries instead of spoofable UDP header
- **Conditional IP Stats**: Can be disabled for high-PPS environments
- **Security Hardening**: Web interface uses secure random secret keys

## 📜 License

GPL-2.0
