// SPDX-License-Identifier: GPL-2.0
/*
 * XDP Anti-DDoS - Bảo vệ DDoS UDP nâng cao
 * Tính năng:
 *   - IP Whitelist (cấu hình qua CLI)
 *   - Chặn khuếch đại UDP (DNS/NTP/SSDP/Memcached)
 *   - Giới hạn tốc độ UDP theo IP nguồn
 *   - Kiểm tra kích thước payload UDP
 *   - Thống kê mở rộng cho giám sát Grafana
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */
#define ONE_SECOND_NS       1000000000ULL
#define MAX_WHITELIST       10000
#define MAX_AMP_PORTS       100
#define MAX_RATE_ENTRIES    1000000
#define MAX_IP_STATS        100000

/* Config map indices */
#define CONFIG_UDP_PPS_LIMIT     0
#define CONFIG_UDP_MAX_SIZE      1
#define CONFIG_ICMP_PPS_LIMIT    2
#define CONFIG_SYN_PPS_LIMIT     3
#define CONFIG_ENABLE_IP_STATS   4  /* 0 = tắt, 1 = bật (giảm tải hệ thống) */
#define CONFIG_MAX_ENTRIES       8

/* Default values */
#define DEFAULT_UDP_PPS_LIMIT    10000
#define DEFAULT_UDP_MAX_SIZE     1024
#define DEFAULT_ICMP_PPS_LIMIT   100
#define DEFAULT_SYN_PPS_LIMIT    10000

/* Drop reason indices */
#define DROP_UNKNOWN_PROTOCOL    0
#define DROP_FRAGMENTED          1
#define DROP_UDP_RATELIMIT       2
#define DROP_UDP_AMPLIFICATION   3
#define DROP_UDP_PAYLOAD_SIZE    4
#define DROP_TCP_INVALID         5
#define DROP_ICMP_RATELIMIT      6
#define DROP_SYN_RATELIMIT       7
#define DROP_BLACKLIST           8
#define DROP_PARSE_ERROR         9   /* Lỗi phân tích gói tin sớm */
#define DROP_MAX_REASONS         10

/* VLAN */
#define ETH_P_8021Q         0x8100
#define ETH_P_8021AD        0x88A8
#define VLAN_HDR_SZ         4

/* TCP Flags */
#define RAW_TCP_FIN         0x01
#define RAW_TCP_SYN         0x02
#define RAW_TCP_RST         0x04
#define RAW_TCP_PSH         0x08
#define RAW_TCP_ACK         0x10
#define RAW_TCP_URG         0x20

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

struct rate_limit_t {
    __u64 last_time;
    __u64 count;
} __attribute__((aligned(16)));

struct xdp_stats {
    __u64 packets_passed;
    __u64 bytes_passed;
    __u64 packets_dropped;
    __u64 bytes_dropped;
    __u64 drop_reasons[DROP_MAX_REASONS];
} __attribute__((aligned(64)));

struct ip_stats {
    __u64 packets_passed;
    __u64 bytes_passed;
    __u64 packets_dropped;
    __u64 bytes_dropped;
    __u64 last_seen;
    __u64 pps;           /* PPS hiện tại cho IP này */
    __u64 last_pps_time; /* Thời gian tính PPS lần cuối */
    __u64 pps_count;     /* Số đếm gói tin để tính PPS */
} __attribute__((aligned(64)));

/* Extended statistics for monitoring */
#define PKT_SIZE_BUCKETS 6
struct extended_stats {
    /* XDP Actions */
    __u64 xdp_pass;
    __u64 xdp_drop;
    __u64 xdp_tx;
    __u64 xdp_redirect;
    
    /* Protocol breakdown */
    __u64 proto_udp;
    __u64 proto_tcp;
    __u64 proto_icmp;
    __u64 proto_other;
    
    /* Packet size buckets: 0-64, 65-128, 129-256, 257-512, 513-1024, 1025+ */
    __u64 pkt_size_buckets[PKT_SIZE_BUCKETS];
    
    /* Source port stats for reflection detection */
    __u64 sport_dns;       /* port 53 */
    __u64 sport_ntp;       /* port 123 */
    __u64 sport_ssdp;      /* port 1900 */
    __u64 sport_memcached; /* port 11211 */
    __u64 sport_chargen;   /* port 19 */
    __u64 sport_other_reflection;
} __attribute__((aligned(64)));  /* Reduced from 128 - cache line is sufficient */

/* ============================================================================
 * BPF MAPS
 * ============================================================================ */

/* Whitelist IPs - key: IP address, value: 1 = allowed */
/* Danh sách trắng IP - key: địa chỉ IP, value: 1 = cho phép */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST);
    __type(key, __u32);
    __type(value, __u8);
} whitelist_map SEC(".maps");

/* Amplification ports to block - key: port, value: 1 = block */
/* Các cổng khuếch đại cần chặn - key: port, value: 1 = chặn */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_AMP_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} amp_ports_map SEC(".maps");

/* Configuration values - array for runtime config */
/* Giá trị cấu hình - mảng cho cấu hình runtime */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CONFIG_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

/* Rate limiting per source IP */
/* Giới hạn tốc độ (Rate limiting) theo mỗi IP nguồn */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_t);
} rate_limit_map SEC(".maps");

/* SYN flood rate limiting (isolated) */
/* Giới hạn tốc độ SYN flood (cách ly) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_t);
} rate_limit_syn_map SEC(".maps");

/* ICMP rate limiting (isolated from UDP) */
/* Giới hạn tốc độ ICMP (cách ly khỏi UDP) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_t);
} rate_limit_icmp_map SEC(".maps");

/* Per-CPU statistics */
/* Thống kê theo từng CPU (Per-CPU statistics) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} stats_map SEC(".maps");

/* Per-IP statistics for top IP tracking */
/* Thống kê theo từng IP đẻ theo dõi top IP */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_IP_STATS);
    __type(key, __u32);
    __type(value, struct ip_stats);
} ip_stats_map SEC(".maps");

/* Extended statistics for monitoring */
/* Thống kê mở rộng để giám sát */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct extended_stats);
} extended_stats_map SEC(".maps");

/* ============================================================================
 * HELPERS
 * ============================================================================ */

static __always_inline __u64 get_config(__u32 key, __u64 default_val)
{
    __u64 *val = bpf_map_lookup_elem(&config_map, &key);
    if (val && *val > 0)
        return *val;
    return default_val;
}

static __always_inline int is_whitelisted(__u32 ip)
{
    __u8 *val = bpf_map_lookup_elem(&whitelist_map, &ip);
    return val != NULL;
}

static __always_inline int is_amp_port(__u16 port)
{
    __u8 *val = bpf_map_lookup_elem(&amp_ports_map, &port);
    return val != NULL;
}

static __always_inline __u16 
parse_eth(struct ethhdr *eth, void *data_end, int *offset)
{
    __u16 h_proto = eth->h_proto;
    *offset = sizeof(*eth);
    
    /* Xử lý VLAN tags (lên đến 2 mức - QinQ) */
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        } *vhdr;
        vhdr = (void *)eth + *offset;
        if ((void *)(vhdr + 1) > data_end) return 0;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        *offset += VLAN_HDR_SZ;
        
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            vhdr = (void *)eth + *offset;
            if ((void *)(vhdr + 1) > data_end) return 0;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            *offset += VLAN_HDR_SZ;
        }
    }
    return h_proto;
}

/* Lấy timestamp làm tham số để tránh gọi ktime nhiều lần mỗi gói tin */
static __always_inline int 
check_rate_limit(void *map, __u32 src_ip, __u64 limit, __u64 now)
{
    struct rate_limit_t *entry = bpf_map_lookup_elem(map, &src_ip);

    if (likely(entry)) {
        /* Reset cửa sổ nếu đã hơn 1 giây trôi qua.
         * Logic: Nếu thời gian hiện tại vượt quá thời gian lần cuối + 1 giây,
         * reset bộ đếm về 1 và cập nhật thời gian mới.
         */
        if (now - entry->last_time > ONE_SECOND_NS) {
            entry->last_time = now;
            entry->count = 1;
            return 0;
        }
        entry->count++;
        if (entry->count > limit) 
            return 1;
        return 0;
    }

    /* IP mới: thêm vào map */
    struct rate_limit_t new_entry = { .last_time = now, .count = 1 };
    bpf_map_update_elem(map, &src_ip, &new_entry, BPF_ANY);
    return 0;
}

static __always_inline void 
track_stats(__u64 len, int action, int reason_idx)
{
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) return;
    
    if (action == XDP_PASS) {
        stats->packets_passed++;
        stats->bytes_passed += len;
    } else {
        stats->packets_dropped++;
        stats->bytes_dropped += len;
        if (reason_idx >= 0 && reason_idx < DROP_MAX_REASONS)
            stats->drop_reasons[reason_idx]++;
    }
}

/* Lấy timestamp làm tham số, thêm kiểm tra bật/tắt vì hiệu năng */
static __always_inline void
track_ip_stats(__u32 src_ip, __u64 len, int action, __u64 now)
{
    /* Kiểm tra xem việc theo dõi thống kê IP có được bật không (mặc định: bật để tương thích) */
    __u64 enabled = get_config(CONFIG_ENABLE_IP_STATS, 1);
    if (!enabled)
        return;
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    
    if (stats) {
        if (action == XDP_PASS) {
            stats->packets_passed++;
            stats->bytes_passed += len;
        } else {
            stats->packets_dropped++;
            stats->bytes_dropped += len;
        }
        stats->last_seen = now;
        
        /* Tính toán PPS: Cập nhật số gói tin mỗi giây để giám sát traffic */
        stats->pps_count++;
        if (now - stats->last_pps_time > ONE_SECOND_NS) {
            stats->pps = stats->pps_count;
            stats->pps_count = 0;
            stats->last_pps_time = now;
        }
    } else {
        struct ip_stats new_stats = { 
            .last_seen = now,
            .last_pps_time = now,
            .pps_count = 1,
            .pps = 0
        };
        if (action == XDP_PASS) {
            new_stats.packets_passed = 1;
            new_stats.bytes_passed = len;
        } else {
            new_stats.packets_dropped = 1;
            new_stats.bytes_dropped = len;
        }
        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_stats, BPF_ANY);
    }
}

/* Theo dõi thống kê mở rộng */
static __always_inline void
track_extended_stats(__u64 pkt_size, __u8 protocol, __u16 sport, int action)
{
    __u32 key = 0;
    struct extended_stats *ext = bpf_map_lookup_elem(&extended_stats_map, (void *)&key);
    if (!ext) return;
    
    /* Các hành động XDP */
    if (action == XDP_PASS)
        ext->xdp_pass++;
    else if (action == XDP_DROP)
        ext->xdp_drop++;
    else if (action == XDP_TX)
        ext->xdp_tx++;
    else if (action == XDP_REDIRECT)
        ext->xdp_redirect++;
    
    /* Phân loại giao thức */
    if (protocol == IPPROTO_UDP)
        ext->proto_udp++;
    else if (protocol == IPPROTO_TCP)
        ext->proto_tcp++;
    else if (protocol == IPPROTO_ICMP)
        ext->proto_icmp++;
    else
        ext->proto_other++;
    
    /* Các bucket kích thước gói tin */
    if (pkt_size <= 64)
        ext->pkt_size_buckets[0]++;
    else if (pkt_size <= 128)
        ext->pkt_size_buckets[1]++;
    else if (pkt_size <= 256)
        ext->pkt_size_buckets[2]++;
    else if (pkt_size <= 512)
        ext->pkt_size_buckets[3]++;
    else if (pkt_size <= 1024)
        ext->pkt_size_buckets[4]++;
    else
        ext->pkt_size_buckets[5]++;
    
    /* Thống kê cổng nguồn để phát hiện tấn công phản xạ (reflection) */
    if (protocol == IPPROTO_UDP) {
        switch (sport) {
            case 53:    ext->sport_dns++; break;
            case 123:   ext->sport_ntp++; break;
            case 1900:  ext->sport_ssdp++; break;
            case 11211: ext->sport_memcached++; break;
            case 19:    ext->sport_chargen++; break;
            default:
                if (sport < 1024) ext->sport_other_reflection++;
                break;
        }
    }
}

/* ============================================================================
 * MAIN PROGRAM
 * ============================================================================ */

SEC("xdp")
int xdp_anti_ddos(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 pkt_size = data_end - data;
    
    /* Lấy timestamp một lần lúc bắt đầu, truyền vào các helper */
    __u64 now = bpf_ktime_get_coarse_ns();
    
    /* 1. Phân tích header Ethernet */
    struct ethhdr *eth = data;
    int eth_off = 0;
    if ((void *)(eth + 1) > data_end) {
        /* Theo dõi các gói tin bị drop sớm */
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR);
        return XDP_DROP;
    }

    __u16 h_proto = parse_eth(eth, data_end, &eth_off);
    
    /* Cho qua các gói tin không phải IP (ARP, IPv6, v.v.) */
    if (h_proto != bpf_htons(ETH_P_IP)) {
        track_stats(pkt_size, XDP_PASS, -1);
        return XDP_PASS;
    }

    /* 2. Phân tích header IP */
    struct iphdr *iph = data + eth_off;
    if ((void *)(iph + 1) > data_end) {
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR);
        return XDP_DROP;
    }

    __u32 src_ip = iph->saddr;
    __u8 protocol = iph->protocol;
    int ip_hdr_len = iph->ihl * 4;
    
    if (ip_hdr_len < 20) {
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR);
        return XDP_DROP;
    }
    
    /* Xác thực giới hạn truy cập header L4 */
    if ((void *)iph + ip_hdr_len > data_end) {
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR);
        return XDP_DROP;
    }

    /* 3. KIỂM TRA WHITELIST - Cho qua ngay lập tức nếu nằm trong danh sách trắng */
    if (unlikely(is_whitelisted(src_ip))) {
        track_stats(pkt_size, XDP_PASS, -1);
        track_ip_stats(src_ip, pkt_size, XDP_PASS, now);
        return XDP_PASS;
    }

    /* 4. Chặn các gói tin bị phân mảnh (vector tấn công DDoS phổ biến) */
    if (unlikely((iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0)) {
        track_stats(pkt_size, XDP_DROP, DROP_FRAGMENTED);
        track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
        return XDP_DROP;
    }

    void *l4_hdr = (void *)iph + ip_hdr_len;

    /* 5. Xử lý UDP */
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) {
            track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR);
            return XDP_DROP;
        }

        __u16 sport = bpf_ntohs(udph->source);
        
        /* Tính toán kích thước payload thực tế từ ranh giới gói tin, không phải header UDP */
        __u64 l4_len = data_end - l4_hdr;
        __u16 payload_len = (l4_len > sizeof(struct udphdr)) ? 
                            (l4_len - sizeof(struct udphdr)) : 0;

        /* Sắp xếp lại thứ tự kiểm tra - Rate limiting trước (lý do drop phổ biến nhất) */
        /* 5a. UDP Rate Limiting - Kiểm tra trước để fail fast */
        __u64 pps_limit = get_config(CONFIG_UDP_PPS_LIMIT, DEFAULT_UDP_PPS_LIMIT);
        if (check_rate_limit(&rate_limit_map, src_ip, pps_limit, now)) {
            track_stats(pkt_size, XDP_DROP, DROP_UDP_RATELIMIT);
            track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
            track_extended_stats(pkt_size, protocol, sport, XDP_DROP);
            return XDP_DROP;
        }

        /* 5b. Kiểm tra kích thước Payload UDP */
        __u64 max_size = get_config(CONFIG_UDP_MAX_SIZE, DEFAULT_UDP_MAX_SIZE);
        if (payload_len > max_size) {
            track_stats(pkt_size, XDP_DROP, DROP_UDP_PAYLOAD_SIZE);
            track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
            track_extended_stats(pkt_size, protocol, sport, XDP_DROP);
            return XDP_DROP;
        }

        /* 5c. Bảo vệ chống khuếch đại UDP (Amplification Protection) - Kiểm tra cổng nguồn
         * LƯU Ý: Điều này phát hiện các cuộc tấn công phản xạ nơi các bộ khuếch đại phản hồi
         * với các cổng nguồn như 53 (DNS), 123 (NTP), v.v.
         */
        if (is_amp_port(sport)) {
            track_stats(pkt_size, XDP_DROP, DROP_UDP_AMPLIFICATION);
            track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
            track_extended_stats(pkt_size, protocol, sport, XDP_DROP);
            return XDP_DROP;
        }

        track_stats(pkt_size, XDP_PASS, -1);
        track_ip_stats(src_ip, pkt_size, XDP_PASS, now);
        track_extended_stats(pkt_size, protocol, sport, XDP_PASS);
        return XDP_PASS;
    }

    /* 6. Xử lý TCP */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) {
            track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR);
            return XDP_DROP;
        }

        /* Trích xuất cổng nguồn TCP để theo dõi */
        __u16 tcp_sport = bpf_ntohs(tcph->source);
        __u8 flags = ((__u8 *)tcph)[13];
        
        /* Phát hiện TCP flags không hợp lệ */
        /* NULL flags */
        if (flags == 0) {
            track_stats(pkt_size, XDP_DROP, DROP_TCP_INVALID);
            track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
            track_extended_stats(pkt_size, protocol, tcp_sport, XDP_DROP);
            return XDP_DROP;
        }
        
        /* SYN+FIN hoặc SYN+RST - các tổ hợp không hợp lệ */
        if ((flags & (RAW_TCP_SYN | RAW_TCP_FIN)) == (RAW_TCP_SYN | RAW_TCP_FIN) ||
            (flags & (RAW_TCP_SYN | RAW_TCP_RST)) == (RAW_TCP_SYN | RAW_TCP_RST)) {
            track_stats(pkt_size, XDP_DROP, DROP_TCP_INVALID);
            track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
            track_extended_stats(pkt_size, protocol, tcp_sport, XDP_DROP);
            return XDP_DROP;
        }

        /* Giới hạn tốc độ SYN Flood */
        if ((flags & RAW_TCP_SYN) && !(flags & RAW_TCP_ACK)) {
            __u64 syn_limit = get_config(CONFIG_SYN_PPS_LIMIT, DEFAULT_SYN_PPS_LIMIT);
            if (check_rate_limit(&rate_limit_syn_map, src_ip, syn_limit, now)) {
                track_stats(pkt_size, XDP_DROP, DROP_SYN_RATELIMIT);
                track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
                track_extended_stats(pkt_size, protocol, tcp_sport, XDP_DROP);
                return XDP_DROP;
            }
        }

        track_stats(pkt_size, XDP_PASS, -1);
        track_ip_stats(src_ip, pkt_size, XDP_PASS, now);
        track_extended_stats(pkt_size, protocol, tcp_sport, XDP_PASS);
        return XDP_PASS;
    }

    /* 7. Xử lý ICMP */
    if (protocol == IPPROTO_ICMP) {
        __u64 icmp_limit = get_config(CONFIG_ICMP_PPS_LIMIT, DEFAULT_ICMP_PPS_LIMIT);
        /* Sử dụng map ICMP riêng biệt thay vì dùng chung rate_limit_map */
        if (check_rate_limit(&rate_limit_icmp_map, src_ip, icmp_limit, now)) {
            track_stats(pkt_size, XDP_DROP, DROP_ICMP_RATELIMIT);
            track_ip_stats(src_ip, pkt_size, XDP_DROP, now);
            track_extended_stats(pkt_size, protocol, 0, XDP_DROP);
            return XDP_DROP;
        }
        
        track_stats(pkt_size, XDP_PASS, -1);
        track_ip_stats(src_ip, pkt_size, XDP_PASS, now);
        track_extended_stats(pkt_size, protocol, 0, XDP_PASS);
        return XDP_PASS;
    }

    /* Mặc định: Cho qua các giao thức khác (GRE, ESP, v.v.) */
    track_stats(pkt_size, XDP_PASS, -1);
    track_ip_stats(src_ip, pkt_size, XDP_PASS, now);
    track_extended_stats(pkt_size, protocol, 0, XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";