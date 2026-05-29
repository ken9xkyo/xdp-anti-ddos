#ifndef __XDP_HELPERS_H
#define __XDP_HELPERS_H

#include "xdp_common.h"
#include "xdp_structs.h"
#include "xdp_maps.h"

/* ============================================================================
 * HÀM HELPER - Các hàm phụ trợ được inline (chèn trực tiếp vào nơi gọi)
 *
 * __always_inline: Bắt buộc compiler chèn code vào thay vì tạo function call.
 * BPF verifier không hỗ trợ function call thông thường trong nhiều trường hợp,
 * nên inline là cách tiếp cận an toàn và nhanh nhất.
 * ============================================================================ */

/*
 * track_stats - GHI NHẬN THỐNG KÊ cho mỗi gói tin đã xử lý.
 *
 * Được gọi trước mỗi return trong hàm main để ghi lại:
 *   - Hành động (PASS/DROP/REDIRECT)
 *   - Lý do DROP (nếu có)
 *   - Giao thức (UDP/TCP/ICMP/other)
 *   - Kích thước gói tin
 *   - Cổng nguồn (để phát hiện amplification)
 *
 * Chỉ cần 1 lần lookup duy nhất vào global_stats_map (tối ưu hiệu năng).
 */
static __always_inline void
track_stats(__u64 pkt_size, int action, int reason_idx, __u8 protocol, __u16 sport)
{
    __u32 key = 0;

    /* Lookup 1 lần duy nhất - lấy con trỏ trực tiếp vào entry trong map */
    struct xdp_global_stats *stats = bpf_map_lookup_elem(&global_stats_map, &key);
    if (!stats) return; /* BPF verifier yêu cầu kiểm tra NULL */

    /* --- Cập nhật số lượng gói và bandwidth --- */
    if (action == XDP_PASS) {
        stats->packets_passed++;
        stats->bytes_passed += pkt_size;
    }
    else if (action == XDP_DROP) {
        stats->packets_dropped++;
        stats->bytes_dropped += pkt_size;

        /* Ghi nhận lý do chặn (reason_idx = -1 nghĩa là không có lý do cụ thể) */
        if (reason_idx >= 0 && reason_idx < DROP_MAX_REASONS) {
            stats->drop_reasons[reason_idx]++;
        }
    }
    else if (action == XDP_REDIRECT) {
        stats->packets_redirected++;
        stats->bytes_redirected += pkt_size;
    }

    /* --- Phân loại theo giao thức --- */
    if (protocol == IPPROTO_UDP) stats->proto_udp++;
    else if (protocol == IPPROTO_TCP) stats->proto_tcp++;
    else if (protocol == IPPROTO_ICMP) stats->proto_icmp++;
    else stats->proto_other++;

    /* --- Phân loại theo kích thước gói tin (6 bucket) ---
     * Giúp nhận diện pattern tấn công, VD:
     *   - Flood gói nhỏ (< 64B): thường là SYN flood hoặc UDP flood
     *   - Flood gói lớn (> 1024B): thường là amplification attack
     */
    if (pkt_size <= 64) stats->pkt_size_buckets[0]++;
    else if (pkt_size <= 128) stats->pkt_size_buckets[1]++;
    else if (pkt_size <= 256) stats->pkt_size_buckets[2]++;
    else if (pkt_size <= 512) stats->pkt_size_buckets[3]++;
    else if (pkt_size <= 1024) stats->pkt_size_buckets[4]++;
    else stats->pkt_size_buckets[5]++;

    /* --- Thống kê cổng nguồn UDP (phát hiện amplification) ---
     * Chỉ theo dõi khi giao thức là UDP vì amplification chỉ dùng UDP.
     * Các cổng well-known thường bị lợi dụng:
     *   53 (DNS), 123 (NTP), 1900 (SSDP), 11211 (Memcached), 19 (Chargen)
     */
    if (protocol == IPPROTO_UDP) {
        switch (sport) {
            case 53:    stats->sport_dns++; break;
            case 123:   stats->sport_ntp++; break;
            case 1900:  stats->sport_ssdp++; break;
            case 11211: stats->sport_memcached++; break;
            case 19:    stats->sport_chargen++; break;
            default:
                /* Cổng < 1024 khác cũng có thể bị lợi dụng */
                if (sport < 1024) stats->sport_other_reflection++;
                break;
        }
    }
}

/*
 * get_config - Đọc giá trị cấu hình từ config_map.
 *
 * Nếu chưa được cấu hình (hoặc = 0), trả về giá trị mặc định.
 * Cho phép userspace thay đổi tham số runtime mà không cần restart.
 */
static __always_inline __u64 get_config(__u32 key, __u64 default_val)
{
    __u64 *val = bpf_map_lookup_elem(&config_map, &key);
    if (val && *val > 0)
        return *val;
    return default_val;
}

/*
 * check_acl - Kiểm tra IP trong ACL map (merged whitelist + blacklist).
 *
 * TỐI ƯU QUAN TRỌNG: Chỉ 1 LPM lookup thay vì 2 (tiết kiệm ~80 cy/pkt).
 * Kernel thực hiện longest-prefix match: rule cụ thể nhất luôn thắng.
 *
 * Trả về:
 *   ACL_ALLOW (1): IP trong whitelist → cho qua
 *   ACL_DENY  (2): IP trong blacklist → chặn
 *   0:             IP không có trong ACL → tiếp tục kiểm tra
 */
static __always_inline __u8 check_acl(__u32 ip)
{
    struct lpm_key_ipv4 key = {
        .prefixlen = 32,  /* Lookup exact match → kernel fallback prefix ngắn hơn */
        .addr = ip        /* Network byte order (từ iph->saddr) */
    };
    __u8 *val = bpf_map_lookup_elem(&acl_map, &key);
    return val ? *val : 0;
}

/*
 * check_acl_v6 - Kiểm tra IPv6 trong ACL map (merged whitelist + blacklist).
 * Tương tự check_acl nhưng cho 128-bit IPv6 address.
 */
static __always_inline __u8 check_acl_v6(const struct in6_addr *ip6)
{
    struct lpm_key_ipv6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, ip6, 16);
    __u8 *val = bpf_map_lookup_elem(&acl_map_v6, &key);
    return val ? *val : 0;
}

/*
 * is_amp_port - Kiểm tra cổng có phải cổng amplification cần chặn không.
 *
 * Trả về: 1 nếu cổng bị chặn, 0 nếu không.
 * Danh sách cổng do userspace cấu hình qua amp_ports_map.
 */
static __always_inline int is_amp_port(__u16 port)
{
    __u8 *val = bpf_map_lookup_elem(&amp_ports_map, &port);
    return val != NULL;
}

/*
 * parse_eth - Phân tích Ethernet header, xử lý cả VLAN tag.
 *
 * Ethernet frame thông thường:
 *   [Dst MAC 6B][Src MAC 6B][EtherType 2B][Payload...]
 *
 * Với VLAN (802.1Q):
 *   [Dst MAC 6B][Src MAC 6B][0x8100 2B][VLAN Tag 2B][EtherType 2B][Payload...]
 *
 * QinQ (VLAN lồng nhau): có thể có 2 lớp VLAN tag.
 *
 * Tham số:
 *   - eth: Con trỏ đến Ethernet header
 *   - data_end: Biên cuối gói tin (BPF verifier yêu cầu kiểm tra)
 *   - offset: [output] Vị trí bắt đầu của header tiếp theo (IP header)
 *
 * Trả về: EtherType thật sự (VD: ETH_P_IP cho IPv4), hoặc 0 nếu lỗi.
 */
static __always_inline __u16
parse_eth(struct ethhdr *eth, void *data_end, int *offset)
{
    __u16 h_proto = eth->h_proto;
    *offset = sizeof(*eth);

    /* Kiểm tra và bóc VLAN tag lớp 1 (nếu có) - Tối ưu bằng unlikely() */
    if (unlikely(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;                  /* VLAN ID + Priority */
            __be16 h_vlan_encapsulated_proto;   /* EtherType thật */
        } *vhdr;
        vhdr = (void *)eth + *offset;
        if (unlikely((void *)(vhdr + 1) > data_end)) return 0;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        *offset += VLAN_HDR_SZ;

        /* Kiểm tra VLAN tag lớp 2 - QinQ (nếu có) */
        if (unlikely(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))) {
            vhdr = (void *)eth + *offset;
            if (unlikely((void *)(vhdr + 1) > data_end)) return 0;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            *offset += VLAN_HDR_SZ;
        }
    }
    return h_proto;
}

/*
 * check_rate_limit - Kiểm tra rate limit (giới hạn tốc độ) cho một IP.
 *
 * Thuật toán cửa sổ trượt đơn giản (fixed window):
 *   1. Nếu đã hơn 1 giây kể từ cửa sổ trước → reset bộ đếm
 *   2. Tăng bộ đếm lên 1
 *   3. Nếu bộ đếm > limit → trả về 1 (bị chặn)
 *
 * Tham số:
 *   - map: BPF map chứa trạng thái rate limit (riêng cho UDP/SYN/ICMP)
 *   - src_ip: Địa chỉ IP nguồn cần kiểm tra
 *   - limit: Số gói tối đa cho phép mỗi giây
 *   - now: Timestamp hiện tại (truyền vào để tránh gọi ktime nhiều lần)
 *
 * Trả về: 1 nếu vượt ngưỡng (cần DROP), 0 nếu trong giới hạn (cho qua).
 */
static __always_inline int
check_rate_limit(void *map, __u32 src_ip, __u64 limit, __u64 now)
{
    struct rate_limit_t *entry = bpf_map_lookup_elem(map, &src_ip);

    if (likely(entry)) {
        /* IP đã có trong map - kiểm tra cửa sổ thời gian */
        if (now - entry->last_time > ONE_SECOND_NS) {
            /* Đã sang giây mới → reset bộ đếm */
            entry->last_time = now;
            entry->count = 1;
            return 0;
        }
        entry->count++;
        if (entry->count > limit)
            return 1; /* VƯỢT NGƯỠNG → cần DROP */
        return 0;
    }

    /* IP mới lần đầu xuất hiện → tạo entry mới với count = 1 */
    struct rate_limit_t new_entry = { .last_time = now, .count = 1 };
    bpf_map_update_elem(map, &src_ip, &new_entry, BPF_ANY);
    return 0;
}

/*
 * xdp_auto_redirect - Tự động chuyển tiếp gói tin nếu IP đích có trong bảng redirect.
 *
 * Quy trình:
 *   1. Tra cứu IP đích trong vm_redirect_map
 *   2. Nếu tìm thấy → rewrite MAC nguồn/đích + redirect sang interface đích
 *   3. Nếu không tìm thấy → XDP_PASS (cho kernel xử lý bình thường)
 *
 * Ứng dụng: Load balancer, reverse proxy ở tầng XDP.
 */
static __always_inline int
xdp_auto_redirect(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
    __u32 dst_ip = iph->daddr;
    struct redirect_info *info = bpf_map_lookup_elem(&vm_redirect_map, &dst_ip);


    if (info) {
        /* Ghi đè MAC address (L2 Rewrite) để Switch đẩy tới VM đích */
        __builtin_memcpy(eth->h_source, info->src_mac, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, info->dst_mac, ETH_ALEN);
        
        /* Thay vì bpf_redirect, sử dụng bpf_redirect_map với tx_port_map */
        /* Giúp tăng mạnh hiệu năng nhờ vào cơ chế TX bulking của kernel */
        return bpf_redirect_map(&tx_port_map, info->ifindex, 0);
    }

    /* Nếu không tìm thấy IP đích trong bảng redirect → DROP */
    return XDP_DROP;
}

/*
 * emit_verdict - Ghi kết quả xử lý vào scratch buffer và tail call sang stats program.
 *
 * TỐI ƯU QUAN TRỌNG: Tách stats tracking sang chương trình BPF riêng biệt.
 * Lợi ích:
 *   1. Giảm instruction count trong main program → instruction cache tốt hơn
 *   2. Nếu tail call thất bại → graceful fallback (chỉ mất stats, không mất packet)
 *   3. Có thể thêm logic stats phức tạp mà không ảnh hưởng main program
 *
 * QUAN TRỌNG: bpf_redirect_map() lưu redirect info trong per-CPU storage,
 * KHÔNG phải trên stack. Nên tail call không ảnh hưởng redirect đã setup.
 */
/*
 * block_ip - Thêm IP vào danh sách chặn tạm thời
 */
static __always_inline void
block_ip(__u32 src_ip, __u64 now)
{
    bpf_map_update_elem(&temp_block_map, &src_ip, &now, BPF_ANY);
}

static __always_inline int
emit_verdict(struct xdp_md *ctx, __u64 pkt_size, int action, int reason, __u8 proto, __u16 sport)
{
    __u32 key = 0;
    struct stats_ctx *sc = bpf_map_lookup_elem(&stats_scratch, &key);
    if (sc) {
        sc->pkt_size = pkt_size;
        sc->action = action;
        sc->reason_idx = reason;
        sc->protocol = proto;
        sc->sport = sport;
    }
    /* Tail call sang stats program — nếu thất bại, fallback trả action trực tiếp */
    bpf_tail_call(ctx, &jmp_table, PROG_STATS);
    return action;
}

#endif /* __XDP_HELPERS_H */
