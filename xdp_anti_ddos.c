// SPDX-License-Identifier: GPL-2.0
/*
 * ============================================================================
 * XDP Anti-DDoS - Chương trình bảo vệ chống tấn công DDoS chạy trên XDP
 * ============================================================================
 *
 * XDP (eXpress Data Path) là công nghệ xử lý gói tin ở tầng thấp nhất trong
 * Linux kernel, cho phép lọc gói tin với hiệu năng cực cao (hàng triệu gói/giây).
 *
 * Tối ưu hóa cho kiến trúc Out-of-Band Scrubbing (2 cổng: IN / OUT)
 * ============================================================================
 *
 * Chương trình này hoạt động như một bộ lọc thông minh:
 *   1. Gói tin đến → Phân tích header (Ethernet → IP → UDP/TCP/ICMP)
 *   2. Kiểm tra whitelist (danh sách IP được phép) → Cho qua ngay
 *   3. Phát hiện gói tin bất thường → Chặn (DROP)
 *   4. Gói tin hợp lệ → L2 MAC Rewrite & Chuyển tiếp (redirect qua DEVMAP)
 *
 * Các tính năng bảo vệ:
 *   - IP Whitelist: Danh sách IP tin cậy, không bị kiểm tra
 *   - Chặn UDP Amplification: Chặn các gói từ cổng hay bị lợi dụng (DNS, NTP...)
 *   - Rate Limiting UDP/ICMP/SYN: Giới hạn số gói tin/giây từ mỗi IP
 *   - Kiểm tra kích thước payload UDP: Chặn gói tin quá lớn
 *   - Chặn TCP bất thường: Phát hiện flag TCP không hợp lệ
 *   - Thống kê toàn diện: Theo dõi realtime cho Grafana
 */

#include "xdp_common.h"
#include "xdp_structs.h"
#include "xdp_maps.h"
#include "xdp_helpers.h"

/*
 * xdp_stats_prog - Chương trình stats chạy qua tail call.
 *
 * Đọc context từ stats_scratch, cập nhật global_stats_map,
 * sau đó trả về XDP action đã lưu.
 *
 * bpf_redirect_map() info được lưu trong per-CPU bpf_redirect_info,
 * nên return XDP_REDIRECT từ đây vẫn hoạt động đúng.
 */
SEC("xdp/stats")
int xdp_stats_prog(struct xdp_md *ctx)
{
    __u32 key = 0;
    struct stats_ctx *sc = bpf_map_lookup_elem(&stats_scratch, &key);
    if (!sc)
        return XDP_PASS;

    track_stats(sc->pkt_size, sc->action, sc->reason_idx, sc->protocol, sc->sport);

    /* Trả về action gốc — kernel sử dụng giá trị này để quyết định */
    return sc->action;
}

/* ============================================================================
 * HÀM CHÍNH - Entry point cho mọi gói tin đến interface
 *
 * Đây là hàm được XDP gọi cho mỗi gói tin. Quy trình xử lý:
 *
 *   Gói tin đến
 *       │
 *       ▼
 *   Phân tích Ethernet header (xử lý VLAN nếu có)
 *       │
 *       ▼
 *   IPv6? ──→ Blacklist/Whitelist check (LPM) → PASS/DROP
 *       │
 *       ▼
 *   Không phải IPv4? ──→ XDP_PASS
 *       │
 *       ▼
 *   Phân tích IP header (bounds + IHL + version validation)
 *       │
 *       ▼
 *   Gói tin phân mảnh? ──→ XDP_DROP (rẻ nhất, check trước)
 *       │
 *       ▼
 *   IP trong blacklist? ──→ DROP (early drop, ưu tiên cao nhất)
 *       │
 *       ▼
 *   IP trong whitelist? ──→ Redirect hoặc PASS (bypass mọi check)
 *       │
 *       ▼
 *   ┌─────────────────────────────────────┐
 *   │ Xử lý theo giao thức:              │
 *   │  UDP  → Amp check → Size → Rate    │
 *   │  TCP  → Flag check → SYN rate      │
 *   │  ICMP → Rate limit                 │
 *   │  Khác → Redirect/PASS              │
 *   └─────────────────────────────────────┘
 *       │
 *       ▼
 *   XDP_PASS / XDP_DROP / XDP_REDIRECT
 *
 * BẢO MẬT:
 *   - Mọi header access đều có bounds check trước (OOB prevention)
 *   - Blacklist kiểm tra TRƯỚC whitelist (early drop cho DDoS)
 *   - IHL validation: min=20, max=60 byte (chống header manipulation)
 *   - Fragment detection: DROP tất cả gói phân mảnh
 *   - LPM Trie maps sử dụng BPF RCU (read-copy-update) tự động
 *   - max_entries cứng trên mọi map (chống resource exhaustion)
 *
 * Trả về:
 *   - XDP_PASS: Cho gói tin vào kernel network stack bình thường
 *   - XDP_DROP: Huỷ gói tin ngay tại driver (nhanh nhất)
 *   - XDP_REDIRECT: Chuyển gói tin sang interface khác
 * ============================================================================ */

SEC("xdp")
int xdp_anti_ddos(struct xdp_md *ctx)
{
    /* === Bước 1: Lấy thông tin cơ bản === */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 pkt_size = data_end - data;

    /*
     * TỐI ƯU: bpf_ktime_get_coarse_ns() là hàm nhanh nhất:
     * - Sử dụng vDSO cached clock (~5ns jitter, đủ cho rate limit 1s window)
     * - bpf_ktime_get_ns(): chính xác hơn nhưng chậm hơn ~10-20cy
     * - bpf_ktime_get_boot_ns(): bao gồm suspend time, chậm hơn
     */
    __u64 now = bpf_ktime_get_coarse_ns();

    /*
     * TỐI ƯU CỰC HẠN (Extreme Performance Tuning):
     * Các giá trị get_config() đã được chuyển sâu xuống từng nhánh protocol (Lazy Evaluation).
     * Giúp giảm từ 3-4 lời gọi BPF map lookup (~120 cycles) đối với mọi gói tin bị drop sớm
     * hoặc không phải giao thức tương ứng (e.g. gói TCP không cần lookup UDP config).
     */

    /* === Bước 2: Ethernet header === */
    struct ethhdr *eth = data;
    int eth_off = 0;

    if (unlikely((void *)(eth + 1) > data_end))
        return XDP_DROP; /* EARLY DROP Strategy: XDP_DROP ngay lập tức, bỏ qua stats để tránh CPU Exhaustion do spam lỗi */

    __u16 h_proto = parse_eth(eth, data_end, &eth_off);

    /* === Bước 3: IPv6 ACL (1 lookup thay vì 2) === */
    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + eth_off;
        if (unlikely((void *)(ip6h + 1) > data_end || ip6h->version != 6))
            return XDP_DROP; /* EARLY DROP */

        __u8 acl_v6 = check_acl_v6(&ip6h->saddr);
        if (unlikely(acl_v6 == ACL_DENY))
            return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_BLACKLIST, 0, 0);
        if (unlikely(acl_v6 == ACL_ALLOW))
            return emit_verdict(ctx, pkt_size, XDP_PASS, -1, 0, 0);
        return emit_verdict(ctx, pkt_size, XDP_PASS, -1, 0, 0);
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return emit_verdict(ctx, pkt_size, XDP_PASS, -1, 0, 0);

    /* === Bước 4: IPv4 header validation === */
    struct iphdr *iph = data + eth_off;
    if (unlikely((void *)(iph + 1) > data_end))
        return XDP_DROP;

    /* SECURITY PATCH & VERIFIER SAFETY: Sử dụng bitwise mask để ép giới hạn cho biến 
     * ip_hdr_len, ngăn chặn triệt để lỗi Pointer Arithmetic và Out-Of-Bounds. */
    __u8 ihl = iph->ihl & 0x0F;
    int ip_hdr_len = ihl * 4;
    
    if (unlikely(ip_hdr_len < (int)sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end))
        return XDP_DROP;

    if (unlikely(iph->version != 4))
        return XDP_DROP;

    __u32 src_ip = iph->saddr;
    __u8 protocol = iph->protocol;

    /* === Bước 5: Fragment check (~3cy, trước LPM ~80cy) === */
    /* SECURITY: Chặn TUYỆT ĐỐI các gói phân mảnh (Fragment Attacks, Teardrop, v.v.). EARLY DROP. */
    if (unlikely((iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0)) {
        block_ip(src_ip, now);
        return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_FRAGMENTED, protocol, 0);
    }

    /* === Bước 6: ACL — 1 lookup thay vì 2 (tiết kiệm ~80cy) ===
     * Merged blacklist + whitelist. Longest prefix match thắng.
     */
    __u8 acl = check_acl(src_ip);

    // Kiểm tra IP có trong whitelist trước để tránh trường hợp chặn nhầm
    if (unlikely(acl == ACL_ALLOW)) {
        int ret = xdp_auto_redirect(ctx, eth, iph);
        return emit_verdict(ctx, pkt_size,
                           (ret == XDP_REDIRECT) ? XDP_REDIRECT : XDP_DROP,
                           -1, protocol, 0);
    }

    // Kiểm tra IP có trong blacklist không
    if (unlikely(acl == ACL_DENY))
        return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_BLACKLIST, protocol, 0);


    /* === Bước 6.5: Kiểm tra Temporary Block (Chặn 10 phút) === */
    // __u64 *blocked_time = bpf_map_lookup_elem(&temp_block_map, &src_ip);
    // if (unlikely(blocked_time)) {
    //     /* Kiểm tra đã quá 10 phút chưa */
    //     if (now - *blocked_time < 10ULL * 60ULL * ONE_SECOND_NS) {
    //         return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_TEMP_BLOCK, protocol, 0);
    //     } else {
    //         /* Hết hạn 10 phút -> Xoá khỏi danh sách chặn tạm thời */
    //         bpf_map_delete_elem(&temp_block_map, &src_ip);
    //     }
    // }

    void *l4_hdr = (void *)iph + ip_hdr_len;

    /* ================================================================
     * UDP — cached config (cfg_udp_pps, cfg_udp_size)
     * ================================================================ */
    if (protocol == IPPROTO_UDP) {
        /* LAZY EVALUATION: Chỉ tra cứu BPF map cho giới hạn cấu hình UDP nếu đúng là UDP traffic. */
        __u64 cfg_udp_size = get_config(CONFIG_UDP_MAX_SIZE, DEFAULT_UDP_MAX_SIZE);
        __u64 cfg_udp_pps  = get_config(CONFIG_UDP_PPS_LIMIT, DEFAULT_UDP_PPS_LIMIT);

        struct udphdr *udph = l4_hdr;
        if (unlikely((void *)(udph + 1) > data_end))
            return XDP_DROP;

        /* SECURITY PATCH: Malformed Packet Defense (Thực thi giới hạn độ dài payload UDP thực tế) */
        __u32 claimed_len = bpf_ntohs(udph->len);
        if (unlikely(claimed_len < sizeof(struct udphdr) || (__u64)(data_end - (void *)udph) < claimed_len))
            return XDP_DROP;

        __u16 sport = bpf_ntohs(udph->source);
        __u64 l4_len = data_end - l4_hdr;
        __u64 payload_len = (l4_len > sizeof(struct udphdr)) ?
                            (l4_len - sizeof(struct udphdr)) : 0;

        if (is_amp_port(sport)) {
            block_ip(src_ip, now);
            return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_UDP_AMPLIFICATION, protocol, sport);
        }
        if (payload_len > cfg_udp_size) {
            block_ip(src_ip, now);
            return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_UDP_PAYLOAD_SIZE, protocol, sport);
        }
        if (check_rate_limit(&rate_limit_map, src_ip, cfg_udp_pps, now)) {
            block_ip(src_ip, now);
            return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_UDP_RATELIMIT, protocol, sport);
        }

        int ret = xdp_auto_redirect(ctx, eth, iph);
        return emit_verdict(ctx, pkt_size,
                           (ret == XDP_REDIRECT) ? XDP_REDIRECT : XDP_DROP,
                           -1, protocol, sport);
    }

    /* ================================================================
     * TCP
     * ================================================================ */
    if (protocol == IPPROTO_TCP) {
        /* LAZY EVALUATION: Tra cứu cấu hình TCP SYN PPS Map riêng cho gói TCP */
        __u64 cfg_syn_pps = get_config(CONFIG_SYN_PPS_LIMIT, DEFAULT_SYN_PPS_LIMIT);

        struct tcphdr *tcph = l4_hdr;
        if (unlikely((void *)(tcph + 1) > data_end))
            return XDP_DROP;

        /* SECURITY PATCH: Malformed Packet Defense (Bảo vệ OOB từ giả mạo tcph->doff) */
        int tcp_hdr_len = (tcph->doff & 0x0F) * 4;
        if (unlikely(tcp_hdr_len < (int)sizeof(struct tcphdr) || (void *)tcph + tcp_hdr_len > data_end))
            return XDP_DROP;

        __u8 flags = ((__u8 *)tcph)[13];

        if (flags == 0 ||
           ((flags & (RAW_TCP_SYN | RAW_TCP_FIN)) == (RAW_TCP_SYN | RAW_TCP_FIN)) ||
           ((flags & (RAW_TCP_SYN | RAW_TCP_RST)) == (RAW_TCP_SYN | RAW_TCP_RST)) ||
           ((flags & (RAW_TCP_FIN | RAW_TCP_RST)) == (RAW_TCP_FIN | RAW_TCP_RST)) ||
           ((flags & (RAW_TCP_FIN | RAW_TCP_PSH | RAW_TCP_URG)) == (RAW_TCP_FIN | RAW_TCP_PSH | RAW_TCP_URG))) {
            block_ip(src_ip, now);
            return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_TCP_INVALID, protocol, 0);
        }

        if ((flags & RAW_TCP_SYN) && !(flags & RAW_TCP_ACK)) {
            if (check_rate_limit(&rate_limit_syn_map, src_ip, cfg_syn_pps, now)) {
                block_ip(src_ip, now);
                return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_SYN_RATELIMIT, protocol, 0);
            }
        }

        int ret = xdp_auto_redirect(ctx, eth, iph);
        return emit_verdict(ctx, pkt_size,
                           (ret == XDP_REDIRECT) ? XDP_REDIRECT : XDP_DROP,
                           -1, protocol, 0);
    }

    /* ================================================================
     * ICMP — cached config (cfg_icmp_pps)
     * ================================================================ */
    if (protocol == IPPROTO_ICMP) {
        /* LAZY EVALUATION: Tra cứu cấu hình ICMP PPS Limit thông qua BPF lookup ở last resort */
        __u64 cfg_icmp_pps = get_config(CONFIG_ICMP_PPS_LIMIT, DEFAULT_ICMP_PPS_LIMIT);

        struct icmphdr *icmph = l4_hdr;
        if (unlikely((void *)(icmph + 1) > data_end))
            return XDP_DROP;

        if (check_rate_limit(&rate_limit_icmp_map, src_ip, cfg_icmp_pps, now)) {
            block_ip(src_ip, now);
            return emit_verdict(ctx, pkt_size, XDP_DROP, DROP_ICMP_RATELIMIT, protocol, 0);
        }

        int ret = xdp_auto_redirect(ctx, eth, iph);
        return emit_verdict(ctx, pkt_size,
                           (ret == XDP_REDIRECT) ? XDP_REDIRECT : XDP_DROP,
                           -1, protocol, 0);
    }

    /* Giao thức khác */
    int ret = xdp_auto_redirect(ctx, eth, iph);
    return emit_verdict(ctx, pkt_size,
                       (ret == XDP_REDIRECT) ? XDP_REDIRECT : XDP_DROP,
                       -1, protocol, 0);
}

/* Khai báo license GPL - BẮT BUỘC để BPF verifier cho phép load chương trình */
char _license[] SEC("license") = "GPL";
