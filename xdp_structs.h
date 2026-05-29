#ifndef __XDP_STRUCTS_H
#define __XDP_STRUCTS_H

#include "xdp_common.h"

/* ============================================================================
 * CẤU TRÚC DỮ LIỆU (DATA STRUCTURES)
 *
 * BPF yêu cầu khai báo cấu trúc dữ liệu rõ ràng vì chạy trong kernel.
 * aligned() giúp truy cập bộ nhớ nhanh hơn nhờ căn chỉnh cache line.
 * ============================================================================ */

/*
 * Cấu trúc thống kê toàn cục - chứa TẤT CẢ số liệu của hệ thống.
 * Đây là struct duy nhất cho thống kê, tránh phân tán dữ liệu.
 *
 * Dùng PERCPU_ARRAY: mỗi CPU có bản sao riêng → không cần lock,
 * userspace tổng hợp kết quả từ tất cả CPU khi đọc.
 */
struct xdp_global_stats {
    /* === Thống kê tổng quan: đếm gói qua/chặn/redirect === */
    __u64 packets_passed;       /* Số gói cho qua */
    __u64 bytes_passed;         /* Tổng byte cho qua */
    __u64 packets_dropped;      /* Số gói bị chặn */
    __u64 bytes_dropped;        /* Tổng byte bị chặn */
    __u64 packets_redirected;   /* Số gói được redirect sang interface khác */
    __u64 bytes_redirected;     /* Tổng byte được redirect */

    /* === Lý do DROP: đếm theo từng loại === */
    __u64 drop_reasons[DROP_MAX_REASONS];

    /* === Phân loại theo giao thức === */
    __u64 proto_udp;     /* Số gói UDP */
    __u64 proto_tcp;     /* Số gói TCP */
    __u64 proto_icmp;    /* Số gói ICMP */
    __u64 proto_other;   /* Các giao thức khác */

    /* === Phân loại kích thước gói (6 khoảng) ===
     * Bucket: 0-64, 65-128, 129-256, 257-512, 513-1024, 1025+
     * Giúp phát hiện pattern tấn công (VD: flood toàn gói nhỏ)
     */
    __u64 pkt_size_buckets[PKT_SIZE_BUCKETS];

    /* === Thống kê cổng nguồn UDP - phát hiện tấn công Amplification ===
     * Amplification attack: Attacker giả IP nạn nhân, gửi request nhỏ đến
     * server (DNS/NTP...), server trả response lớn về IP nạn nhân.
     * Theo dõi các cổng hay bị lợi dụng giúp nhận diện loại tấn công.
     */
    __u64 sport_dns;             /* Cổng 53 - DNS amplification */
    __u64 sport_ntp;             /* Cổng 123 - NTP amplification */
    __u64 sport_ssdp;            /* Cổng 1900 - SSDP amplification */
    __u64 sport_memcached;       /* Cổng 11211 - Memcached amplification */
    __u64 sport_chargen;         /* Cổng 19 - Chargen amplification */
    __u64 sport_other_reflection; /* Các cổng phản xạ khác (< 1024) */
};

/*
 * Cấu trúc rate limiting - theo dõi tốc độ gửi gói tin.
 *
 * Cách hoạt động: Đếm số gói trong cửa sổ 1 giây.
 * Nếu vượt ngưỡng → gói bị DROP cho đến khi reset cửa sổ mới.
 * aligned(16) giúp truy cập nhanh hơn trên các kiến trúc CPU hiện đại.
 */
struct rate_limit_t {
    __u64 last_time;  /* Thời điểm bắt đầu cửa sổ đếm hiện tại (nanosecond) */
    __u64 count;      /* Số gói đã đếm trong cửa sổ hiện tại */
} __attribute__((aligned(16)));

/*
 * Cấu trúc key cho BPF LPM Trie (Longest Prefix Match) - IPv4.
 *
 * BPF_MAP_TYPE_LPM_TRIE yêu cầu key phải có trường prefixlen ở đầu,
 * theo sau là dữ liệu địa chỉ. Kernel sử dụng Radix Tree (compressed trie)
 * để thực hiện bitwise longest-prefix matching.
 *
 * Ví dụ:
 *   - prefixlen=32, addr=10.1.2.3 → match chính xác IP 10.1.2.3
 *   - prefixlen=24, addr=10.1.2.0 → match tất cả IP trong 10.1.2.0/24
 *   - prefixlen=8,  addr=10.0.0.0 → match tất cả IP trong 10.0.0.0/8
 */
struct lpm_key_ipv4 {
    __u32 prefixlen;  /* Số bit prefix (0-32 cho IPv4) */
    __u32 addr;       /* Địa chỉ IPv4 (network byte order) */
};

/*
 * Cấu trúc key cho BPF LPM Trie - IPv6.
 *
 * Tương tự IPv4 nhưng với 128-bit address.
 * - prefixlen: Số bit prefix (0-128 cho IPv6)
 * - addr: Địa chỉ IPv6 (16 byte, network byte order)
 *
 * Ví dụ:
 *   - prefixlen=128, addr=2001:db8::1 → match chính xác
 *   - prefixlen=48,  addr=2001:db8:1:: → match subnet /48
 */
struct lpm_key_ipv6 {
    __u32 prefixlen;  /* Số bit prefix (0-128 cho IPv6) */
    __u8  addr[16];   /* Địa chỉ IPv6 (128-bit, network byte order) */
};

/*
 * Thông tin redirect - dùng để chuyển tiếp gói tin sang interface khác.
 *
 * Khi server nhận traffic cho một VM (Virtual IP), gói tin sẽ được
 * rewrite MAC và redirect sang server backend thật sự xử lý.
 */
struct redirect_info {
    unsigned char src_mac[6];  /* MAC nguồn mới (thường là MAC của server này) */
    unsigned char dst_mac[6];  /* MAC đích mới (MAC của backend server) */
    __u32 ifindex;             /* Interface index để gửi gói tin đi */
};

/*
 * Context truyền dữ liệu cho tail-called stats program.
 * Dùng per-CPU array để tránh lock. Main program ghi → stats program đọc.
 */
struct stats_ctx {
    __u64 pkt_size;     /* Kích thước gói tin */
    __s32 action;       /* XDP action (PASS/DROP/REDIRECT) */
    __s32 reason_idx;   /* Lý do DROP (-1 nếu không DROP) */
    __u8  protocol;     /* IP protocol (UDP/TCP/ICMP) */
    __u16 sport;        /* Source port (cho UDP stats) */
} __attribute__((aligned(8)));

#endif /* __XDP_STRUCTS_H */
