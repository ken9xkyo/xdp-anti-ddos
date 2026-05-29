#ifndef __XDP_COMMON_H
#define __XDP_COMMON_H

/* === Các thư viện cần thiết === */
#include <linux/bpf.h>        /* Các định nghĩa BPF cơ bản (XDP_PASS, XDP_DROP...) */
#include <linux/if_ether.h>   /* Cấu trúc Ethernet header (ethhdr) */
#include <linux/ip.h>         /* Cấu trúc IP header (iphdr) */
#include <linux/ipv6.h>       /* Cấu trúc IPv6 header (ipv6hdr) */
#include <linux/tcp.h>        /* Cấu trúc TCP header (tcphdr) */
#include <linux/udp.h>        /* Cấu trúc UDP header (udphdr) */
#include <linux/icmp.h>       /* Cấu trúc ICMP header */
#include <linux/in.h>         /* Các hằng số protocol (IPPROTO_UDP, IPPROTO_TCP...) */
#include <bpf/bpf_helpers.h>  /* Các hàm helper BPF (bpf_map_lookup_elem...) */
#include <bpf/bpf_endian.h>   /* Chuyển đổi byte order (bpf_htons, bpf_ntohs) */

/*
 * IP_MF và IP_OFFSET dùng để kiểm tra gói tin IP bị phân mảnh (fragmented).
 * Gói tin phân mảnh thường bị lợi dụng trong tấn công DDoS.
 * - IP_MF (More Fragments): Cờ báo còn fragment tiếp theo
 * - IP_OFFSET: Vị trí fragment trong gói tin gốc
 */
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

/* ============================================================================
 * CẤU HÌNH CHƯƠNG TRÌNH
 * Các tham số có thể thay đổi từ userspace (qua xdp_cli.py hoặc control_tool)
 * ============================================================================ */

/* Hằng số thời gian: 1 giây = 1 tỷ nanosecond */
#define ONE_SECOND_NS       1000000000ULL

/* Giới hạn kích thước tối đa cho các BPF map */
#define MAX_WHITELIST       10000      /* Số IP/CIDR tối đa trong whitelist */
#define MAX_BLACKLIST       10000      /* Số IP/CIDR tối đa trong blacklist */
#define MAX_AMP_PORTS       100        /* Số cổng amplification tối đa */
#define MAX_RATE_ENTRIES    1000000    /* Số entry rate limit tối đa (LRU tự xoá cũ) */

/*
 * Chỉ số (index) trong config_map - mỗi chỉ số tương ứng một tham số cấu hình.
 * Userspace có thể thay đổi giá trị runtime mà không cần biên dịch lại.
 */
#define CONFIG_UDP_PPS_LIMIT     0   /* Giới hạn gói UDP/giây từ mỗi IP */
#define CONFIG_UDP_MAX_SIZE      1   /* Kích thước payload UDP tối đa (byte) */
#define CONFIG_ICMP_PPS_LIMIT    2   /* Giới hạn gói ICMP/giây từ mỗi IP */
#define CONFIG_SYN_PPS_LIMIT     3   /* Giới hạn gói SYN/giây từ mỗi IP */
#define CONFIG_MAX_ENTRIES       8   /* Tổng số entry trong config_map */

/* Giá trị mặc định cho các tham số cấu hình */
#define DEFAULT_UDP_PPS_LIMIT    10000  /* 10k gói UDP/giây - đủ cho traffic bình thường */
#define DEFAULT_UDP_MAX_SIZE     1024   /* 1KB - payload UDP lớn hơn thường là tấn công */
#define DEFAULT_ICMP_PPS_LIMIT   100    /* 100 ping/giây - đủ cho monitoring bình thường */
#define DEFAULT_SYN_PPS_LIMIT    10000  /* 10k SYN/giây - cho phép nhiều kết nối mới */

/*
 * Mã lý do DROP - dùng để thống kê tại sao gói tin bị chặn.
 * Rất hữu ích khi debug hoặc hiển thị trên Grafana dashboard.
 */
#define DROP_UNKNOWN_PROTOCOL    0   /* Giao thức không được nhận diện */
#define DROP_FRAGMENTED          1   /* Gói tin bị phân mảnh (fragment attack) */
#define DROP_UDP_RATELIMIT       2   /* Vượt quá giới hạn gói UDP/giây */
#define DROP_UDP_AMPLIFICATION   3   /* Gói từ cổng hay bị amplification */
#define DROP_UDP_PAYLOAD_SIZE    4   /* Payload UDP quá lớn */
#define DROP_TCP_INVALID         5   /* Cờ TCP không hợp lệ (scan/attack) */
#define DROP_ICMP_RATELIMIT      6   /* Vượt quá giới hạn ICMP/giây */
#define DROP_SYN_RATELIMIT       7   /* Vượt quá giới hạn SYN/giây */
#define DROP_BLACKLIST           8   /* IP nằm trong danh sách đen */
#define DROP_PARSE_ERROR         9   /* Lỗi khi phân tích header gói tin */
#define DROP_TEMP_BLOCK          10  /* Đang bị chặn tạm thời do vi phạm */
#define DROP_MAX_REASONS         11  /* Tổng số lý do DROP (kích thước mảng) */

/*
 * ACL (Access Control List) - Giá trị hành động trong acl_map (merged BL/WL).
 * Hợp nhất blacklist + whitelist vào 1 map duy nhất để tiết kiệm 1 LPM lookup
 * (~80 cycles/packet). Rule cụ thể nhất (longest prefix) luôn thắng.
 */
#define ACL_ALLOW               1   /* Cho phép (whitelist) */
#define ACL_DENY                2   /* Chặn (blacklist) */
#define MAX_ACL_ENTRIES         20000  /* MAX_WHITELIST + MAX_BLACKLIST */

/* Tail call program indices trong jmp_table */
#define PROG_STATS              0   /* Chương trình thống kê (tail-called) */

/*
 * VLAN (Virtual LAN) - mạng ảo trên cùng switch vật lý.
 * Gói tin VLAN có thêm 4 byte header chứa VLAN ID.
 * QinQ (802.1ad) cho phép lồng 2 lớp VLAN.
 */
#define ETH_P_8021Q         0x8100   /* VLAN tag đơn (802.1Q) */
#define ETH_P_8021AD        0x88A8   /* VLAN tag kép - QinQ (802.1ad) */
#define VLAN_HDR_SZ         4        /* Kích thước VLAN header: 4 byte */

/*
 * Các cờ TCP (TCP Flags) - dùng để nhận diện loại gói TCP.
 * Tổ hợp flag bất thường (ví dụ: SYN+FIN) là dấu hiệu tấn công.
 */
#define RAW_TCP_FIN         0x01  /* Kết thúc kết nối */
#define RAW_TCP_SYN         0x02  /* Bắt đầu kết nối mới */
#define RAW_TCP_RST         0x04  /* Reset kết nối */
#define RAW_TCP_PSH         0x08  /* Gửi dữ liệu ngay, không buffer */
#define RAW_TCP_ACK         0x10  /* Xác nhận đã nhận dữ liệu */
#define RAW_TCP_URG         0x20  /* Dữ liệu khẩn cấp */

/*
 * Macro tối ưu hiệu năng - gợi ý cho compiler dự đoán nhánh:
 * - likely(x): x hầu như luôn đúng → tối ưu nhánh đúng
 * - unlikely(x): x hầu như luôn sai → tối ưu nhánh sai
 * Giúp CPU dự đoán nhánh (branch prediction) tốt hơn.
 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

/* Số bucket (khoảng) phân loại kích thước gói tin cho thống kê */
#define PKT_SIZE_BUCKETS 6

#endif /* __XDP_COMMON_H */
