// SPDX-License-Identifier: GPL-2.0
/*
 * ============================================================================
 * XDP Anti-DDoS - Chương trình bảo vệ chống tấn công DDoS chạy trên XDP
 * ============================================================================
 *
 * XDP (eXpress Data Path) là công nghệ xử lý gói tin ở tầng thấp nhất trong
 * Linux kernel, cho phép lọc gói tin với hiệu năng cực cao (hàng triệu gói/giây).
 *
 * Chương trình này hoạt động như một bộ lọc thông minh:
 *   1. Gói tin đến → Phân tích header (Ethernet → IP → UDP/TCP/ICMP)
 *   2. Kiểm tra whitelist (danh sách IP được phép) → Cho qua ngay
 *   3. Phát hiện gói tin bất thường → Chặn (DROP)
 *   4. Gói tin hợp lệ → Chuyển tiếp (redirect) hoặc cho qua (pass)
 *
 * Các tính năng bảo vệ:
 *   - IP Whitelist: Danh sách IP tin cậy, không bị kiểm tra
 *   - Chặn UDP Amplification: Chặn các gói từ cổng hay bị lợi dụng (DNS, NTP...)
 *   - Rate Limiting UDP/ICMP/SYN: Giới hạn số gói tin/giây từ mỗi IP
 *   - Kiểm tra kích thước payload UDP: Chặn gói tin quá lớn
 *   - Chặn TCP bất thường: Phát hiện flag TCP không hợp lệ
 *   - Thống kê toàn diện: Theo dõi realtime cho Grafana
 */

/* === Các thư viện cần thiết === */
#include <linux/bpf.h>        /* Các định nghĩa BPF cơ bản (XDP_PASS, XDP_DROP...) */
#include <linux/if_ether.h>   /* Cấu trúc Ethernet header (ethhdr) */
#include <linux/ip.h>         /* Cấu trúc IP header (iphdr) */
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
#define MAX_WHITELIST       10000      /* Số IP tối đa trong whitelist */
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
#define DROP_MAX_REASONS         10  /* Tổng số lý do DROP (kích thước mảng) */

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
 * Thông tin redirect - dùng để chuyển tiếp gói tin sang interface khác.
 *
 * Khi server nhận traffic cho một VIP (Virtual IP), gói tin sẽ được
 * rewrite MAC và redirect sang server backend thật sự xử lý.
 */
struct redirect_info {
    unsigned char src_mac[6];  /* MAC nguồn mới (thường là MAC của server này) */
    unsigned char dst_mac[6];  /* MAC đích mới (MAC của backend server) */
    __u32 ifindex;             /* Interface index để gửi gói tin đi */
};

/* ============================================================================
 * BPF MAPS - Các "bảng dữ liệu" chia sẻ giữa kernel và userspace
 *
 * BPF Map là cơ chế chính để:
 *   1. Kernel ↔ Userspace trao đổi dữ liệu
 *   2. Lưu trạng thái giữa các lần xử lý gói tin
 *
 * Các loại map dùng trong chương trình:
 *   - HASH: Bảng băm key-value, tra cứu O(1)
 *   - LRU_PERCPU_HASH: Hash + tự xoá entry cũ nhất + mỗi CPU riêng
 *   - PERCPU_ARRAY: Mảng với bản sao per-CPU (không lock, hiệu năng cao)
 * ============================================================================ */

/*
 * Danh sách trắng IP (Whitelist)
 * IP trong whitelist được cho qua ngay, không kiểm tra gì thêm.
 * - Key: __u32 = địa chỉ IPv4 (4 byte)
 * - Value: __u8 = 1 (chỉ cần tồn tại, giá trị không quan trọng)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST);
    __type(key, __u32);
    __type(value, __u8);
} whitelist_map SEC(".maps");

/*
 * Danh sách cổng Amplification cần chặn
 * Gói UDP từ các cổng này thường là tấn công khuếch đại.
 * Userspace có thể thêm/xoá cổng runtime qua xdp_cli.py.
 * - Key: __u16 = số cổng nguồn
 * - Value: __u8 = 1 (chỉ cần tồn tại)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_AMP_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} amp_ports_map SEC(".maps");

/*
 * Cấu hình runtime - mảng chứa các tham số có thể thay đổi khi đang chạy.
 * - Key: __u32 = chỉ số CONFIG_xxx (xem phần #define ở trên)
 * - Value: __u64 = giá trị cấu hình
 * Ví dụ: key=0 (CONFIG_UDP_PPS_LIMIT, value=10000 (10k gói/giây)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CONFIG_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

/*
 * Rate limiting cho gói UDP - đếm theo từng IP nguồn.
 *
 * LRU_PERCPU_HASH:
 * - LRU: Khi map đầy, tự xoá entry ít dùng nhất → không lo tràn bộ nhớ
 * - PERCPU: Mỗi CPU có bản sao riêng → không cần lock, cực nhanh
 *   (trade-off: tổng PPS thực tế = limit × số_CPU, chấp nhận được)
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_t);
} rate_limit_map SEC(".maps");

/*
 * Rate limiting riêng cho SYN flood
 * Tách riêng khỏi UDP để tránh SYN flood ảnh hưởng đến UDP limit
 * và ngược lại. Mỗi loại tấn công có ngưỡng riêng.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_t);
} rate_limit_syn_map SEC(".maps");

/*
 * Rate limiting riêng cho ICMP (ping flood)
 * ICMP flood là loại tấn công phổ biến, cần giới hạn riêng.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_t);
} rate_limit_icmp_map SEC(".maps");

/*
 * Bảng redirect theo VIP (Virtual IP)
 * Khi gói tin đến có IP đích nằm trong bảng này, gói sẽ được
 * rewrite MAC và chuyển tiếp sang backend server tương ứng.
 * - Key: __u32 = IP đích (VIP)
 * - Value: struct redirect_info = thông tin MAC + interface đích
 * - pinning: Map được ghim (pin) trong filesystem (/sys/fs/bpf/)
 *   để các tool userspace khác có thể truy cập.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct redirect_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vip_redirect_map SEC(".maps");

/*
 * Thống kê toàn cục (global stats)
 * Chỉ có 1 entry (key=0), chứa toàn bộ số liệu thống kê hệ thống.
 * PERCPU_ARRAY: Mỗi CPU ghi vào bản sao riêng → không xung đột.
 * Userspace (prometheus_exporter.py) sẽ tổng hợp từ tất cả CPU.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_global_stats);
} global_stats_map SEC(".maps");

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
 * is_whitelisted - Kiểm tra IP có trong danh sách trắng không.
 *
 * Trả về: 1 nếu IP được whitelist (cho qua ngay), 0 nếu không.
 * Chỉ cần kiểm tra key có tồn tại, không cần đọc value.
 */
static __always_inline int is_whitelisted(__u32 ip)
{
    __u8 *val = bpf_map_lookup_elem(&whitelist_map, &ip);
    return val != NULL;
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

    /* Kiểm tra và bóc VLAN tag lớp 1 (nếu có) */
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;                  /* VLAN ID + Priority */
            __be16 h_vlan_encapsulated_proto;   /* EtherType thật */
        } *vhdr;
        vhdr = (void *)eth + *offset;
        if ((void *)(vhdr + 1) > data_end) return 0;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        *offset += VLAN_HDR_SZ;

        /* Kiểm tra VLAN tag lớp 2 - QinQ (nếu có) */
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            vhdr = (void *)eth + *offset;
            if ((void *)(vhdr + 1) > data_end) return 0;
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
 *   1. Tra cứu IP đích trong vip_redirect_map
 *   2. Nếu tìm thấy → rewrite MAC nguồn/đích + redirect sang interface đích
 *   3. Nếu không tìm thấy → XDP_PASS (cho kernel xử lý bình thường)
 *
 * Ứng dụng: Load balancer, reverse proxy ở tầng XDP.
 */
static __always_inline int
xdp_auto_redirect(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
    __u32 dst_ip = iph->daddr;
    struct redirect_info *info = bpf_map_lookup_elem(&vip_redirect_map, &dst_ip);

    if (info) {
        /* Ghi đè MAC address: đổi nguồn/đích để gói tin đi đúng hướng */
        __builtin_memcpy(eth->h_source, info->src_mac, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, info->dst_mac, ETH_ALEN);
        /* Gửi gói tin ra interface đích */
        return bpf_redirect(info->ifindex, 0);
    }
    /* Không có rule redirect → cho kernel xử lý */
    return XDP_PASS;
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
 *   Không phải IPv4? ──→ XDP_PASS (cho qua)
 *       │
 *       ▼
 *   Phân tích IP header
 *       │
 *       ▼
 *   IP trong whitelist? ──→ Redirect hoặc PASS
 *       │
 *       ▼
 *   Gói tin phân mảnh? ──→ XDP_DROP
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
 * Trả về:
 *   - XDP_PASS: Cho gói tin vào kernel network stack bình thường
 *   - XDP_DROP: Huỷ gói tin ngay tại driver (nhanh nhất)
 *   - XDP_REDIRECT: Chuyển gói tin sang interface khác
 * ============================================================================ */

SEC("xdp")
int xdp_anti_ddos(struct xdp_md *ctx)
{
    /* === Bước 1: Lấy thông tin cơ bản của gói tin === */
    void *data_end = (void *)(long)ctx->data_end; /* Biên cuối gói tin */
    void *data = (void *)(long)ctx->data;         /* Biên đầu gói tin */
    __u64 pkt_size = data_end - data;             /* Kích thước tổng gói tin */
    __u64 now = bpf_ktime_get_coarse_ns();        /* Timestamp hiện tại (ns) */

    /* === Bước 2: Phân tích Ethernet header ===
     * Mỗi gói tin bắt đầu bằng Ethernet header (14 byte).
     * Cần kiểm tra gói tin đủ lớn trước khi đọc (BPF verifier yêu cầu).
     */
    struct ethhdr *eth = data;
    int eth_off = 0;

    if ((void *)(eth + 1) > data_end) {
        /* Gói tin quá nhỏ, không đủ Ethernet header → DROP */
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR, 0, 0);
        return XDP_DROP;
    }

    /* Phân tích EtherType, bóc VLAN nếu có. eth_off = vị trí IP header */
    __u16 h_proto = parse_eth(eth, data_end, &eth_off);

    /* === Bước 3: Chỉ xử lý IPv4 ===
     * IPv6 và các giao thức khác được cho qua để kernel xử lý.
     * Chương trình này chỉ bảo vệ chống DDoS trên IPv4.
     */
    if (h_proto != bpf_htons(ETH_P_IP)) {
        track_stats(pkt_size, XDP_PASS, -1, 0, 0);
        return XDP_PASS;
    }

    /* === Bước 4: Phân tích IP header ===
     * Kiểm tra gói tin đủ lớn để chứa IP header.
     * IP header có kích thước biến đổi: tối thiểu 20 byte (ihl=5),
     * tối đa 60 byte (khi có IP options).
     */
    struct iphdr *iph = data + eth_off;
    if ((void *)(iph + 1) > data_end) {
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR, 0, 0);
        return XDP_DROP;
    }

    int ip_hdr_len = iph->ihl * 4; /* ihl = số word 32-bit, nhân 4 ra byte */
    if (ip_hdr_len < 20 || (void *)iph + ip_hdr_len > data_end) {
        /* IP header không hợp lệ (quá nhỏ hoặc tràn giới hạn gói tin) */
        track_stats(pkt_size, XDP_DROP, DROP_PARSE_ERROR, 0, 0);
        return XDP_DROP;
    }

    __u32 src_ip = iph->saddr;     /* Địa chỉ IP nguồn */
    __u8 protocol = iph->protocol; /* Giao thức tầng trên (UDP=17, TCP=6, ICMP=1) */

    /* === Bước 5: Kiểm tra Whitelist ===
     * IP trong whitelist được cho qua ngay, không kiểm tra rate limit hay gì cả.
     * unlikely() vì đa số IP không nằm trong whitelist.
     */
    if (unlikely(is_whitelisted(src_ip))) {
        track_stats(pkt_size, XDP_PASS, -1, protocol, 0);
        return xdp_auto_redirect(ctx, eth, iph);
    }

    /* === Bước 6: Chặn gói tin phân mảnh (IP Fragment) ===
     * Fragment attack: Attacker gửi gói tin phân mảnh để bypass firewall
     * vì fragment thứ 2 trở đi không có TCP/UDP header.
     * Giải pháp đơn giản: DROP tất cả gói phân mảnh.
     */
    if (unlikely((iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0)) {
        track_stats(pkt_size, XDP_DROP, DROP_FRAGMENTED, protocol, 0);
        return XDP_DROP;
    }

    /* Con trỏ đến header tầng 4 (TCP/UDP/ICMP) */
    void *l4_hdr = (void *)iph + ip_hdr_len;

    /* ================================================================
     * XỬ LÝ UDP
     * Thứ tự kiểm tra được tối ưu: rẻ nhất trước, đắt nhất sau
     *   1. Amplification port check (chỉ lookup map, rẻ)
     *   2. Payload size check (so sánh số, rẻ)
     *   3. Rate limit check (lookup + write map, đắt nhất)
     * ================================================================ */
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) return XDP_DROP;

        __u16 sport = bpf_ntohs(udph->source); /* Cổng nguồn (network → host byte order) */
        __u64 l4_len = data_end - l4_hdr;       /* Tổng kích thước tầng 4 */
        /* Payload = tổng - UDP header (8 byte) */
        __u16 payload_len = (l4_len > sizeof(struct udphdr)) ?
                            (l4_len - sizeof(struct udphdr)) : 0;

        /* 1. Kiểm tra cổng Amplification (rẻ nhất - chỉ lookup hash map) */
        if (is_amp_port(sport)) {
            track_stats(pkt_size, XDP_DROP, DROP_UDP_AMPLIFICATION, protocol, sport);
            return XDP_DROP;
        }

        /* 2. Kiểm tra kích thước payload (rẻ - so sánh số) */
        if (payload_len > get_config(CONFIG_UDP_MAX_SIZE, DEFAULT_UDP_MAX_SIZE)) {
            track_stats(pkt_size, XDP_DROP, DROP_UDP_PAYLOAD_SIZE, protocol, sport);
            return XDP_DROP;
        }

        /* 3. Rate Limiting (đắt nhất - lookup + write map) */
        if (check_rate_limit(&rate_limit_map, src_ip,
                             get_config(CONFIG_UDP_PPS_LIMIT, DEFAULT_UDP_PPS_LIMIT), now)) {
            track_stats(pkt_size, XDP_DROP, DROP_UDP_RATELIMIT, protocol, sport);
            return XDP_DROP;
        }

        /* Gói UDP hợp lệ → Thử redirect, nếu không thì PASS */
        track_stats(pkt_size, XDP_PASS, -1, protocol, sport);
        return xdp_auto_redirect(ctx, eth, iph);
    }

    /* ================================================================
     * XỬ LÝ TCP
     * 1. Phát hiện flag bất thường (port scan, OS fingerprinting)
     * 2. SYN flood protection (rate limit riêng cho SYN)
     * ================================================================ */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) return XDP_DROP;

        /* Đọc byte flag TCP (byte thứ 13 trong TCP header, tính từ 0) */
        __u8 flags = ((__u8 *)tcph)[13];

        /* Phát hiện flag TCP bất thường - dấu hiệu của scan hoặc tấn công:
         *   - flags == 0: NULL scan (không có flag nào)
         *   - SYN+FIN: Không bao giờ hợp lệ (bắt đầu + kết thúc cùng lúc)
         *   - SYN+RST: Không bao giờ hợp lệ (bắt đầu + reset cùng lúc)
         */
        // if (flags == 0 ||
        //    ((flags & (RAW_TCP_SYN | RAW_TCP_FIN)) == (RAW_TCP_SYN | RAW_TCP_FIN)) ||
        //    ((flags & (RAW_TCP_SYN | RAW_TCP_RST)) == (RAW_TCP_SYN | RAW_TCP_RST))) {
        //     track_stats(pkt_size, XDP_DROP, DROP_TCP_INVALID, protocol, 0);
        //     return XDP_DROP;
        // }

        /* SYN flood protection:
         * Chỉ rate limit gói SYN thuần (SYN=1, ACK=0).
         * Gói SYN-ACK (bước 2 của 3-way handshake) không bị limit.
         */
        if ((flags & RAW_TCP_SYN) && !(flags & RAW_TCP_ACK)) {
            if (check_rate_limit(&rate_limit_syn_map, src_ip,
                                 get_config(CONFIG_SYN_PPS_LIMIT, DEFAULT_SYN_PPS_LIMIT), now)) {
                track_stats(pkt_size, XDP_DROP, DROP_SYN_RATELIMIT, protocol, 0);
                return XDP_DROP;
            }
        }

        /* Gói TCP hợp lệ → Thử redirect, nếu không thì PASS */
        track_stats(pkt_size, XDP_PASS, -1, protocol, 0);
        return xdp_auto_redirect(ctx, eth, iph);
    }

    /* ================================================================
     * XỬ LÝ ICMP (ping, traceroute...)
     * Chỉ cần rate limit để chống ICMP flood / ping flood.
     * ICMP flood ít nguy hiểm hơn UDP/SYN flood nhưng vẫn cần kiểm soát.
     * ================================================================ */
    if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = l4_hdr;
        if ((void *)(icmph + 1) > data_end) return XDP_DROP;

        /* Rate limit ICMP - ngưỡng mặc định 100 gói/giây (thấp hơn UDP/SYN) */
        if (check_rate_limit(&rate_limit_icmp_map, src_ip,
                             get_config(CONFIG_ICMP_PPS_LIMIT, DEFAULT_ICMP_PPS_LIMIT), now)) {
            track_stats(pkt_size, XDP_DROP, DROP_ICMP_RATELIMIT, protocol, 0);
            return XDP_DROP;
        }

        /* ICMP hợp lệ → Thử redirect, nếu không thì PASS */
        track_stats(pkt_size, XDP_PASS, -1, protocol, 0);
        return xdp_auto_redirect(ctx, eth, iph);
    }

    /* ================================================================
     * CÁC GIAO THỨC KHÁC (SCTP, GRE, ESP...)
     * Không có rule đặc biệt → Thử redirect, nếu không thì PASS.
     * ================================================================ */
    track_stats(pkt_size, XDP_PASS, -1, protocol, 0);
    return xdp_auto_redirect(ctx, eth, iph);
}

/* Khai báo license GPL - BẮT BUỘC để BPF verifier cho phép load chương trình */
char _license[] SEC("license") = "GPL";