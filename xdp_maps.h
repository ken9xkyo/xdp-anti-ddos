#ifndef __XDP_MAPS_H
#define __XDP_MAPS_H

#include "xdp_common.h"
#include "xdp_structs.h"

/* ============================================================================
 * BPF MAPS - Các "bảng dữ liệu" chia sẻ giữa kernel và userspace
 *
 * BPF Map là cơ chế chính để:
 *   1. Kernel ↔ Userspace trao đổi dữ liệu
 *   2. Lưu trạng thái giữa các lần xử lý gói tin
 *
 * Các loại map dùng trong chương trình:
 *   - LPM_TRIE: Prefix Tree cho IP lookup (whitelist/blacklist, hỗ trợ CIDR)
 *   - HASH: Bảng băm key-value, tra cứu O(1)
 *   - LRU_PERCPU_HASH: Hash + tự xoá entry cũ nhất + mỗi CPU riêng
 *   - PERCPU_ARRAY: Mảng với bản sao per-CPU (không lock, hiệu năng cao)
 * ============================================================================ */

/*
 * ACL Map (Access Control List) - IPv4, hợp nhất whitelist + blacklist.
 *
 * TỐI ƯU HÓA QUAN TRỌNG: Gộp 2 map (whitelist + blacklist) thành 1.
 * Tiết kiệm ~80 cycles/packet vì chỉ cần 1 LPM lookup thay vì 2.
 *
 * Value = ACL_ALLOW (1) hoặc ACL_DENY (2).
 * Longest Prefix Match: Rule cụ thể nhất luôn thắng.
 * VD: 10.0.0.0/8 → ALLOW, 10.1.0.0/16 → DENY
 *     → 10.1.2.3 match DENY (/16 cụ thể hơn /8)
 *
 * BPF_F_NO_PREALLOC là BẮT BUỘC cho LPM Trie map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ACL_ENTRIES);
    __type(key, struct lpm_key_ipv4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_map SEC(".maps");

/*
 * ACL Map IPv6 - hợp nhất whitelist_v6 + blacklist_v6.
 * Tương tự acl_map nhưng cho địa chỉ IPv6 (128-bit prefix).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ACL_ENTRIES);
    __type(key, struct lpm_key_ipv6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_map_v6 SEC(".maps");

/*
 * Danh sách cổng Amplification cần chặn
 * Gói UDP từ các cổng này thường là tấn công khuếch đại.
 * Userspace có thể thêm/xoá cổng runtime qua xdp_cli.py.
 * - Key: __u16 = số cổng nguồn
 * - Value: __u8 = 1 (chỉ cần tồn tại)
 */
/*
 * TỐI ƯU: PERCPU_HASH loại bỏ lock contention giữa các CPU core.
 * Mỗi CPU có bản sao riêng → lookup nhanh hơn ~10 cycles.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
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
 * Bảng chặn tạm thời (Temporary Block)
 * Lưu trữ IPs bị chặn trong 10 phút sau khi vi phạm
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} temp_block_map SEC(".maps");

/*
 * Bảng redirect theo IP 
 * Khi gói tin đến có IP đích nằm trong bảng này, gói sẽ được
 * rewrite MAC và chuyển tiếp sang backend server tương ứng.
 * - Key: __u32 = IP đích
 * - Value: struct redirect_info = thông vị MAC + interface đích
 * - pinning: Map được ghim (pin) trong filesystem (/sys/fs/bpf/)
 *   để các tool userspace khác có thể truy cập.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct redirect_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vm_redirect_map SEC(".maps");

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

/* * DEVMAP: Map quản lý phần cứng mạng cho bpf_redirect_map.
 * Bắt buộc phải có để tận dụng cơ chế bulking đẩy gói tin siêu tốc.
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);   /* Key là ifindex cổng xuất */
    __type(value, __u32); /* Value cũng là ifindex cổng xuất */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port_map SEC(".maps");

/*
 * Stats scratch space - per-CPU buffer truyền data cho tail-called stats program.
 * Main program ghi stats context vào đây, rồi tail call sang xdp_stats_prog.
 * PERCPU_ARRAY: mỗi CPU có bản sao riêng → không cần lock.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_ctx);
} stats_scratch SEC(".maps");

/*
 * Jump table cho bpf_tail_call - chứa fd của sub-programs.
 * Userspace (loader) phải populate map này sau khi load program.
 * Entry PROG_STATS (0) → fd của xdp_stats_prog.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

#endif /* __XDP_MAPS_H */
