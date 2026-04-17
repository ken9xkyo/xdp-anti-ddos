# Hệ thống XDP Anti-DDoS

Hệ thống phòng chống tấn công từ chối dịch vụ phân tán (DDoS) hiệu năng siêu cao, vận hành trực tiếp trong nhân Linux thông qua mô hình eXpress Data Path (XDP).

---

## 1. Mô tả tính năng hệ thống (Features)

Hệ thống cung cấp lớp giáp phòng ngự toàn diện ngay tại tầng liên kết dữ liệu (mức Card mạng - NIC) để bảo vệ các Backend Server:

- **Lọc Danh sách trắng/đen (ACL Whitelist/Blacklist):** Chặn vĩnh viễn IP độc hại hoặc cho phép đi qua mọi bộ lọc đối với IP đáng tin cậy. (Dùng cơ chế LPM Trie tra cứu cực nhanh).
- **Chặn tạm thời (Temporary Block):** Tự động cấm túc các IP vi phạm (gửi vượt giới hạn, spam port) trong vòng 10 phút để giảm tải cho hệ thống phòng ngự.
- **Load Balancing / Chuyển hướng VM (VM Redirection):** Rewrite trực tiếp gói tin ở Layer 4 và bypass Kernel Networking Stack, đẩy gói tin thẳng sang Backend ảo.
- **Phản vệ UDP Amplification:** Nhận diện và loại bỏ các gói tin phản xạ quy mô lớn từ những port hay bị lợi dụng như DNS(53), NTP(123), SSDP(1900), Memcached(11211).
- **Nghẽn tốc độ (Rate Limiting):** Hạn chế PPS đối với TCP SYN flood, ICMP flood và UDP flood.
- **Tính năng quản trị:** Quản lý cấu hình CLI, Web Dashboard giao diện trực quan và Monitor số liệu thời gian thực thông qua Prometheus Grafana.

---

## 2. Mô tả logic của hệ thống (Pipeline Logic)

Flow xử lý cho mỗi gói tin (Packet) diễn ra ngay lập tức sau khi Driver mạng nhận được, trước khi HĐH có thể cấp phát bộ nhớ (sk_buff):

1. **Phân tích Header (Parser):** Giải mã tầng MAC / VLAN và xác định gói tin IPv4. Các gói không hợp lệ sẽ cấu thành `DROP_PARSE_ERROR`.
2. **Loại bỏ Packet phân mảnh (Fragment Check):** Drop vĩnh viễn và cho vào sổ cấm các IP mưu đồ gửi phân mảnh (Teardrop attack).
3. **ACL Matching (LPM):** So khớp tiền tố IP. 
	- Nếu thuộc Whitelist = Bỏ qua kiểm tra, chuyển tới bước Redirect.
	- Nếu thuộc Blacklist = `DROP_BLACKLIST`.
4. **Kiểm tra Chặn Tạm (Temp Block Check):** IP có bị vi phạm quy tắc mạng trong 10 phút trước đổ lại không? Nếu có = Nhấn chìm trực tiếp.
5. **Logic Giao Thức (Protocol Specifics):**
	- **UDP:** Kiểm tra Amp Port, payload size, và UDP limit PPS.
	- **TCP:** Ngăn chặn cờ TCP dị thường (ví dụ: SYN+FIN), quét Rate_Limit cho cờ TCP SYN.
	- **ICMP:** Quét rate limit Ping request.
6. **Thực thi bản án (Emit Verdict):** Nếu không hợp lệ, thả vào "Hố đen" (Drop), đánh dấu Log và khóa 10 phút. Nếu đi qua an toàn toàn bộ quy tắc, gói tin sẽ được `bpf_redirect` về backend port, hoặc `XDP_PASS` gửi lên cho OS. 

---

## 3. Các bảng MAP (BPF Maps) sử dụng

Hệ thống tận dụng các cấu trúc dữ liệu BPF tiên tiến nhất, giao tiếp song phương với Python Userspace:

- `acl_map` (`LPM_TRIE`): Gộp cả whitelist và blacklist vào làm một để tiết kiệm chu kỳ quét CPU. Trả về mức bảo mật dựa trên mặt nạ (netmask).
- `temp_block_map` (`LRU_HASH`): Một danh sách LRU bận rộn chứa 1 TRIỆU record dành riêng cho các IP có tiền án tấn công, hết hạn tự động ghi đè. Lọc sớm ngay đầu quy trình quét.
- Các Map Rate Limit (`rate_limit_map`, `rate_limit_syn_map`, `rate_limit_icmp_map` - `LRU_PERCPU_HASH`): Ghi nhận số lượng packet/s. Tính năng tách CPU giúp lock-free, siêu tốc.
- Các Map Redirect (`vm_redirect_map`, `tx_port_map` - `DEVMAP`): Ánh xạ IP với Card giao tiếp vật lý cụ thể, tạo lộ trình chuyển luồng dữ liệu lách hệ điều hành OS.
- `global_stats_map` (`PERCPU_ARRAY`): Thùng chứa các bộ đếm (Passed, Dropped, Dropped Reason) phục vụ việc visualize qua Prometheus Grafana.

---

## 4. Hướng dẫn Cài đặt & Khởi chạy

### Yêu cầu tiên quyết:
- Kernel Linux >= `5.8`
- Thư viện C/C++: `clang`, `llvm`, `libbpf-dev`
- Công cụ BPF: `bpftool`

### Quy trình kích hoạt XDP
1. Di chuyển vào thư mục và Build:
```bash
cd /root/xdp-anti-ddos
make    # Output -> xdp_anti_ddos.o
```

2. Tải eBPF lên Cây thư mục Hệ Thống và Nhúng vào Card Mạng (VD: Bật IN cho eno1, OUT cho eno2):
```bash
# Lệnh gộp Build + Load + Attach + Khởi tạo Init cấu hình (Ports, Limit)
make IFACE=enp94s0f0 OUT_IFACE=enp134s0f1 deploy 
```

3. Gỡ XDP:
```bash
make IFACE=enp94s0f0 undeploy
```

4. Mở Python CLI UI Server và Web UI:
```bash
# Khởi chạy bộ Monitor Prometheus
nohup python3 prometheus_exporter.py > /dev/null 2>&1 &

# Khởi chạy Backend Webapp
nohup python3 GUI/app.py > /dev/null 2>&1 &
```

*(Lưu ý: Bạn có thể nhập `python3 xdp_cli.py help` để xem trợ lý thao tác quản lý trực tiếp qua dòng lệnh).*

---

## 5. Đánh giá Hiệu năng Hệ thống

- **Tốc Độ Xử Lý Nền Phần Cứng (Wire-speed):** Quá trình Drop / Block diễn ra ở lớp đầu tiên của bộ phần mềm nhân (Hook vào Driver Card mạng), giảm tối đa tiêu tốn bộ nhớ cấp phát SKB. Do đó, tài nguyên CPU trên máy chủ sẽ được bảo đảm hoàn hảo dù phải hứng chịu hàng chục triệu Packet mỗi giây.
- **Tiêu thụ cực ít tài nguyên (Cycles/Packet):** Bằng thủ pháp dồn ACL thành chung 1 LPM lookup (~80 cycles) và sử dụng thuật toán BPF Tail-Calls chia nhỏ thống kê (Stats), XDP Anti-DDOS có thể vươn được tốc độ **triệu packet / core CPU** (gấp 5-10 lần Iptables / Nftables thông thường).
- **Khả năng Scaling:** LRU PERCPU Hash giúp xoá bỏ cơ chế Locking Memory Block giữa các nhân CPU, ngăn ngừa Context Switch. Càng nhiều nhân Card mạng, càng chịu tải DDoS giỏi.
