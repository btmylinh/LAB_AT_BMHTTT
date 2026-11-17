# BÁO CÁO THỰC HÀNH LAB 8: LOCAL DNS ATTACK - DNS SPOOFING VÀ CACHE POISONING TRONG MẠNG ẢO CÔ LẬP

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Triển khai và phân tích kỹ thuật tấn công DNS cục bộ (Local DNS Spoofing & Cache Poisoning) trên hạ tầng mạng ảo cô lập với pfSense và BIND9

---

## 1. Môi Trường Thực Hành và Kiến Trúc Mô Hình
* **Tường lửa pfSense CE:** Quản lý phân vùng mạng cô lập `DNSLAB` (`10.9.0.1/24`) và vùng `DMZ` (`172.16.6.1/24`), ngăn chặn rò rỉ gói tin thử nghiệm ra môi trường bên ngoài.
* **Máy chủ phân giải DNS (DNS-SERVER - `10.9.0.10`):** Vận hành dịch vụ BIND9 đóng vai trò Recursive/Caching Resolver cho vùng mạng nội bộ `DNSLAB`.
* **Máy trạm nạn nhân (Victim):** Máy trạm thuộc dải `10.9.0.0/24` cấu hình trỏ DNS về `10.9.0.10`.
* **Máy tấn công (Kali Linux - `10.9.0.200`):** Đặt cùng phân đoạn mạng `DNSLAB` với chế độ card mạng ảo Promiscuous Mode = Allow VMs để thực hiện lắng nghe và tiêm gói tin giả mạo.
* **Máy chủ dịch vụ mục tiêu (DMZ Web - `172.16.6.10`):** Phục vụ trang web hợp lệ cho tên miền kiểm thử `www.external.lab9.test`.

---

## 2. Nội Dung Thực Hiện và Kiểm Chứng
1. **Thiết lập Baseline và kiểm tra cấu hình BIND9:** Cấu hình giao diện `DNSLAB` trên pfSense, kiểm tra cú pháp bằng `named-checkconf` và `named-checkzone`, xác nhận phân giải chuẩn `www.external.lab9.test -> 172.16.6.10`.
2. **Task 1 — Tấn công sửa đổi tệp `/etc/hosts` cục bộ:** Kiểm chứng sự khác biệt giữa bộ phân giải hệ điều hành (trình duyệt/`curl` bị chuyển hướng về `10.9.0.200`) và truy vấn trực tiếp qua `dig @DNS-SERVER` (vẫn trả về `172.16.6.10`).
3. **Task 2 — Giả mạo phản hồi DNS trực tiếp tới Victim (Local DNS Spoofing):** Bắt gói truy vấn trên mạng LAN và phát gói phản hồi giả mạo khớp Transaction ID/UDP Port khiến Victim nhận địa chỉ `10.9.0.200`.
4. **Task 3 — Đầu độc bộ nhớ đệm máy chủ phân giải (DNS Cache Poisoning):** Tiêm bản ghi giả mạo vào bộ nhớ đệm của BIND9 (`10.9.0.10`), kiểm chứng trạng thái cache trước và sau khi xóa (`rndc flush`) và khôi phục Promiscuous Mode về `Deny`.

---

## 3. Danh Mục Tệp Tài Liệu Nộp Bài
1. **Báo cáo chi tiết:** `lab8_cnpm2_1150080145_BuiThiMyLinh.docx` *(Bao gồm đầy đủ ảnh chụp minh chứng thực tế trên máy ảo và phần trả lời chi tiết 10 câu hỏi phân tích)*.
2. **Tài liệu tóm tắt:** `README.md`.
