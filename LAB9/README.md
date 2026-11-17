# BÁO CÁO THỰC HÀNH LAB 9: REMOTE DNS CACHE POISONING TRONG MÔI TRƯỜNG PFSENSE CÔ LẬP

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Мо phỏng tấn công Remote DNS Cache Poisoning (Kaminsky Attack) và triển khai các biện pháp gia cố an ninh (Hardening) cho máy chủ BIND9 Resolver

---

## 1. Môi Trường Thực Hành và Kiến Trúc Mô Hình
* **Tường lửa pfSense CE:** Phân tách ranh giới giữa 3 vùng mạng độc lập:
  * `DNSLAB` (`10.9.0.0/24`): Chứa máy chủ phân giải nội bộ `DNS-SERVER` (`10.9.0.10`) và máy trạm `VICTIM`.
  * `DMZ` (`172.16.6.0/24`): Chứa máy chủ web hợp lệ (`172.16.6.10`) và máy chủ tên miền thẩm quyền `AUTH-DNS` (`172.16.6.20`).
  * `ATTACKNET` (`10.10.0.0/24`): Chứa máy tấn công `Kali Linux` (`10.10.0.200`) hoàn toàn tách rời khỏi nhánh mạng `DNSLAB` với thiết lập `Promiscuous Mode = Deny`.

---

## 2. Nội Dung Thực Hiện và Kiểm Chứng
1. **Thiết lập kiến trúc cô lập và kiểm tra Baseline:** Định tuyến và áp đặt luật tường lửa trên pfSense cho phân vùng `ATTACKNET`; xác nhận `VICTIM` phân giải tên miền `www.example.lab10.test` về đúng `172.16.6.10`.
2. **Thực thi kịch bản Remote DNS Cache Poisoning:**
   * Truy vấn các tên miền con ngẫu nhiên thuộc vùng `example.lab10.test` để vượt qua cơ chế lưu đệm (cache effect) và kích hoạt cửa sổ truy vấn đệ quy từ `DNS-SERVER` tới `AUTH-DNS`.
   * Gửi lô gói tin phản hồi giả mạo (forged responses) chứa bản ghi ủy quyền `NS` và bản ghi `Glue A` trỏ về `10.10.0.200`.
   * Xác nhận trạng thái `[HIT]` và kiểm tra bộ nhớ đệm của resolver đã lưu bản ghi ủy quyền độc hại, làm `VICTIM` chuyển hướng sang trang web giả mạo.
3. **Gia cố an toàn hệ thống (Resolver Hardening):** Khôi phục cấu hình BIND9 sử dụng cổng nguồn ngẫu nhiên (loại bỏ cổng cố định `33333`), thu hồi quyền truy vấn đệ quy từ mạng ngoài (`Recursion ACL`) và bật xác thực chữ ký số `DNSSEC`.

---

## 3. Danh Mục Tệp Tài Liệu Nộp Bài
1. **Báo cáo chi tiết:** `lab9_cnpm2_1150080145_BuiThiMyLinh.docx` *(Bao gồm đầy đủ ảnh chụp minh chứng thực tế và phần trả lời chi tiết 12 câu hỏi phân tích)*.
2. **Tài liệu tóm tắt:** `README.md`.
