# BÁO CÁO THỰC HÀNH LAB 5: CẤU HÌNH TƯỜNG LỬA BẢO VỆ MẠNG VỚI PFSENSE

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Thiết lập và quản trị tường lửa lọc gói có trạng thái (Stateful Firewall) pfSense trên mô hình đa phân vùng WAN - LAN - DMZ

---

## 1. Môi Trường Thực Hành
* **Nền tảng ảo hóa:** Oracle VM VirtualBox / VMware Workstation Pro (Môi trường mạng kiểm thử độc lập, cách ly an toàn).
* **Tường lửa biên:** Máy ảo pfSense Community Edition phiên bản 2.7.2-RELEASE (64-bit amd64), cấp phát 2 GB bộ nhớ RAM.
* **Vùng mạng ngoài (WAN):** Card mạng cầu nối (Bridged Adapter) nhận địa chỉ từ cổng vật lý, hoặc dải mạng ảo riêng biệt `192.168.250.0/24`.
* **Vùng mạng nội bộ (LAN):** Card mạng Host-Only kết nối máy thật và máy ảo, dải mạng `10.0.0.0/8` (Cổng ngõ mặc định pfSense: `10.0.0.1`).
* **Vùng phi quân sự (DMZ):** Card mạng mạng nội bộ ảo (Internal Network: `dmz-net`), dải mạng `172.16.0.0/16` (Cổng ngõ mặc định pfSense: `172.16.0.1`).
* **Máy chủ quản lý miền nội bộ (Domain Controller):** Windows Server 2019/2022 (`10.0.0.2/8`, Cổng ngõ: `10.0.0.1`, DNS: `10.0.0.2`).
* **Máy trạm kiểm thử nội bộ (LAN-Test):** Ubuntu Server 22.04/24.04 LTS hoặc Windows Client (`10.0.0.3/8`, Cổng ngõ: `10.0.0.1`).
* **Máy chủ dịch vụ Web vùng DMZ (DMZ-Web):** Windows Server 2019/2022 cài dịch vụ IIS (`172.16.0.2/16`, Cổng ngõ: `172.16.0.1`).
* **Máy trạm điều phối và kiểm thử vật lý (Host):** Windows 10/11 (`10.0.0.100/8` trên card mạng Host-Only).

---

## 2. Danh Mục Tệp Tài Liệu và Nộp Bài
1. **Kế hoạch và cẩm nang thực hành toàn diện:** `Ke_Hoach_Va_Huong_Dan_Lab5.md` *(Cung cấp toàn bộ lý thuyết ngăn xếp mạng, quy chuẩn an toàn, lệnh thực thi từng bước, bảng ca kiểm thử và đáp án phân tích chuyên sâu)*.
2. **Gói tài nguyên và bộ cài đặt chính thức:** Thư mục `LAB5-pfSense/` *(Bao gồm tài liệu mẫu Word, liên kết tải từ máy chủ Netgate, kịch bản kiểm tra mã băm toàn vẹn)*.
3. **Mã băm kiểm tra tính toàn vẹn bộ cài:** `LAB5-pfSense/SHA256SUMS.txt` và kịch bản `LAB5-pfSense/VERIFY_SHA256.ps1`.
4. **Thư mục minh chứng kết quả:** `Evidence/` *(Lưu trữ các tệp nhật ký tường lửa, bảng trạng thái kết nối và ảnh chụp màn hình nghiệm thu các tình huống)*.
