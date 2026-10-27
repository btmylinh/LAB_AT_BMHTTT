# BÁO CÁO THỰC HÀNH LAB 6: TÍCH HỢP TƯỜNG LỬA PFSENSE VỚI ACTIVE DIRECTORY VÀ CHÍNH SÁCH TRUY CẬP

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Tích hợp pfSense với Active Directory (LDAP TCP/389), triển khai Cổng xác thực Captive Portal, cấu hình định danh Alias, kiểm soát khung thời gian Schedule và thực thi 7 kịch bản chính sách truy cập mạng

---

## 1. Môi Trường Thực Hành
* **Nền tảng ảo hóa:** Oracle VM VirtualBox (Hạ tầng mạng 4 phân vùng độc lập, cách ly an toàn).
* **Tường lửa pfSense:** Máy ảo pfSense Community Edition phiên bản 2.7.x (4 card mạng: WAN, MGMT, LAN, DMZ).
* **Phân vùng mạng ngoài (WAN):** NAT Network `LAB6-WAN` (`192.168.250.0/24`), nhận địa chỉ IP động qua DHCP.
* **Phân vùng quản trị (MGMT):** Card mạng Host-Only `192.168.56.0/24` (pfSense: `192.168.56.254/24`, Máy thật: `192.168.56.1/24`).
* **Phân vùng mạng nội bộ (LAN):** Mạng nội bộ ảo `lab6-lan` (`10.6.0.0/24`), pfSense giữ vai trò Cổng ngõ mặc định `10.6.0.1/24`.
* **Phân vùng phi quân sự (DMZ):** Mạng nội bộ ảo `lab6-dmz` (`172.16.6.0/24`), pfSense giữ vai trò Cổng ngõ mặc định `172.16.6.1/24`.
* **Máy chủ điều khiển miền (DC01):** Windows Server (`10.6.0.10/24`), tên miền `lab6.test`, tài khoản người dùng `sv_a`, `sv_b` và tài khoản dịch vụ `svc_pfsense_ldap`.
* **Máy trạm kiểm thử Client-A:** Windows 10/11 (`10.6.0.21/24`, Cổng ngõ: `10.6.0.1`, DNS: `10.6.0.10`).
* **Máy trạm kiểm thử Client-B:** Windows 10/11 (`10.6.0.22/24`, Cổng ngõ: `10.6.0.1`, DNS: `10.6.0.10`).
* **Máy chủ dịch vụ Web DMZ (DMZ-WEB):** Ubuntu Server cài đặt Nginx mang 4 địa chỉ IPv4 phụ:
  * `172.16.6.10`: Cổng thông tin doanh nghiệp (`GENERAL_SITE`)
  * `172.16.6.20`: Trang web tuyển dụng việc làm (`JOB_SITE`)
  * `172.16.6.30`: Mạng xã hội giải trí (`SOCIAL_SITE`)
  * `172.16.6.40`: Nội dung nhạy cảm bị cấm (`RESTRICTED_SITE`)

---

## 2. Danh Mục Tệp Tài Liệu và Nộp Bài
1. **Cẩm nang và kế hoạch triển khai chi tiết:** `Ke_Hoach_Va_Huong_Dan_Lab6.md` *(Bao gồm toàn bộ lý thuyết nền tảng, sơ đồ 4 phân vùng mạng, cấu hình chi tiết 7 kịch bản chính sách, ma trận kiểm chứng, xử lý sự cố và đáp án 12 câu hỏi phân tích)*.
2. **Đề bài thực hành gốc:** `LAB6_pfSense_AD_Access_Policies_2026.docx` và `LAB6_pfSense_AD_Access_Policies_2026.pdf`.
3. **Thư mục minh chứng kết quả:** `Evidence/` *(Lưu trữ nhật ký tường lửa, bảng trạng thái kết nối và tệp cấu hình xuất từ hệ thống `config-pfSense-LAB6.xml`)*.
4. **Thư mục ảnh chụp màn hình:** `images/` *(Chứa toàn bộ 13 ảnh chụp minh chứng H1 đến H13 phục vụ báo cáo)*.
5. **Video thực hành:** [Xem trên YouTube](https://www.youtube.com/watch?v=6-94BqEIed8)

