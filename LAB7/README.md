# BÁO CÁO THỰC HÀNH LAB 7: XÂY DỰNG CHÍNH SÁCH WEB PROTECTION TRÊN MÔ HÌNH PFSENSE + WEB PROXY

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Xây dựng chính sách Web Protection trên mô hình pfSense + Web Proxy (Squid, E2Guardian, ClamAV)

---

## 1. Môi Trường Thực Hành và Kiến Trúc Mô Hình
* **Mô hình kiến trúc:** Tách bạch giữa Cổng tường lửa (Firewall Gateway) và Máy chủ lọc nội dung Web (Web Proxy).
  * **pfSense CE (Gateway/Firewall):** Chịu trách nhiệm định tuyến, quản lý băng thông và áp đặt quy tắc tường lửa (Layer 3/Layer 4).
  * **Ubuntu 24.04 LTS (WEB-PROXY - `10.6.0.30`):** Đảm nhiệm lọc nội dung tầng ứng dụng (Layer 7) kết hợp bộ ba:
    * **Squid:** Caching proxy server trung gian.
    * **E2Guardian:** Bộ lọc nội dung chuyên sâu (content filtering, URL blacklist/whitelist, content scanning, temporary bypass).
    * **ClamAV:** Trình quét mã độc thời gian thực đối với các tệp dữ liệu tải xuống (phát hiện và ngăn chặn mã độc kiểm thử EICAR).
  * **Windows Server (DC01 - `10.6.0.10`):** Máy chủ Active Directory và hệ thống phân giải tên miền DNS nội bộ.
  * **Máy trạm kiểm thử Client-A / Client-B:** Nhận cấu hình proxy, bị kiểm soát toàn bộ lưu lượng web ra Internet và mạng ngoài.

---

## 2. Các Chính Sách và Kịch Bản Triển Khai
1. **Ép buộc chuyển tiếp qua Proxy:** Cấu hình Alias và ruleset trên pfSense khóa triệt để kết nối trực tiếp (Block direct TCP 80, 443 và QUIC UDP 443) từ các máy trạm; bắt buộc mọi luồng duyệt web phải đi qua máy chủ Web Proxy `10.6.0.30:8080`.
2. **Kiểm duyệt danh mục trang web:**
   * **Hard Block:** Chặn hoàn toàn và không cho phép bỏ qua đối với các danh mục cấm (Geo-Sim, Job Search).
   * **Warning + Temporary Bypass:** Hiển thị cảnh báo rủi ro và cấp quyền tạm thời truy cập có giới hạn thời gian đối với các website trong danh sách cảnh báo.
   * **Education Whitelist:** Cho phép thông suốt đối với các trang học tập và nghiên cứu.
3. **Kiểm soát theo khung thời gian (Schedule 60 phút):** Giới hạn lưu lượng giải trí hoặc danh mục đặc thù theo lịch trình định sẵn trên hệ thống.
4. **Bảo vệ phòng chống mã độc (Anti-Virus scanning):** Tích hợp ClamAV quét luồng truyền tải tệp, chặn tệp tin mã độc kiểm chuẩn EICAR và ghi nhận log cảnh báo tức thời.
5. **Kiểm soát phân tích SSL/HTTPS Inspection (tùy chọn mở rộng):** Cơ chế giải mã và tái mã hóa qua chứng chỉ trung gian CA phục vụ quét nội dung sâu.

---

## 3. Danh Mục Tệp Tài Liệu Nộp Bài
1. **Báo cáo chi tiết:** `lab7_cnpm2_1150080145_BuiThiMyLinh.docx` *(Bao gồm ảnh chụp minh chứng toàn bộ các bước cấu hình, kiểm thử thực tế và trả lời đầy đủ 10 câu hỏi phân tích chuyên sâu)*.
2. **Tài liệu hướng dẫn & Báo cáo tóm tắt:** `README.md`.
