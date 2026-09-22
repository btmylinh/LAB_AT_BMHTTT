# BÁO CÁO THỰC HÀNH LAB 3: NHẬN DIỆN VÀ ỨNG PHÓ CÁC MỐI ĐE DỌA AN TOÀN THÔNG TIN

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin

---

## 1. Môi Trường Thực Hành
* **Nền tảng ảo hóa:** VMware Workstation Pro (chế độ mạng nội bộ Host-only cô lập an toàn).
* **Hệ điều hành máy trạm:** Windows 10 Enterprise LTSC 64-bit.
* **Công cụ phục vụ thực hành:** Microsoft Defender Antivirus, Windows Security Log, Sysmon, Autoruns, Process Explorer, Wireshark, Python 3.

---

## 2. Tóm Tắt Kết Quả Thực Hiện 7 Tình Huống

| Tình huống | Nội dung kỹ thuật triển khai | Kết quả đánh giá |
| :---: | :--- | :---: |
| **Tình huống 1** | Lấy mẫu đối chiếu ban đầu, lập bảng quản lý rủi ro và phân loại 5 nguồn đe dọa. | **ĐẠT** |
| **Tình huống 2** | Kiểm chứng cơ chế phát hiện và cách ly chuỗi kiểm thử mã độc EICAR của Microsoft Defender. | **ĐẠT** |
| **Tình huống 3** | Kích hoạt kiểm toán đăng nhập, phân tích sự kiện 4624/4625/4648 và xoay vòng mật khẩu. | **ĐẠT** |
| **Tình huống 4** | Giám sát tiến trình bằng Sysmon, kiểm tra mục tự khởi động với Autoruns và mở cổng nội bộ 8080. | **ĐẠT** |
| **Tình huống 5** | Bắt gói tin Wireshark: chứng minh điểm yếu của HTTP văn bản rõ và đối chứng với mã hóa HTTPS (TLS). | **ĐẠT** |
| **Tình huống 6** | Thử nghiệm đo tải nội bộ trên cổng 8080, phân tích dữ liệu tấn công phân tán (DDoS) và dội bom thư. | **ĐẠT** |
| **Tình huống 7** | Bóc tách 5 chỉ dấu thư lừa đảo (Phishing) và phân loại 6 trường hợp tấn công tâm lý xã hội. | **ĐẠT** |
| **Dọn dẹp hệ thống** | Xóa bỏ toàn bộ mục khởi động thử nghiệm, lập bảng băm SHA-256 bảo toàn chứng cứ số. | **ĐẠT** |

---

## 3. Danh Mục Tệp Nộp Bài
1. **Báo cáo Word chính thức:** `lab3_cnpm2_1150080145_BuiThiMyLinh.docx`.
2. **Cẩm nang hướng dẫn thực hành chi tiết chuẩn 1:1:** `Ke_Hoach_Va_Huong_Dan_Lab3.md`.
3. **Thư mục dữ liệu và gói tài nguyên thực hành:** `LAB3_Threats_Assets/`.
