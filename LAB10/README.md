# BÁO CÁO THỰC HÀNH LAB 10: HIỆN THỰC MÃ HÓA ĐỐI XỨNG CỔ ĐIỂN VÀ THÁM MÃ VỚI JAVA SWING

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Xây dựng ứng dụng mã hóa đối xứng cổ điển và mô phỏng thám mã bằng Java Swing (Maven) kết hợp lưu trữ lịch sử trên Microsoft SQL Server

---

## 1. Nội Dung Thực Hiện
1. **Xây dựng tiện ích đọc/ghi tệp (`FileTextIO.java`):** Hỗ trợ nạp bản rõ và xuất bản mã ra tệp văn bản chuẩn UTF-8 cho toàn bộ các biểu mẫu.
2. **Hiện thực 6 thuật toán mật mã đối xứng cổ điển kèm giao diện đồ họa Java Swing:**
   * Thuật toán mã hóa dịch chuyển **Caesar Cipher** (`CaesarCipher.java`, `frm_Caesar.java`).
   * Thuật toán mã hóa đa bảng **Vigenère Cipher** (`VigenereCipher.java`, `frm_Vigenere.java`).
   * Thuật toán hoán vị hàng rào **Rail Fence Cipher** (`RailFenceCipher.java`, `frm_RailFence.java`).
   * Thuật toán mã hóa cặp ký tự ma trận 5x5 **Playfair Cipher** (`PlayfairCipher.java`, `frm_Playfair.java`).
   * Thuật toán hoán vị cột **Columnar Transposition Cipher** (`TranspositionCipher.java`, `frm_Transposition.java`).
   * Thuật toán khóa tự động **Autokey Cipher** (`AutokeyCipher.java`, `frm_Autokey.java`).
3. **Tích hợp cơ sở dữ liệu Microsoft SQL Server (`DbConfig.java`, `CipherTongHop.java`):** Lưu trữ lịch sử các phiên mã hóa/giải mã, tra cứu trên bảng `JTable` và thực hiện các kịch bản thám mã (vét cạn khóa, phân tích tần suất, Known-Plaintext Attack).

---

## 2. Danh Mục Tệp Tài Liệu và Mã Nguồn Nộp Bài
1. **Báo cáo thực hành chi tiết:** `lab10_cnpm2_1150080145_BuiThiMyLinh.docx` *(Bao gồm đầy đủ ảnh chụp giao diện thực thi từng thuật toán, cấu hình kết nối SQL Server, truy vấn SSMS và kiểm thử thám mã)*.
2. **Thư mục mã nguồn dự án Maven:** `BaoMat/` *(Bao gồm `pom.xml`, mã nguồn `src/main/java` cùng các biểu mẫu `.form` và tệp dữ liệu kiểm thử)*.
3. **Tài liệu tóm tắt:** `README.md`.
