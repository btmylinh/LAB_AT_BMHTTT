# BÁO CÁO THỰC HÀNH LAB 12: MÃ HÓA KHÓA CÔNG KHAI (RSA, ECC), HỆ MÃ LAI RSA + AES VÀ CHỮ KÝ SỐ ECDSA

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Đề tài thực hành:** Hiện thực các hệ mật mã khóa công khai (RSA, ECC), hệ mã hóa lai (RSA kết hợp AES), chữ ký số đường cong Elliptic (ECDSA) bằng Java Swing và quản lý lịch sử trên Microsoft SQL Server

---

## 1. Nội Dung Thực Hiện
1. **Mã hóa khóa công khai RSA (`RSACipher.java`, `frm_RSA.java`):** Sinh cặp khóa Public/Private Key, thực hiện mã hóa và giải mã dữ liệu văn bản, hỗ trợ đọc/ghi tệp khóa và bản mã.
2. **Mã hóa đường cong Elliptic ECC (`ECCCipher.java`, `frm_ECC.java`):** Triển khai sinh khóa và mã hóa/giải mã bất đối xứng trên đường cong Elliptic.
3. **Hệ mật mã lai RSA + AES (`RSA_AES_Cipher.java`, `frm_RSA_AES.java`):** Kết hợp tốc độ mã hóa khối dữ liệu lớn của AES với cơ chế bảo vệ khóa phiên (Session Key) bằng khóa công khai RSA.
4. **Chữ ký số ECDSA (`ECCSignature.java`, `frm_ECC_Signature.java`):** Ký số văn bản bằng khóa bí mật ECC và xác thực tính toàn vẹn, chống chối bỏ bằng khóa công khai.
5. **Tích hợp Microsoft SQL Server (`DbConfig.java`, `HistoryDao.java`, `frm_KetNoiSQL.java`, `frm_LichSu.java`):** Lưu trữ và truy vấn nhật ký thực thi các phiên mã hóa, giải mã và ký số thông qua tập lệnh `LAB3_MaHoaKhoaCongKhai.sql` và `03_KiemTra_LichSu.sql`.

---

## 2. Danh Mục Tệp Tài Liệu và Mã Nguồn Nộp Bài
1. **Báo cáo thực hành:** `lab12_cnpm2_1150080145_BuiThiMyLinh.docx`.
2. **Thư mục mã nguồn và cơ sở dữ liệu:** `LAB3_MaHoaKhoaCongKhai_1150080145/` *(Bao gồm tệp kịch bản SQL và dự án Maven Java Swing `LAB3_MaHoaKhoaCongKhai`)*.
3. **Tài liệu tóm tắt:** `README.md`.
