# BÀI THỰC HÀNH LAB 1: BẮT VÀ PHÂN TÍCH GÓI TIN TELNET - SSH BẰNG WIRESHARK
---

## 1. Mô Hình Ba Máy Thí Nghiệm Thực Tế

1. **Máy chủ dịch vụ (Server):** Máy ảo Kali Linux trên VMware, cài đặt dịch vụ máy chủ Telnet thật (`inetutils-telnetd` cổng TCP 23) và máy chủ OpenSSH (`openssh-server` cổng TCP 22), tạo tài khoản sinh viên thử nghiệm `uitlab`.
2. **Máy khách thao tác (Client):** Máy ảo Windows 10 Lab trên VMware, sử dụng phần mềm PuTTY kết nối từ xa đến máy chủ Kali Linux qua hai giao thức Telnet và SSH.
3. **Máy giám sát / Thu thập gói tin (Attacker / Monitor):** Máy thật Windows 10 cài đặt phần mềm Wireshark 4.6.8, lắng nghe trên card mạng ảo đại diện `VMware Network Adapter VMnet8` để thu thập trọn vẹn 100% các khung tin trao đổi giữa hai máy ảo.

---

## 2. Nội Dung Đã Thực Hiện

1. **Thiết lập mô hình mạng và kiểm tra kết nối:**
   - Cấu hình cả hai máy ảo kết nối qua mạng nội bộ ảo NAT (VMnet8).
   - Kiểm tra lệnh `ping` thông suốt hai chiều giữa Windows 10 và Kali Linux.

2. **Cấu hình dịch vụ trên máy chủ Kali Linux:**
   - Cài đặt và khởi chạy dịch vụ: `sudo apt update && sudo apt install -y inetutils-telnetd openssh-server`.
   - Tạo tài khoản sinh viên: `sudo useradd -m -s /bin/bash uitlab` và đặt mật khẩu MSSV: `echo "uitlab:14520123" | sudo chpasswd`.
   - Kích hoạt dịch vụ SSH: `sudo systemctl enable --now ssh`.
   - Kiểm tra hai cổng 22 và 23 đang lắng nghe: `ss -ltn | grep -E ':22|:23'`.

3. **Thực nghiệm phân tích giao thức Telnet:**
   - Dùng Wireshark trên máy thật lọc `tcp.port == 23` để bắt gói tin.
   - Máy ảo Windows 10 mở PuTTY kết nối Telnet vào Kali Linux, gõ các lệnh `pwd`, `ls -la`, `mkdir`, `whoami`.
   - Trích xuất luồng TCP (Follow TCP Stream) chứng minh Telnet gửi toàn bộ tên đăng nhập, mật khẩu MSSV và nội dung lệnh dưới dạng chữ rõ (Plaintext).
   - Thực nghiệm nâng cao với mật khẩu phức tạp trên 10 ký tự (`echo "uitlab:P@ssw0rd#2026!Sec" | sudo chpasswd`), chứng minh mật khẩu phức tạp vẫn lộ nguyên văn từng ký tự.

4. **Thực nghiệm phân tích giao thức SSH:**
   - Ghi nhận cảnh báo xác thực dấu vân tay khóa máy chủ (Host-Key Fingerprint) khi kết nối SSH lần đầu trên PuTTY.
   - Bắt gói tin với bộ lọc `tcp.port == 22` trên Wireshark, chứng minh toàn bộ dữ liệu tải trọng đều được mã hóa nhị phân an toàn (`Encrypted packet data`).

5. **Thực nghiệm mở rộng xác thực bằng cặp khóa công khai (Public-Key Authentication):**
   - Sinh cặp khóa chuẩn Ed25519 trên Windows 10 bằng `ssh-keygen`.
   - Đưa khóa công khai vào tệp `~/.ssh/authorized_keys` trên máy chủ Kali Linux và kết nối thành công không cần nhập mật khẩu.

6. **Hoàn thành lời giải chuyên sâu 11 câu hỏi lý thuyết - thực nghiệm:**
   - Đã biên soạn đầy đủ trong tệp báo cáo Microsoft Word chính thức.

---

## 3. Danh Mục Tệp Nghiệm Thu

- **Tệp báo cáo Microsoft Word chính thức:** [Lab1_BaoCao_ThucHanh_ATBMHTTT.docx](Lab1_BaoCao_ThucHanh_ATBMHTTT.docx).
- **Tệp cẩm nang hướng dẫn chi tiết:** [Ke_Hoach_Va_Huong_Dan_Lab1.md](Ke_Hoach_Va_Huong_Dan_Lab1.md).
