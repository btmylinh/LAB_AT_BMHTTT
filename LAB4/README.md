# BÁO CÁO THỰC HÀNH LAB 4: QUÉT MẠNG VÀ RÀ SOÁT LỖ HỔNG VỚI NMAP

## Thông Tin Sinh Viên
* **Họ và tên:** Bùi Thị Mỹ Linh
* **Mã số sinh viên:** 1150080145
* **Lớp:** CNPM2
* **Học phần:** An toàn và Bảo mật Hệ thống Thông tin
* **Video minh chứng thực hành:** [Xem trên YouTube](https://youtu.be/kcKABGwdmGI)

---

## 1. Môi Trường Thực Hành
* **Nền tảng ảo hóa:** VMware Workstation Pro (Mạng nội bộ Host-only VMnet1: `192.168.126.0/24` cô lập an toàn).
* **Máy quét (Attacker/Scanner):** Kali Linux (`192.168.126.130`).
* **Máy đích phục vụ rà quét (Target):** Metasploitable 2 Linux (`192.168.126.129`).
* **Máy trạm kiểm chứng phòng thủ:** Windows 10 Host (`192.168.126.1`).
* **Công cụ sử dụng chính:** Nmap 7.99, Nmap Scripting Engine (NSE), xsltproc, Windows Defender Firewall.

---

## 2. Danh Mục Tệp Nộp Bài và Tài Liệu
1. **Báo cáo Word chính thức:** `lab4_cnpm2_1150080145_BuiThiMyLinh.docx` *(hoàn thiện theo mẫu nộp bài)*.
2. **Kế hoạch và cẩm nang thực hành chi tiết:** `Ke_Hoach_Va_Huong_Dan_Lab4.md` *(đầy đủ lý thuyết, lệnh thực thi, đáp án 14 câu hỏi phân tích)*.
3. **Thư mục minh chứng kết quả quét:** `Evidence/` *(chứa tệp đầu ra .nmap, .xml, .gnmap, .html và bảng băm SHA-256)*.
4. **Thư mục hình ảnh minh chứng:** `images/` *(đầy đủ 8 ảnh chụp màn hình H1 đến H8 phục vụ dán báo cáo)*.
5. **Video ghi lại toàn bộ quá trình thực hành:** https://youtu.be/kcKABGwdmGI
