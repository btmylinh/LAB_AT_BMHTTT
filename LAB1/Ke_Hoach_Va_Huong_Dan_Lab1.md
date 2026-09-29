# Kế Hoạch Và Cẩm Nang Hướng Dẫn Thực Hiện Lab 1: Bắt Gói Tin Telnet - SSH

Tài liệu chi tiết từng bước triển khai kịch bản theo đúng thứ tự tài liệu hướng dẫn học phần, áp dụng trên mô hình ba máy chuẩn gồm Máy chủ Kali Linux, Máy khách Windows 10 và Máy giám sát máy thật Windows 10, kèm theo đầy đủ câu lệnh quản trị, quy trình bắt gói Wireshark và lời giải 11 câu hỏi chuyên môn.

---

## A. TỔNG QUAN VÀ MÔ HÌNH THỰC HIỆN

### 1. Mục Tiêu Thực Hành
* Giả lập mô hình truyền thông dòng lệnh Máy khách (Client) kết nối đến Máy chủ (Server) qua hai giao thức Telnet và SSH trong mạng nội bộ.
* Nắm vững kỹ năng sử dụng công cụ Wireshark để bắt và trích xuất luồng dữ liệu gói tin trên đường truyền mạng.
* Chứng minh thực nghiệm điểm yếu mất an toàn nghiêm trọng của Telnet: truyền thông tin dạng chữ rõ (Plaintext), mật khẩu dù dài và phức tạp vẫn bị lộ hoàn toàn trên đường truyền.
* Phân tích cơ chế bảo vệ toàn diện của SSH: mã hóa dữ liệu tải trọng (Payload Encryption), vai trò của dấu vân tay máy chủ (Host-Key Fingerprint) và trình diễn cơ chế xác thực bằng cặp khóa công khai (Public-Key Authentication).

### 2. Bố Trí Mô Hình Ba Máy Thí Nghiệm
Toàn bộ hệ thống kết nối chung vào card mạng nội bộ ảo NAT (công tắc mạng ảo VMnet8):
* **Máy 1 - Máy chủ dịch vụ (Máy ảo Kali Linux trên VMware):**
  * *Tệp cấu hình máy ảo:* `D:\University\Y4-5 AT&BM HTTT\Tools\Kali-Linux-VMware\kali-linux-2026.2-vmware-amd64.vmwarevm\kali-linux-2026.2-vmware-amd64.vmx`
  * *Tài khoản quản trị mặc định:* `kali` / mật khẩu: `kali`.
  * *Vai trò:* Cung cấp dịch vụ máy chủ Telnet thật (`inetutils-telnetd` cổng TCP 23) và OpenSSH Server (`openssh-server` cổng TCP 22).
* **Máy 2 - Máy khách thao tác (Máy ảo Windows 10 Lab trên VMware):**
  * *Tệp cấu hình máy ảo:* `D:\University\Y4-5 AT&BM HTTT\Tools\VM-Windows10-Lab\Windows10.vmx`
  * *Tài khoản đăng nhập:* `win10` / mật khẩu: `win10`.
  * *Vai trò:* Chạy phần mềm PuTTY kết nối điều khiển từ xa vào máy chủ Kali Linux.
* **Máy 3 - Máy giám sát / Bắt gói tin (Máy thật Windows 10 của sinh viên):**
  * *Phần mềm sử dụng:* Wireshark 4.6.8 tại `C:\Program Files\Wireshark\Wireshark.exe`.
  * *Vai trò:* Lắng nghe trên card mạng ảo đại diện `VMware Network Adapter VMnet8`, thu thập toàn bộ các gói tin trao đổi giữa hai máy ảo.

---

## B. QUY TRÌNH THỰC HÀNH CHI TIẾT THEO THỨ TỰ TÀI LIỆU HƯỚNG DẪN

---

### 1. Thiết Lập Môi Trường Và Tạo Tài Khoản

* **Bước 1.1: Khởi động 2 máy ảo và xác định địa chỉ mạng**
  * Trên VMware Workstation Pro: Bật máy ảo **Kali Linux** và máy ảo **Windows 10 Lab**. Đảm bảo card mạng của cả hai máy ảo đều chọn chế độ **NAT**.
  * Trên máy ảo Kali Linux: Mở Terminal, gõ lệnh lấy địa chỉ IP:
    ```bash
    ip -4 addr show eth0
    ```
    *(Ghi nhận địa chỉ IP của Kali, ví dụ: `192.168.101.128`).*
  * Trên máy ảo Windows 10: Mở Command Prompt (CMD), gõ lệnh:
    ```cmd
    ipconfig
    ```
    *(Ghi nhận địa chỉ IP của Windows 10, ví dụ: `192.168.101.129`).*

* **Bước 1.2: Kiểm tra kết nối mạng hai chiều**
  * Tại máy khách Windows 10, gõ lệnh kiểm tra kết nối tới máy chủ Kali Linux:
    ```cmd
    ping <Địa_Chỉ_IP_Kali_Linux>
    ```
  * Nhận đủ 4 gói tin phản hồi thành công (`Reply from...`) chứng minh đường truyền nội bộ giữa hai máy ảo đã thông suốt.

* **Bước 1.3: Cài đặt dịch vụ và tạo tài khoản sinh viên trên máy chủ Kali Linux**
  * Mở Terminal trên Kali Linux, chạy lệnh cài đặt dịch vụ Telnet và SSH:
    ```bash
    sudo apt update -y
    sudo apt install -y inetutils-telnetd openssh-server
    ```
    *(Nhập mật khẩu `kali` khi hệ thống yêu cầu).*
  * Tạo tài khoản sinh viên thử nghiệm:
    ```bash
    sudo useradd -m -s /bin/bash uitlab
    echo "uitlab:14520123" | sudo chpasswd
    ```
    *(Lưu ý: Thay `uitlab` bằng Tên của bạn viết liền không dấu, thay `14520123` bằng Mã số sinh viên của bạn).*

---

### 2. Bắt Gói Tin Khi Sử Dụng Giao Thức Telnet

* **Bước 2.1: Bật dịch vụ Telnet trên máy chủ Kali Linux**
  1. *Khởi động dịch vụ:* Dịch vụ `inetutils-telnetd` tự động kích hoạt sau khi cài đặt hoặc kiểm tra bằng lệnh:
     ```bash
     sudo systemctl restart inetutils-telnetd
     ```
  2. *Kiểm tra cổng lắng nghe:* Kiểm tra cổng 23 đang mở trên máy chủ:
     ```bash
     ss -ltn | grep :23
     ```
     Thấy xuất hiện dòng trạng thái `LISTEN` trên cổng `:23` nghĩa là máy chủ Telnet đã sẵn sàng.

* **Bước 2.2: Xác nhận tài khoản Telnet**
  * Trên hệ điều hành Linux hiện đại không cần nhóm TelnetClients như Windows cũ. Tài khoản sinh viên `uitlab` vừa tạo đã có quyền đăng nhập ngay lập tức.

* **Bước 2.3: Bật phần mềm Wireshark trên máy thật để đón bắt gói tin**
  1. Trên máy thật Windows 10 của bạn, mở phần mềm **Wireshark**.
  2. Nhấp đúp chuột vào card mạng ảo **VMware Network Adapter VMnet8** để bắt đầu bắt gói.
  3. Tại thanh lọc gói tin (Display Filter) ở trên cùng, nhập cú pháp:
     ```text
     tcp.port == 23
     ```
     và nhấn Enter.

* **Bước 2.4: Kết nối Telnet từ máy khách Windows 10 vào máy chủ**
  1. Trên máy ảo Windows 10, mở phần mềm **PuTTY**.
  2. Nhập địa chỉ IP của máy chủ Kali Linux vào ô **Host Name**.
  3. Tích chọn mục **Telnet** (cổng tự động chuyển thành **23**).
  4. Bấm nút **Open**.
  5. Cửa sổ dòng lệnh màu đen hiện ra: Nhập tên đăng nhập sinh viên (`uitlab`), sau đó nhập mật khẩu (`14520123`) và nhấn Enter.
  6. Khi đã đăng nhập thành công vào máy chủ, gõ một số câu lệnh tương tác cơ bản:
     ```bash
     pwd
     ls -la
     mkdir ThucHanhLab1
     cd ThucHanhLab1
     whoami
     ```

* **Bước 2.5: Dừng bắt gói tin trên máy thật và phân tích dữ liệu**
  1. Trên máy thật, bấm nút dừng bắt gói trên Wireshark (nút hình vuông màu đỏ).
  2. Lưu tệp bắt gói: Vào menu **File** > **Save As** > đặt tên `telnet_traffic_capture.pcapng`.
  3. Chọn một dòng gói tin Telnet trên danh sách, nhấp chuột phải, chọn **Follow** > **TCP Stream**.
  4. Quan sát kết quả: Toàn bộ tên đăng nhập, mật khẩu MSSV và các câu lệnh đã gõ hiển thị hoàn toàn dưới dạng văn bản thô đọc được từng chữ rõ ràng.
  5. Chụp ảnh màn hình cửa sổ này để dán vào báo cáo chính thức.

* **Bước 2.6: Thử nghiệm kiểm chứng với mật khẩu phức tạp**
  1. Trên máy chủ Kali Linux, chạy lệnh đổi mật khẩu tài khoản sinh viên thành chuỗi ký tự phức tạp trên 10 ký tự:
     ```bash
     echo "uitlab:P@ssw0rd#2026!Sec" | sudo chpasswd
     ```
  2. Lặp lại từ Bước 2.3 đến Bước 2.5: Bật Wireshark trên máy thật, từ máy Windows 10 kết nối Telnet bằng mật khẩu mới, sau đó dùng tính năng Follow TCP Stream.
  3. Quan sát kết quả: Mật khẩu phức tạp vẫn hiển thị nguyên văn từng ký tự rõ ràng trên Wireshark. Chụp ảnh lại làm bằng chứng chứng minh độ dài mật khẩu không có tác dụng bảo vệ Telnet.

---

### 3. Bắt Gói Tin Khi Sử Dụng Giao Thức SSH

* **Bước 3.1: Khởi động dịch vụ OpenSSH Server trên máy chủ Kali Linux**
  * Mở Terminal trên máy chủ Kali Linux, chạy lệnh kích hoạt dịch vụ:
    ```bash
    sudo systemctl enable --now ssh
    sudo systemctl status ssh
    ```

* **Bước 3.2: Kiểm tra dịch vụ SSH đang hoạt động**
  * Chạy lệnh kiểm tra cổng 22 đang lắng nghe:
    ```bash
    ss -ltn | grep :22
    ```
  * Xác nhận thấy cổng 22 đang ở trạng thái `LISTEN`.

* **Bước 3.3: Bật Wireshark trên máy thật để đón bắt gói tin SSH**
  * Trên Wireshark (máy thật), đổi bộ lọc hiển thị sang:
    ```text
    tcp.port == 22
    ```
  * Bấm nút bắt đầu phiên bắt gói tin mới (biểu tượng vây cá mập màu xanh).

* **Bước 3.4: Đổi mật khẩu về đơn giản và kết nối SSH từ máy khách Windows 10**
  1. Trên Kali Linux, đặt lại mật khẩu đơn giản:
     ```bash
     echo "uitlab:14520123" | sudo chpasswd
     ```
  2. Trên máy ảo Windows 10, mở **PuTTY**:
     * Nhập địa chỉ IP của Kali Linux.
     * Chọn kiểu kết nối **SSH**, cổng **22**.
     * Bấm nút **Open**.
  3. *Quan sát cảnh báo:* Hộp thoại **PuTTY Security Alert** xuất hiện thông báo xác nhận dấu vân tay máy chủ (**Host-Key Fingerprint**). Chụp ảnh lại màn hình cảnh báo này để trả lời câu hỏi số 8.
  4. Bấm nút **Accept** (hoặc **Yes**) để tiếp tục.
  5. Nhập tên tài khoản (`uitlab`) và mật khẩu (`14520123`).
  6. Sau khi đăng nhập thành công vào hệ thống, gõ lệnh kiểm tra:
     ```bash
     uname -a
     ls -la
     ```

* **Bước 3.5: Dừng bắt gói tin trên máy thật và phân tích dữ liệu SSH**
  1. Trên máy thật, bấm nút dừng bắt gói tin trên Wireshark.
  2. Lưu tệp gói tin với tên: `ssh_traffic_capture.pcapng`.
  3. Chọn một gói tin SSH trên danh sách, nhấp chuột phải chọn **Follow** > **TCP Stream**.
  4. Quan sát kết quả: Toàn bộ nội dung trao đổi đều hiển thị là các khối ký tự nhị phân ngẫu nhiên không thể đọc được, các gói tin đều mang nhãn `Encrypted packet data`. Hoàn toàn không thể tìm thấy tên đăng nhập, mật khẩu hay câu lệnh đã thực hiện.
  5. Chụp ảnh màn hình này để dán vào báo cáo đối chiếu với Telnet.

---

### Bảng Tổng Hợp Phân Vai Thao Tác Giữa Các Máy

| Thứ tự bước | Máy thực hiện | Ứng dụng / Công cụ | Thao tác và câu lệnh trọng tâm |
| :--- | :--- | :--- | :--- |
| **B.1.1** | Kali Linux & Win10 | Terminal / CMD | Lấy IP: `ip -4 addr show eth0` (Kali) và `ipconfig` (Win10) |
| **B.1.2** | Windows 10 | CMD | `ping <IP_Kali_Linux>` kiểm tra kết nối thông suốt |
| **B.1.3** | Kali Linux | Terminal | Cài `inetutils-telnetd`, `openssh-server`, tạo user `uitlab` |
| **B.2.1** | Kali Linux | Terminal | Kiểm tra cổng Telnet: `ss -ltn \| grep :23` |
| **B.2.3** | Máy thật Windows | Wireshark 4.6.8 | Chọn card mạng `VMnet8`, áp bộ lọc `tcp.port == 23` |
| **B.2.4** | Windows 10 | PuTTY | Kết nối Telnet cổng 23, đăng nhập và gõ lệnh `ls`, `mkdir` |
| **B.2.5** | Máy thật Windows | Wireshark | Dừng bắt, chọn **Follow > TCP Stream**, chụp ảnh lộ tên và mật khẩu |
| **B.2.6** | Kali Linux | Terminal | Đổi mật khẩu phức tạp, lặp lại các bước bắt gói |
| **B.3.1** | Kali Linux | Terminal | `sudo systemctl enable --now ssh`, kiểm tra cổng 22 |
| **B.3.3** | Máy thật Windows | Wireshark | Chọn card `VMnet8`, đổi bộ lọc sang `tcp.port == 22` |
| **B.3.4** | Windows 10 | PuTTY | Kết nối SSH cổng 22, chụp ảnh cảnh báo Host Key, đăng nhập |
| **B.3.5** | Máy thật Windows | Wireshark | Dừng bắt, chọn **Follow > TCP Stream**, chụp ảnh mã hóa tải trọng SSH |

---

## C. ĐÁP ÁN CHI TIẾT 11 CÂU HỎI HỌC PHẦN

### Câu 1: Telnet và SSH là gì và được ứng dụng trong trường hợp nào?
* **Telnet (Telecommunication Network):** Là giao thức mạng tầng ứng dụng hoạt động trên cổng mặc định TCP 23, phát triển từ năm 1969 nhằm cung cấp giao diện dòng lệnh từ xa. Toàn bộ thông tin truyền đi dưới dạng văn bản thô (Plaintext) không mã hóa.
  * *Ứng dụng:* Không còn dùng trong sản xuất thực tế. Chỉ dùng trong phòng thí nghiệm học tập hoặc kiểm tra nhanh cổng mạng (`telnet <host> <port>`).
* **SSH (Secure Shell):** Là giao thức mạng bảo mật tầng ứng dụng hoạt động trên cổng mặc định TCP 22, thiết kế để thay thế Telnet và các giao thức cũ không an toàn. SSH áp dụng mật mã hóa khóa công khai, mã hóa đối xứng và mã xác thực thông điệp.
  * *Ứng dụng:* Tiêu chuẩn hàng đầu trong quản trị máy chủ từ xa an toàn, truyền tệp an toàn (SFTP/SCP), tạo đường hầm mạng mã hóa (SSH Tunneling/Port Forwarding) và quy trình CI/CD.

### Câu 2: So sánh Telnet và SSH
* *Cổng mặc định:* Telnet dùng TCP 23; SSH dùng TCP 22.
* *Mã hóa:* Telnet truyền văn bản thô (Plaintext); SSH mã hóa toàn bộ dữ liệu tải trọng (Payload Encryption).
* *Tính toàn vẹn:* Telnet không hỗ trợ bảo vệ; SSH dùng mã xác thực thông điệp (HMAC / AEAD).
* *Xác thực:* Telnet chỉ có mật khẩu thô một chiều; SSH hỗ trợ mật khẩu mã hóa, cặp khóa công khai (Public-Key), chứng chỉ số và MFA.
* *Mức độ tin cậy:* Telnet bị cấm dùng trên môi trường thực tế; SSH là chuẩn bắt buộc toàn cầu.

### Câu 3: Cách đăng nhập SSH ngoài username/password và demo minh họa
* Ngoài mật khẩu truyền thống, SSH hỗ trợ: Xác thực bằng cặp khóa bất đối xứng (**Public-Key Authentication**), Chứng chỉ số SSH (**SSH Certificates**) và Xác thực đa yếu tố (**MFA/2FA qua TOTP hoặc khóa phần cứng FIDO2/U2F**).
* **Demo minh họa Public-Key:**
  1. Trên Windows 10, mở CMD tạo cặp khóa: `ssh-keygen -t ed25519 -C "lab1_student_key"`.
  2. Đưa khóa công khai vào tệp `~/.ssh/authorized_keys` trên máy chủ Kali Linux.
  3. Phân quyền tệp trên Kali: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`.
  4. Kết nối từ Windows 10: `ssh -i %USERPROFILE%\.ssh\id_ed25519 uitlab@<IP_Kali_Linux>`. Kết nối thành công ngay lập tức không cần nhập mật khẩu.

### Câu 4: Phân tích sự khác biệt dưới góc độ ba thuộc tính an toàn thông tin (CIA Triad)
1. **Tính bí mật (Confidentiality):**
   * *Telnet:* Bằng 0. Mọi gói tin truyền trần trụi, bắt gói tin đọc được 100% tài khoản và mật khẩu.
   * *SSH:* Rất cao. Trao đổi khóa an toàn (Diffie-Hellman/ECDH) tạo khóa phiên đối xứng (AES, ChaCha20), kẻ nghe lén chỉ thấy dữ liệu nhị phân ngẫu nhiên.
2. **Tính toàn vẹn (Integrity):**
   * *Telnet:* Không có bảo vệ. Kẻ tấn công có thể tiêm lệnh giả mạo hoặc sửa đổi gói tin giữa chừng.
   * *SSH:* Toàn vẹn nghiêm ngặt nhờ HMAC hoặc AEAD. Thay đổi dù chỉ 1 bit sẽ khiến kiểm tra toàn vẹn thất bại và phiên kết nối bị ngắt ngay lập tức.
3. **Tính xác thực (Authentication):**
   * *Telnet:* Chỉ có xác thực mật khẩu thô một chiều từ người dùng lên máy chủ, không có xác thực danh tính máy chủ.
   * *SSH:* Xác thực hai chiều toàn diện: Máy chủ chứng minh danh tính qua Host Key và dấu vân tay; người dùng chứng minh quyền truy cập qua mật khẩu mã hóa hoặc khóa công khai.

### Câu 5: Thông tin khôi phục qua Wireshark giữa phiên Telnet và SSH
* **Phiên Telnet:** Khôi phục trọn vẹn 100% địa chỉ IP, cổng 23, tên tài khoản đăng nhập (`login:`), từng ký tự mật khẩu (`Password:`), toàn bộ câu lệnh thực thi và kết quả hiển thị của máy chủ.
* **Phiên SSH:** Wireshark chỉ nhìn thấy chuỗi định danh phiên bản giao thức ban đầu (banner `SSH-2.0...`) và danh sách thuật toán trao đổi khóa; toàn bộ các gói tin dữ liệu sau đó đều là `Encrypted packet data` không thể khôi phục nội dung.

### Câu 6: Tại sao mật khẩu dài và phức tạp không khắc phục được điểm yếu của Telnet?
* Điểm yếu của Telnet xuất phát từ **kiến trúc tầng truyền dẫn của giao thức không có lớp mã hóa**, không bắt nguồn từ độ mạnh yếu của mật khẩu.
* Mật khẩu dù dài 30 ký tự chứa đầy đủ ký tự đặc biệt vẫn bị Telnet chia nhỏ đóng trực tiếp vào tải trọng của các phân đoạn TCP dạng mã ASCII rõ ràng. Wireshark chỉ việc gom gói tin lại là đọc được nguyên vẹn mà không cần bẻ khóa hay vét cạn.

### Câu 7: Siêu dữ liệu (metadata) của SSH bị lộ trên Wireshark và rủi ro
* **Thông tin quan sát được:** IP nguồn/đích, cổng dịch vụ TCP 22, chuỗi phiên bản phần mềm (Software Banner), danh sách thuật toán mã hóa hỗ trợ, kích thước gói tin và khoảng thời gian phát sinh gói tin.
* **Rủi ro:**
  * Khai thác lỗ hổng đã biết theo phiên bản OpenSSH cũ chưa vá lỗi (Known CVEs).
  * Tấn công phân tích lưu lượng (Traffic Analysis / Keystroke Timing): suy đoán độ dài mật khẩu hoặc dự đoán câu lệnh tương tác dựa trên nhịp độ gõ phím.
  * Nhận diện sơ đồ mạng nội bộ và các máy chủ quản trị trọng yếu.

### Câu 8: Vai trò của Host-Key Fingerprint và rủi ro khi chấp nhận tùy tiện
* **Vai trò:** Khóa máy chủ (Host Key) và dấu vân tay (Fingerprint) giúp người dùng xác minh máy khách đang kết nối tới đúng máy chủ hợp pháp của mình, ngăn chặn kết nối nhầm sang máy chủ mạo danh.
* **Rủi ro:** Nếu kẻ tấn công thực hiện tấn công đứng giữa (Man-in-the-Middle) qua đầu độc ARP/DNS và chuyển hướng kết nối về máy giả mạo, việc bấm chấp nhận bừa bãi sẽ thiết lập kênh mã hóa tới máy kẻ tấn công, khiến toàn bộ thông tin đăng nhập bị chiếm đoạt.

### Câu 9: Tại sao máy Attacker cùng mạng chưa chắc bắt được lưu lượng Unicast? Kỹ thuật thực tế cần có
* **Nguyên nhân:** Thiết bị chuyển mạch (Switch - bao gồm Virtual Switch của VMware) hoạt động ở Tầng 2, duy trì bảng địa chỉ MAC (CAM Table). Khi gói tin là đơn hướng (Unicast), Switch chỉ chuyển tiếp tới đúng cổng của máy đích, không phát tán ra cổng của máy Attacker.
* **Điều kiện/Kỹ thuật thực tế:**
  1. Cấu hình cổng phản chiếu (Port Mirroring / SPAN Port) trên Switch.
  2. Sử dụng thiết bị phần cứng trích tín hiệu mạng (Network TAP).
  3. Thực hiện tấn công đầu độc bộ nhớ đệm ARP (ARP Cache Poisoning / Spoofing).
  4. Cài đặt công cụ giám sát trực tiếp ngay trên máy Client hoặc máy Server.

### Câu 10: Nguyên lý Public-Key Authentication và ưu điểm so với mật khẩu
* **Nguyên lý:** Hoạt động theo cơ chế Thử thách - Đáp ứng (Challenge - Response). Người dùng giữ Khóa riêng (Private Key) trên máy khách và đưa Khóa công khai (Public Key) lên máy chủ. Máy chủ gửi chuỗi thử thách ngẫu nhiên, máy khách dùng khóa riêng tạo chữ ký số gửi lại, máy chủ dùng khóa công khai kiểm tra chữ ký để cấp quyền đăng nhập.
* **Ưu điểm:** Khóa bí mật không bao giờ truyền qua mạng; miễn nhiễm hoàn toàn trước tấn công vét cạn mật khẩu (Brute-force); hỗ trợ tự động hóa an toàn.

### Câu 11: Ba biện pháp làm cứng (Hardening) cho SSH trong thực tế
1. **Khóa tính năng đăng nhập bằng mật khẩu (`PasswordAuthentication no`):** Buộc 100% người dùng dùng khóa công khai, triệt tiêu nguy cơ bị botnet tấn công dò quét mật khẩu.
2. **Cấm tài khoản root đăng nhập trực tiếp (`PermitRootLogin no`):** Buộc quản trị viên đăng nhập bằng tài khoản cá nhân có danh tính rõ ràng, phục vụ nhật ký kiểm toán (Audit log).
3. **Đổi cổng dịch vụ mặc định từ TCP 22 sang cổng ngẫu nhiên bảo mật (ví dụ: cổng 22442):** Giảm thiểu trên 95% các cuộc quét mạng tự động của tin tặc trên Internet.
4. **Cài đặt công cụ chặn tự động Fail2ban hoặc cấu hình giới hạn địa chỉ IP tin cậy (IP Whitelisting).**

---

## D. QUY CHUẨN ĐÓNG GÓI KHO LƯU TRỮ GITHUB

```text
LAB_AT_BMHTTT/
└── LAB1/
    ├── README.md                          <-- Báo cáo tóm tắt theo quy chuẩn
    ├── Lab1_BaoCao_ThucHanh_ATBMHTTT.docx <-- Tệp Word báo cáo chính thức
    ├── captures/
    │   ├── telnet_traffic_capture.pcapng  <-- Tệp dữ liệu Telnet bắt từ Wireshark
    │   └── ssh_traffic_capture.pcapng     <-- Tệp dữ liệu SSH bắt từ Wireshark
    └── images/
        ├── telnet_wireshark_cleartext.png <-- Ảnh lộ thông tin đăng nhập Telnet
        ├── telnet_complex_password.png    <-- Ảnh mật khẩu phức tạp vẫn lộ
        ├── ssh_hostkey_warning.png        <-- Ảnh cảnh báo Host Key trên PuTTY
        ├── ssh_wireshark_encrypted.png    <-- Ảnh dữ liệu SSH mã hóa nhị phân
        └── ssh_publickey_demo.png         <-- Ảnh demo đăng nhập bằng khóa công khai
```
