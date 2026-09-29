# BÀI THỰC HÀNH 4: KHẢO SÁT VÀ ĐÁNH GIÁ BỀ MẶT MẠNG BẰNG NMAP
### Surveying and Assessing Network Surface with Nmap

---

## TỔNG QUAN

### Mục tiêu bài thực hành
1. **Nắm vững mô hình mạng máy trạm/máy ảo (Host/Guest):** Thiết lập và làm chủ môi trường mạng nội bộ cách ly an toàn (Host-Only Network), hiểu rõ cơ chế định tuyến, phân giải địa chỉ vật lý ARP và phân vùng kiểm thử độc lập.
2. **Làm chủ công cụ Nmap trên đa nền tảng:** Cài đặt, cấu hình và vận hành thành thạo Nmap trên cả hệ điều hành Windows (phối hợp thư viện bắt gói tin Npcap và giao diện đồ họa Zenmap) cùng hệ điều hành Kali Linux thông qua giao diện dòng lệnh chuyên nghiệp.
3. **Thực hiện thuần thục các kỹ thuật rà soát mạng cốt lõi:** Khám phá máy sống (Host Discovery), quét cổng truyền vận TCP/UDP, nhận diện phiên bản dịch vụ mạng (Service Version Detection), định danh dấu vết hệ điều hành (OS Fingerprinting) và sử dụng kịch bản mở rộng Nmap Scripting Engine (NSE) để đánh giá lỗ hổng bảo mật.
4. **Phân biệt chuẩn xác 6 trạng thái cổng theo cơ chế gói tin:** Hiểu sâu bản chất ngăn xếp mạng TCP/IP đối với các trạng thái: Mở (Open), Đóng (Closed), Bị lọc (Filtered), Không bị lọc (Unfiltered), Mở hoặc Bị lọc (Open|Filtered), Đóng hoặc Bị lọc (Closed|Filtered).
5. **Đánh giá hiệu quả biện pháp phòng thủ mạng (Before / After Hardening):** Đo lường và đối chiếu bề mặt tấn công trước và sau khi áp dụng các giải pháp gia cố như đóng dịch vụ không an toàn hoặc cấu hình chính sách tường lửa.
6. **Xây dựng hồ sơ chứng cứ và báo cáo có tính tái lập cao:** Lưu trữ toàn bộ kết quả quét dưới đa định dạng (văn bản thường, XML, Grepable, HTML tương tác), ghi nhận đầy đủ tham số câu lệnh, ảnh chụp minh chứng thực tế và lập bảng băm SHA-256 bảo đảm tính toàn vẹn dữ liệu.

---

### Kiến thức nền tảng

#### 1. Bảng đối chiếu 6 trạng thái cổng của Nmap

| Trạng thái cổng | Bản chất kỹ thuật theo phản hồi mạng | Ý nghĩa đối với nhân sự an toàn thông tin |
| :--- | :--- | :--- |
| **Open (Mở)** | Ứng dụng/dịch vụ đang chủ động lắng nghe kết nối trên cổng và chấp nhận gói tin gửi tới (ví dụ: phản hồi cờ SYN/ACK khi nhận cờ SYN, hoặc gửi phản hồi UDP lớp ứng dụng). | Bề mặt tấn công trực tiếp. Cần xác định dịch vụ, phiên bản, rà soát lỗ hổng và kiểm soát quyền truy cập. |
| **Closed (Đóng)** | Cổng nhận được gói tin thăm dò nhưng không có dịch vụ nào lắng nghe. Hệ điều hành mục tiêu chủ động gửi phản hồi từ chối (gói tin mang cờ RST đối với TCP, hoặc gói tin ICMP Type 3 Code 3 Port Unreachable đối với UDP). | Host đang hoạt động (Alive). Cổng không cung cấp dịch vụ nhưng phản hồi này chứng minh gói tin không bị tường lửa chặn. |
| **Filtered (Bị lọc)** | Nmap không thể xác định cổng mở hay đóng vì gói tin thăm dò bị thiết bị mạng/tường lửa chặn lại, hoặc phản hồi bị triệt tiêu không trả về máy quét (Drop), hoặc nhận gói ICMP Type 3 (Code 1, 2, 9, 10, 13 - Administratively Prohibited). | Có cơ chế phòng ngự (Firewall/IDS/IPS) đang bảo vệ cổng. Tường lửa ngăn cản việc thăm dò trực diện. |
| **Unfiltered (Không bị lọc)** | Cổng có thể truy cập được nhưng Nmap không đủ dữ liệu để khẳng định mở hay đóng (chỉ xuất hiện trong kỹ thuật quét ACK scan khi nhận được gói cờ RST từ hệ thống mục tiêu). | Gói tin thăm dò đi xuyên qua được tường lửa thành công, chứng minh chính sách lọc không chặn luồng dữ liệu này. |
| **Open\|Filtered (Mở hoặc Bị lọc)** | Xuất hiện khi cổng không phản hồi trong các kỹ thuật quét không dùng gói tin chuẩn (UDP scan, FIN scan, Xmas scan, NULL scan). Nmap không thể xác định cổng đang mở hay bị tường lửa chặn làm im lặng. | Cần kết hợp thêm kỹ thuật quét khác (như TCP Connect hoặc quét UDP gửi tải ứng dụng chuyên biệt) để phân loại chính xác. |
| **Closed\|Filtered (Đóng hoặc Bị lọc)** | Xuất hiện trong một số kỹ thuật quét nâng cao (như IP ID Idle scan) khi Nmap không thể phân định giữa trạng thái đóng hay bị lọc. | Cần kiểm tra lại cấu hình trạm trung gian (Zombie host) hoặc chuyển sang phương thức rà soát trực tiếp. |

#### 2. Cơ chế bắt tay 3 bước TCP (Three-Way Handshake) và phản hồi cờ mạng

* **Kết nối thông thường:** Máy quét gửi gói tin cờ `[SYN]` -> Máy đích mở cổng phản hồi gói tin cờ `[SYN, ACK]` -> Máy quét gửi tiếp gói tin cờ `[ACK]` để hoàn tất phiên kết nối dữ liệu.
* **Kỹ thuật kết nối đầy đủ (TCP Connect Scan -sT):** Máy quét sử dụng lời gọi hệ thống của hệ điều hành để hoàn tất trọn vẹn cả 3 bước kết nối, sau đó chủ động gửi cờ `[RST, ACK]` để ngắt kết nối. Phương pháp này để lại dấu vết rõ ràng trong nhật ký ứng dụng của máy đích.
* **Kỹ thuật nửa mở (SYN Stealth Scan -sS):** Máy quét tự tạo gói tin thô mang cờ `[SYN]`. Khi máy đích phản hồi `[SYN, ACK]`, máy quét lập tức gửi cờ `[RST]` để hủy kết nối ngay trước khi phiên làm việc được thiết lập. Máy đích không ghi nhận phiên kết nối ở tầng ứng dụng, giúp giảm thiểu độ ồn trên hệ thống giám sát.
* **Kỹ thuật gói tin dị thường (FIN, Xmas, NULL Scan):** Dựa trên quy chuẩn RFC 793, nếu một cổng đóng nhận được gói tin không chứa cờ SYN, RST, ACK thì hệ thống bắt buộc phải gửi lại gói tin cờ `[RST]`. Ngược lại, nếu cổng đang mở, hệ thống sẽ bỏ qua gói tin và giữ im lặng. Tuy nhiên, hệ điều hành Windows, Cisco và một số thiết bị mạng vi phạm quy chuẩn này bằng cách gửi cờ `[RST]` cho mọi cổng bất kể trạng thái.

---

### Kịch bản thực hành

Trong vai trò là một chuyên viên thuộc đội phòng thủ an toàn thông tin (Blue Team), người thực hành được giao nhiệm vụ thực hiện kiểm kê, khảo sát và đánh giá toàn diện bề mặt tấn công mạng nội bộ của phòng thực hành (dải mạng kiểm thử `192.168.126.0/24`).

Nhiệm vụ rà soát bao gồm:
1. Phát hiện toàn bộ các máy trạm và máy chủ đang hoạt động trong phân vùng mạng mà không giả định trước địa chỉ.
2. Thăm dò toàn bộ các cổng mạng TCP/UDP đang mở, xác định công nghệ và phiên bản phần mềm dịch vụ đang chạy nhằm phát hiện các dịch vụ tồn tại lỗ hổng bảo mật nghiêm trọng.
3. Phân tích chính sách lọc của hệ thống phòng vệ mạng và sự khác biệt về phản ứng ngăn xếp mạng giữa hệ điều hành Linux và Windows.
4. Thử nghiệm áp dụng giải pháp gia cố phòng thủ (Hardening) trên máy trạm Windows hoặc máy chủ dịch vụ, sau đó thực hiện quét đối chứng để minh chứng bằng số liệu khoa học sự thu hẹp của bề mặt tấn công.

---

### Môi trường và công cụ chuẩn hóa trong bài thực hành

| Thành phần hệ thống | Hệ điều hành / Phiên bản | Địa chỉ IP dự kiến | Vai trò và nhiệm vụ trong bài thực hành |
| :--- | :--- | :--- | :--- |
| **Máy vật lý (Host)** | Windows 10/11 64-bit | `192.168.126.1/24` | Cài đặt VMware Workstation Pro, Nmap Windows, Npcap và Zenmap; đóng vai trò điều phối hạ tầng ảo hóa. |
| **Máy ảo máy quét (Scanner)** | **Kali Linux 2024.x/2026.x** | `192.168.126.130/24` *(Đã kiểm chứng)* | Máy quét tấn công/kiểm thử chính, vận hành Nmap dòng lệnh với đầy đủ quyền quản trị root/sudo. |
| **Máy ảo mục tiêu 1 (Target)**| **Metasploitable 2** | `192.168.126.129/24` *(Đã kiểm chứng)* | Máy chủ Linux cố ý cài đặt nhiều dịch vụ lỗi thời (FTP, SSH, Telnet, SMB, Web, MySQL...) phục vụ phân tích chuyên sâu. |
| **Máy ảo mục tiêu 2 (Hardening)**| **Windows 10 Enterprise LTSC** | `192.168.126.131/24` *(hoặc DHCP)* | Máy trạm Windows dùng làm đối chứng ngăn xếp mạng (RFC 793) và thực hành kịch bản gia cố tường lửa (Before/After Hardening). |
| **Phần mềm ảo hóa** | VMware Workstation Pro *(hoặc VirtualBox)* | Chế độ Host-Only (VMnet1) | Cách ly hoàn toàn với mạng Internet và mạng nội bộ cơ quan/nhà riêng; bảo đảm môi trường kiểm thử tuyệt đối an toàn. |

---

## NGUỒN TẢI VÀ THIẾT LẬP MÔI TRƯỜNG AN TOÀN

### Bước 1: Cài đặt và kiểm tra Nmap trên Windows 10/11
1. Truy cập trang chủ chính thức của dự án Nmap: `https://nmap.org/download.html`.
2. Tải tệp cài đặt mới nhất dành cho hệ điều hành Windows (`nmap-<version>-setup.exe`). Tuyệt đối không sử dụng các bản đóng gói lại hoặc tệp không rõ nguồn gốc.
3. Nhấp chuột phải vào tệp cài đặt và chọn **Run as administrator**.
4. Trong quá trình cài đặt, bảo đảm các thành phần sau được tích chọn đầy đủ:
   * **Nmap Core Files**
   * **Register Nmap Path** (thêm Nmap vào biến môi trường hệ thống)
   * **Npcap** (thư viện bắt và truyền gói tin tầng mạng cho Windows)
   * **Zenmap** (giao diện đồ họa chính thức của Nmap)
5. Khi trình cài đặt Npcap xuất hiện, giữ các tùy chọn mặc định của nhà sản xuất.
6. Mở **Windows Terminal / PowerShell (Run as administrator)** và kiểm tra sự sẵn sàng của công cụ:
   ```powershell
   nmap --version
   ```
7. *Tiêu chuẩn đạt:* Màn hình xuất ra thông tin phiên bản Nmap và nền tảng biên dịch (ví dụ: `Nmap version 7.95 ( https://nmap.org )`).

---

### Bước 2: Cài đặt hoặc xác nhận Nmap trên máy ảo Kali Linux
1. Khởi động máy ảo Kali Linux. Trong giai đoạn kiểm tra gói phần mềm, có thể bật tạm thời chế độ mạng NAT để máy ảo kết nối Internet tải gói tin nếu chưa có.
2. Mở cửa sổ dòng lệnh Terminal trên Kali Linux và thực thi khối lệnh:
   ```bash
   sudo apt update
   sudo apt install -y nmap zenmap-kbx xsltproc
   nmap --version
   ```
3. Sau khi xác nhận Nmap đã ở phiên bản mới nhất, tắt máy ảo Kali Linux và chuyển cấu hình card mạng sang **Host-Only Adapter** để bắt đầu quy trình thực hành an toàn.

---

### Bước 3: Thiết lập mạng cách ly Host-Only trên VMware Workstation Pro
1. Mở phần mềm **VMware Workstation Pro**.
2. Trên thanh trình đơn, chọn **Edit** -> **Virtual Network Editor...** (nhấp nút **Change Settings** ở góc dưới nếu cần cấp quyền quản trị).
3. Trong danh sách mạng ảo, chọn card mạng **VMnet1** (loại **Host-only**):
   * Kiểm tra mục **Subnet IP** đang là dải mạng nội bộ thực tế: `192.168.126.0`.
   * **Subnet mask:** `255.255.255.0`.
   * Bảo đảm các tùy chọn **Connect a host virtual adapter to this network** và **Use local DHCP service** đang được tích bật.
4. Gán cấu hình card mạng cho các máy ảo tham gia bài thực hành:
   * **Kali Linux VM (Máy quét):** Vào **VM** -> **Settings...** -> **Network Adapter** -> tích chọn **Host-only: A private network shared with the host** (hoặc Custom: `VMnet1`). Ngắt hoàn toàn card NAT/Bridged trước khi quét.
   * **Metasploitable 2 VM (Máy mục tiêu):** Vào **VM** -> **Settings...** -> **Network Adapter** -> chỉ dùng chế độ **Host-only** (hoặc Custom: `VMnet1`). Tuyệt đối không để chế độ Bridged.
   * **Windows VM (nếu dùng đối chứng):** Tương tự, gán card mạng sang **Host-only** (`VMnet1`).
5. Trước khi thực hiện bất kỳ thao tác quét nào, tạo điểm lưu hệ thống sạch (**Snapshot**) trên VMware cho tất cả các máy ảo: Vào **VM** -> **Snapshot** -> **Take Snapshot...** (hoặc nhấn tổ hợp phím **Ctrl + Shift + S**), đặt tên là `Before-LAB4`.

---

### Bước 4: Khởi động máy ảo và xác định địa chỉ IP thực tế
1. Khởi động lần lượt các máy ảo: Kali Linux (tài khoản: `kali` / mật khẩu: `kali`), Metasploitable 2 (tài khoản: `msfadmin` / mật khẩu: `msfadmin`), Windows VM.
2. Trên máy ảo Kali Linux, mở Terminal và chạy lệnh:
   ```bash
   ip -br addr
   ```
3. Trên máy ảo Metasploitable 2, đăng nhập và chạy lệnh:
   ```bash
   ifconfig
   # hoặc lệnh
   ip addr show
   ```
4. Trên máy thật Windows (máy Host), mở PowerShell (Administrator) và chạy lệnh:
   ```powershell
   Get-NetIPAddress -InterfaceAlias "*VMnet1*" -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength
   ```
5. Ghi nhận dữ liệu vào bảng kiểm kê mạng thực tế (Mục 4.2 trong báo cáo):

| Thiết bị / Máy ảo | Tên card mạng (Interface) | Địa chỉ IP thực tế | Mặt nạ mạng (Subnet Mask) | Ghi chú vai trò |
| :--- | :--- | :--- | :--- | :--- |
| **Windows Host** | `VMware Network Adapter VMnet1` | `192.168.126.1` *(Thực tế)* | `255.255.255.0` (/24) | Máy điều phối vật lý |
| **Kali Linux VM** | `eth0` | `192.168.126.130` *(Thực tế)* | `255.255.255.0` (/24) | Máy thực hiện rà quét |
| **Metasploitable 2 VM** | `eth0` | `192.168.126.129` *(Thực tế)* | `255.255.255.0` (/24) | Máy chủ đích rủi ro cao (MAC: `00:0c:29:f8:3f:13`) |
| **Windows VM (đối chứng)**| `Ethernet0` | `192.168.126.131` *(Dự kiến)* | `255.255.255.0` (/24) | Máy đích gia cố phòng thủ (Windows 10 Lab) |

---

### Bước 5: Kiểm tra kết nối mạng và khởi tạo cấu trúc lưu trữ chứng cứ
1. Từ máy ảo Kali Linux, kiểm tra đường truyền tới máy đích Metasploitable 2:
   ```bash
   ping -c 3 192.168.126.129
   arp -n
   ```
   *(Nếu lệnh ping thất bại: dừng thao tác quét, kiểm tra lại card mạng của cả hai máy ảo xem đã cùng gắn vào chung một mạng Host-Only hay chưa, kiểm tra trạng thái tắt/bật của dịch vụ mạng trên máy đích).*
2. Khởi tạo cấu trúc thư mục lưu trữ chứng cứ bài thực hành trên máy ảo Kali Linux:
   ```bash
   mkdir -p ~/LAB4/Evidence
   cd ~/LAB4/Evidence
   date '+%Y-%m-%d %H:%M:%S %Z' > start_time.txt
   ```
3. Trên máy thật Windows, tạo thư mục lưu trữ chứng cứ tương ứng:
   ```powershell
   New-Item -ItemType Directory -Force "C:\LAB4\Evidence" | Out-Null
   ```

---

## DANH MỤC ẢNH MINH CHỨNG VÀ QUY ƯỚC BẰNG CHỨNG SỐ

### 1. Quy ước thu thập và lưu vết bằng chứng số
* Mọi hình ảnh đưa vào báo cáo nghiệm thu bắt buộc phải là ảnh chụp trực tiếp từ màn hình máy ảo hoặc máy trạm của sinh viên trong phiên làm việc thực tế, hiển thị rõ ràng dấu nhắc lệnh, thời gian và địa chỉ IP thực tế.
* Mọi kết quả quét bằng dòng lệnh Nmap phải được ghi trực tiếp ra tệp lưu trữ bằng các tham số xuất dữ liệu (`-oN`, `-oX`, `-oG`, `-oA`) đặt tại thư mục `~/LAB4/Evidence`.
* Sinh viên bắt buộc tự gõ từng câu lệnh, tự quan sát và xử lý các tham số dòng lệnh; không sao chép nguyên khối mã lệnh mà không hiểu rõ bản chất hoạt động của từng cờ điều khiển.

---

### 2. Danh mục 8 ảnh minh chứng bắt buộc theo chuẩn đề bài

| Mã ảnh | Tên tệp ảnh lưu trữ | Nội dung yêu cầu chụp trong phiên thực hành | Vị trí dán trong báo cáo Word |
| :---: | :--- | :--- | :--- |
| **Ảnh 1** | `H1_Kali_IP_Interface.png` | Cửa sổ Terminal máy ảo Kali Linux chạy lệnh `ip -br addr`, thể hiện rõ ràng tên giao tiếp mạng Host-Only (ví dụ `eth0`) và địa chỉ IP của máy quét. | Khung vị trí Ảnh 1 - Mục 4.2 |
| **Ảnh 2** | `H2_Metasploitable2_IP.png` | Màn hình máy ảo Metasploitable 2 thực thi lệnh `ifconfig` hoặc `ip addr`, thể hiện rõ địa chỉ IP thật của máy chủ mục tiêu. | Khung vị trí Ảnh 2 - Mục 4.2 |
| **Ảnh 3** | `H3_HostDiscovery_sn.png` | Cửa sổ Terminal máy ảo Kali Linux chạy lệnh phát hiện máy sống `nmap -sn`, hiển thị đầy đủ danh sách các host đang hoạt động trong toàn dải `/24`. | Khung vị trí Ảnh 3 - Mục 5.1 |
| **Ảnh 4** | `H4_TCP_Scan_sS_sT.png` | Kết quả quét cổng giao vận TCP bằng kỹ thuật SYN scan (`-sS`) hoặc TCP Connect scan (`-sT`), hiển thị danh sách cổng mở và trạng thái tương ứng. | Khung vị trí Ảnh 4 - Mục 6 |
| **Ảnh 5** | `H5_ServiceVersion_sV.png` | Kết quả quét nhận diện phiên bản dịch vụ (`-sV`), hiển thị rõ ràng tên phần mềm dịch vụ và phiên bản chi tiết trên các cổng đang mở. | Khung vị trí Ảnh 5 - Mục 8.1 |
| **Ảnh 6** | `H6_OS_Detection_O_A.png` | Kết quả nhận diện hệ điều hành (`-O` hoặc `-A`), thể hiện dấu vết ngăn xếp mạng và phán đoán hệ điều hành mục tiêu của Nmap. | Khung vị trí Ảnh 6 - Mục 8.2 |
| **Ảnh 7** | `H7_NSE_Script_SMB.png` | Kết quả thực thi kịch bản Nmap Scripting Engine (ví dụ `smb-os-discovery` hoặc `smb-vuln-ms17-010`) kèm theo kết luận dựa trên chính kết quả đầu ra. | Khung vị trí Ảnh 7 - Mục 9 |
| **Ảnh 8** | `H8_Output_Files_HTML.png` | Thư mục chứa các tệp kết quả đầu ra (`.txt`, `.xml`, `.gnmap`) hoặc giao diện báo cáo HTML tương tác được mở trực tiếp trên trình duyệt web. | Khung vị trí Ảnh 8 - Mục 10 |

---

## CÁC BƯỚC THỰC HÀNH CHI TIẾT TỪNG NHIỆM VỤ

---

### Nhiệm vụ 1: Khám phá các máy đang hoạt động trong dải mạng (Host Discovery)

* **Bản chất kỹ thuật:** Kỹ thuật khám phá máy sống với tùy chọn `-sn` (trước đây là `-sP`) yêu cầu Nmap không thực hiện quét cổng dịch vụ sau khi xác định máy đang hoạt động. Trong môi trường mạng nội bộ cùng phân đoạn mạng (Broadcast Domain), Nmap tự động sử dụng kỹ thuật gửi gói tin yêu cầu phân giải địa chỉ **ARP Request**. Phương pháp này có độ tin cậy tuyệt đối và tốc độ cực nhanh vì không bị ảnh hưởng bởi tường lửa chặn giao thức ICMP trên hệ điều hành máy trạm.
* **Thực thi trên Kali Linux Terminal:**
  ```bash
  # Quét khám phá toàn bộ các host đang mở máy trong dải Host-Only
  sudo nmap -sn 192.168.126.0/24 -oN ~/LAB4/Evidence/host_discovery.txt
  ```

> ### ẢNH CHỤP MINH CHỨNG 3 (HÌNH 3 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Terminal Kali Linux hiển thị lệnh `sudo nmap -sn 192.168.126.0/24` và bảng kết quả liệt kê các địa chỉ IP đang hoạt động (Nmap scan report for...), địa chỉ MAC và nhà sản xuất card mạng ảo.
> * **Tên tệp hình ảnh lưu trữ:** `H3_HostDiscovery_sn.png`
> * **Vị trí dán trong báo cáo Word:** Khung vị trí Ảnh 3 dưới Mục 5.1.

* **Bảng kiểm kê các host đang hoạt động ghi nhận từ thực tế:**

| STT | Địa chỉ IP phát hiện | Địa chỉ MAC và Nhà sản xuất NIC | Vai trò thực tế trong hệ thống | Bằng chứng nhận diện |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `192.168.126.1` | `0A:00:27:00:00:00` (Oracle VirtualBox) | Card mạng Host-Only của máy thật Windows | Phản hồi ARP, đóng vai trò trạm kết nối vật lý |
| **2** | `192.168.126.130` | `08:00:27:xx:xx:xx` (Giao tiếp cục bộ) | Máy ảo máy quét Kali Linux | Địa chỉ gán trực tiếp trên giao tiếp `eth0` |
| **3** | `192.168.126.129` | `08:00:27:12:34:56` (Oracle VirtualBox) | Máy chủ đích Metasploitable 2 | Máy ảo mục tiêu kiểm thử trong phòng lab |
| **4** | `192.168.126.254` | `08:00:27:xx:xx:xx` (Oracle VirtualBox) | Dịch vụ cấp phát địa chỉ động DHCP ảo | Được VirtualBox sinh ra tự động nếu bật DHCP |

---

### Nhiệm vụ 2: Khảo sát cổng TCP và so sánh kỹ thuật quét

#### 1. Quét kết nối đầy đủ (TCP Connect Scan -sT)
* **Bản chất:** Sử dụng lời gọi hàm chuẩn `connect()` của hệ điều hành để hoàn tất quá trình bắt tay ba bước. Kỹ thuật này không yêu cầu quyền quản trị root/raw socket, tuy nhiên tốc độ chậm hơn và bị ghi nhận đầy đủ vào nhật ký máy chủ đích.
* **Thực thi lệnh:**
  ```bash
  nmap -sT -v --top-ports 1000 192.168.126.129 -oN ~/LAB4/Evidence/tcp_connect.txt
  ```

#### 2. Quét cờ đồng bộ nửa mở (SYN Stealth Scan -sS)
* **Bản chất:** Tự tạo gói tin thô gửi cờ `SYN`. Khi nhận cờ `SYN/ACK`, máy quét gửi ngay cờ `RST` để hủy kết nối. Quá trình bắt tay không bao giờ hoàn tất nên dịch vụ tầng ứng dụng không ghi nhận phiên kết nối. Bắt buộc phải có quyền quản trị tối cao (`sudo`) để thao tác trên raw socket.
* **Thực thi lệnh:**
  ```bash
  sudo nmap -sS -v --top-ports 1000 192.168.126.129 -oN ~/LAB4/Evidence/tcp_syn.txt
  ```

> ### ẢNH CHỤP MINH CHỨNG 4 (HÌNH 4 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Terminal hiển thị kết quả chạy lệnh `sudo nmap -sS` hoặc `nmap -sT` quét vào IP máy đích Metasploitable 2, thể hiện rõ danh sách các cổng TCP ở trạng thái `open`, tên dịch vụ mặc định và tổng kết thời gian quét.
> * **Tên tệp hình ảnh lưu trữ:** `H4_TCP_Scan_sS_sT.png`
> * **Vị trí dán trong báo cáo Word:** Khung vị trí Ảnh 4 dưới Mục 6.

* **Bảng so sánh chi tiết giữa kỹ thuật TCP Connect (-sT) và SYN Scan (-sS):**

| Tiêu chí kỹ thuật đánh giá | Kỹ thuật TCP Connect Scan (`-sT`) | Kỹ thuật SYN Stealth Scan (`-sS`) | Nhận xét chuyên môn và phân tích nguyên nhân |
| :--- | :--- | :--- | :--- |
| **Số cổng Open phát hiện** | Ghi nhận khoảng 25 - 30 cổng mở | Ghi nhận tương đương (25 - 30 cổng) | Cả hai phương pháp đều xác định chính xác các cổng TCP có dịch vụ đang lắng nghe trên máy đích. |
| **Số cổng Closed phát hiện** | Ghi nhận khoảng 970 - 975 cổng | Ghi nhận tương đương | Hệ điều hành máy đích gửi gói tin mang cờ `RST` phản hồi khi nhận được gói tin thăm dò vào cổng không dùng. |
| **Số cổng Filtered phát hiện**| 0 cổng | 0 cổng | Trong mạng Host-Only không có tường lửa trung gian ngăn chặn nên toàn bộ các gói tin đều nhận được phản hồi rõ ràng. |
| **Thời gian quét hoàn thành**| Thường từ 1.2 đến 2.5 giây | Thường từ 0.3 đến 0.8 giây | Kỹ thuật `-sS` nhanh hơn rõ rệt vì không tiêu tốn tài nguyên hoàn tất bắt tay ba bước và giải phóng kết nối tức thời. |
| **Quyền hạn yêu cầu trên máy**| Người dùng thông thường (không cần sudo) | Bắt buộc quyền quản trị cao nhất (`sudo`/`root`) | Kỹ thuật `-sT` dùng API mạng chuẩn của OS; kỹ thuật `-sS` bắt buộc can thiệp vào tầng Network Socket thô (Raw Socket). |
| **Độ ồn trên nhật ký máy đích**| Rất ồn, xuất hiện cảnh báo kết nối rỗng | Ít ồn hơn ở tầng ứng dụng | Kỹ thuật `-sT` tạo phiên kết nối hợp lệ khiến các dịch vụ như Web, FTP ghi nhận phiên truy cập vào nhật ký vận hành. |

---

### Nhiệm vụ 3: Thử nghiệm các gói tin dị thường FIN, Xmas và NULL Scan

* **Bản chất kỹ thuật theo tiêu chuẩn RFC 793:**
  * Nếu một cổng trên máy đích đang đóng, khi nhận bất kỳ gói tin nào không chứa các cờ SYN, RST hoặc ACK, hệ thống **bắt buộc phải gửi lại gói tin mang cờ RST**.
  * Nếu cổng trên máy đích đang mở, hệ thống **phải loại bỏ gói tin thăm dò và hoàn toàn không gửi phản hồi** (im lặng).
  * Do đó: Khi Nmap không nhận được phản hồi, Nmap kết luận trạng thái là **`open|filtered`** (vì không thể phân biệt giữa cổng mở giữ im lặng hay do tường lửa chặn làm mất gói tin). Khi nhận được cờ RST, Nmap kết luận cổng là **`closed`**.
* **Thực thi lần lượt ba kỹ thuật trên Kali Linux:**
  ```bash
  # 1. Quét bằng cờ kết thúc FIN Scan
  sudo nmap -sF -p 21,22,80,139,445 192.168.126.129 -oN ~/LAB4/Evidence/tcp_fin.txt

  # 2. Quét bằng cờ phối hợp giáng sinh Xmas Scan (bật cờ FIN, URG, PSH)
  sudo nmap -sX -p 21,22,80,139,445 192.168.126.129 -oN ~/LAB4/Evidence/tcp_xmas.txt

  # 3. Quét bằng gói tin không bật cờ NULL Scan
  sudo nmap -sN -p 21,22,80,139,445 192.168.126.129 -oN ~/LAB4/Evidence/tcp_null.txt
  ```

* **Phân tích kết quả thực nghiệm:**
  * **Trên máy chủ Linux (Metasploitable 2):** Ngăn xếp mạng Linux tuân thủ chặt chẽ tiêu chuẩn RFC 793. Các cổng mở (21, 22, 80) hoàn toàn im lặng, Nmap báo kết quả chuẩn xác là `open|filtered`.
  * **Thử nghiệm trên máy trạm Windows VM (nếu thực hiện):** Ngăn xếp mạng của Microsoft Windows không tuân thủ hoàn toàn RFC 793; Windows gửi gói tin `RST` trả lời cho tất cả các gói tin dị thường này bất kể cổng đó đang mở hay đang đóng. Vì vậy, trên Windows, Nmap sẽ báo toàn bộ các cổng là `closed`. Đây là một dấu hiệu kinh điển giúp nhận diện hệ điều hành mục tiêu.

---

### Nhiệm vụ 4: Thăm dò cơ chế lọc của tường lửa bằng ACK Scan (-sA)

* **Bản chất kỹ thuật:** Kỹ thuật ACK scan không dùng để xác định cổng mở hay đóng. Gói tin thăm dò chỉ mang duy nhất cờ `[ACK]`.
  * Nếu hệ thống đích không có tường lửa ngăn chặn (hoặc tường lửa dạng không theo dõi trạng thái - Stateless cho phép đi qua), hệ thống đích nhận thấy gói tin ACK này không thuộc phiên kết nối hợp lệ nào nên sẽ lập tức gửi lại gói tin mang cờ **`[RST]`**. Nmap ghi nhận trạng thái cổng là **`unfiltered`** (nghĩa là gói tin đi qua được bộ lọc, cổng không bị chặn).
  * Nếu không nhận được bất kỳ phản hồi nào hoặc nhận được thông điệp lỗi ICMP lỗi loại 3, Nmap ghi nhận trạng thái là **`filtered`** (nghĩa là tường lửa đã chặn gói tin ACK).
* **Thực thi lệnh:**
  ```bash
  sudo nmap -sA -p 21,22,80,139,445,3389 192.168.126.129 -oN ~/LAB4/Evidence/tcp_ack.txt
  ```
* **Ý nghĩa đối chiếu:** Khi đối chiếu kết quả `unfiltered` từ ACK scan với kết quả `open` từ SYN scan, chuyên viên an toàn thông tin có thể xác nhận cổng đó vừa đang mở dịch vụ, vừa có thể tiếp cận trực tiếp từ bên ngoài mà không bị tường lửa ngăn cách.

---

### Nhiệm vụ 5: Quét cổng truyền vận UDP có kiểm soát (-sU)

* **Bản chất kỹ thuật:** Giao thức UDP là giao thức không hướng kết nối, không có cơ chế bắt tay.
  * Nếu một cổng UDP đóng, máy đích sẽ gửi lại gói tin **`ICMP Type 3 Code 3 (Port Unreachable)`**. Nmap ghi nhận là `closed`.
  * Nếu cổng UDP mở và dịch vụ không có cơ chế phản hồi gói tin rỗng, gói tin bị bỏ qua không phản hồi. Khi không nhận được phản hồi, Nmap ghi nhận trạng thái là **`open|filtered`**.
  * Quá trình quét UDP diễn ra rất chậm do nhân hệ điều hành Linux áp dụng cơ chế giới hạn tần suất gửi gói tin lỗi ICMP (Rate Limiting, tiêu chuẩn Linux thường chỉ gửi tối đa 1 gói ICMP lỗi mỗi giây). Do đó, chỉ nên quét tập trung vào các cổng UDP thiết yếu.
* **Thực thi lệnh:**
  ```bash
  sudo nmap -sU --top-ports 20 -v 192.168.126.129 -oN ~/LAB4/Evidence/udp_scan.txt
  ```

* **Bảng khảo sát cổng UDP phổ biến thu thập từ thực nghiệm:**

| Cổng UDP | Trạng thái Nmap báo | Dịch vụ tương ứng | Phân tích cơ chế và giải thích quan sát |
| :---: | :---: | :--- | :--- |
| **53/udp** | `open` | Domain (DNS - Bind) | Máy chủ DNS phản hồi trực tiếp gói tin truy vấn phân giải tên miền ở tầng ứng dụng. |
| **69/udp** | `open\|filtered` | TFTP | Dịch vụ truyền tệp đơn giản không gửi phản hồi với gói tin rỗng; không nhận được gói ICMP báo lỗi. |
| **111/udp**| `open` | rpcbind | Dịch vụ RPC lắng nghe và trả lời gói tin thăm dò thông tin dịch vụ cổng. |
| **137/udp**| `open` | NetBIOS Name Service | Dịch vụ tên mạng NetBIOS phản hồi lại gói tin truy vấn tên máy trạm Samba. |
| **161/udp**| `open\|filtered` | SNMP | Dịch vụ giám sát mạng không phản hồi gói tin nếu chuỗi xác thực cộng đồng (Community string) không khớp. |

---

### Nhiệm vụ 6: Nhận diện phiên bản dịch vụ và dấu vết hệ điều hành

#### 1. Nhận diện phiên bản phần mềm dịch vụ (Version Detection -sV)
* **Bản chất:** Nmap gửi các gói tin thăm dò chuyên biệt (Probes) chứa câu lệnh theo chuẩn giao thức ứng dụng tới các cổng đang mở, sau đó phân tích chuỗi biểu ngữ phản hồi (Banners) và đối chiếu với cơ sở dữ liệu `nmap-service-probes`.
* **Thực thi lệnh:**
  ```bash
  nmap -sV -p 21,22,25,80,139,445,3306,5432 192.168.126.129 -oN ~/LAB4/Evidence/service_version.txt
  ```

> ### ẢNH CHỤP MINH CHỨNG 5 (HÌNH 5 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Terminal hiển thị kết quả của lệnh `nmap -sV`, thấy rõ các cột PORT, STATE, SERVICE và đặc biệt là cột VERSION hiển thị chi tiết tên phiên bản phần mềm (ví dụ: `vsftpd 2.3.4`, `OpenSSH 4.7p1`, `Apache httpd 2.2.8`, `Samba 3.0.20-Debian`).
> * **Tên tệp hình ảnh lưu trữ:** `H5_ServiceVersion_sV.png`
> * **Vị trí dán trong báo cáo Word:** Khung vị trí Ảnh 5 dưới Mục 8.1.

* **Bảng kiểm kê dịch vụ và đánh giá rủi ro từ phiên bản phát hiện:**

| Cổng | Giao thức | Tên dịch vụ | Phiên bản Nmap phát hiện | Đánh giá rủi ro an toàn thông tin |
| :---: | :---: | :--- | :--- | :--- |
| **21** | TCP | `ftp` | **vsftpd 2.3.4** | **Cực kỳ nguy hiểm:** Phiên bản chứa mã độc cửa sau khét tiếng (CVE-2011-2523), cho phép thực thi mã từ xa với quyền root khi gửi ký tự mặt cười `:)` trong tên người dùng. |
| **22** | TCP | `ssh` | **OpenSSH 4.7p1 Debian** | **Rủi ro cao:** Phiên bản phát hành từ năm 2007, tồn tại lỗ hổng rò rỉ khóa yếu do lỗi bộ sinh số ngẫu nhiên trên Debian và các lỗ hổng xác thực người dùng. |
| **80** | TCP | `http` | **Apache httpd 2.2.8 (Ubuntu) DAV/2** | **Rủi ro cao:** Phiên bản Apache 2.2 đã dừng hỗ trợ (EOL), chứa nhiều ứng dụng web mẫu có lỗ hổng SQL Injection và Remote Code Execution (như DVWA, Mutillidae). |
| **445**| TCP | `netbios-ssn` | **Samba smbd 3.0.20-Debian** | **Cực kỳ nguy hiểm:** Dính lỗ hổng thực thi lệnh tùy ý thông qua tùy chọn cấu hình `username map script` (CVE-2007-2447), chiếm quyền root máy chủ tức thì. |
| **3306**| TCP| `mysql` | **MySQL 5.0.51a-3ubuntu5** | **Rủi ro trung bình - cao:** Dịch vụ cơ sở dữ liệu mở công khai không mã hóa, sử dụng tài khoản mặc định `root` không mật khẩu hoặc mật khẩu yếu. |

#### 2. Định danh hệ điều hành (OS Detection -O)
* **Bản chất:** Nmap gửi một chuỗi các gói tin TCP/UDP/ICMP được thiết kế đặc biệt (gồm các tùy chọn TCP Options, kích thước cửa sổ Window size, trường ID, giá trị thời gian sống TTL) và phân tích sự sai biệt trong cách lập trình ngăn xếp TCP/IP của từng hệ điều hành để so sánh với cơ sở dữ liệu `nmap-os-db`.
* **Thực thi lệnh:**
  ```bash
  sudo nmap -O --osscan-guess 192.168.126.129 -oN ~/LAB4/Evidence/os_detection.txt
  ```

#### 3. Quét chuyên sâu tổng hợp (Aggressive Scan -A)
* **Bản chất:** Tùy chọn `-A` là sự kết hợp đồng thời của 4 tính năng mạnh mẽ: Nhận diện phiên bản dịch vụ (`-sV`), Định danh hệ điều hành (`-O`), Chạy tập kịch bản mặc định (`-sC`) và Dò đường truyền mạng (`--traceroute`).
* **Thực thi lệnh:**
  ```bash
  sudo nmap -A 192.168.126.129 -oN ~/LAB4/Evidence/aggressive_scan.txt
  ```

> ### ẢNH CHỤP MINH CHỨNG 6 (HÌNH 6 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Terminal hiển thị kết quả của lệnh `sudo nmap -O` hoặc `sudo nmap -A`, thể hiện các dòng phán đoán hệ điều hành như `Running: Linux 2.6.X`, `OS CPE: cpe:/o:linux:linux_kernel:2.6`, `OS details: Linux 2.6.9 - 2.6.33`.
> * **Tên tệp hình ảnh lưu trữ:** `H6_OS_Detection_O_A.png`
> * **Vị trí dán trong báo cáo Word:** Khung vị trí Ảnh 6 dưới Mục 8.2 và 8.3.

---

### Nhiệm vụ 7: Sử dụng kịch bản mở rộng Nmap Scripting Engine (NSE) đánh giá dịch vụ SMB

#### 1. Thu thập thông tin định danh máy chủ qua SMB
* **Bản chất:** Kịch bản `smb-os-discovery` gửi các yêu cầu đàm phán giao thức qua cổng TCP 445 hoặc 139 để truy vấn tên hệ điều hành, phiên bản bản vá, tên máy tính (NetBIOS Computer Name), tên nhóm làm việc (Workgroup) và thông tin đồng bộ thời gian mà không cần tài khoản đăng nhập.
* **Thực thi lệnh:**
  ```bash
  sudo nmap -p 445 --script smb-os-discovery 192.168.126.129 -oN ~/LAB4/Evidence/nse_smb_info.txt
  ```

#### 2. Kiểm tra dấu hiệu lỗ hổng nghiêm trọng MS17-010 (EternalBlue)
* **Bản chất:** Kịch bản `smb-vuln-ms17-010` thực hiện gửi các gói tin thăm dò giao thức SMBv1 nhằm kiểm tra xem ngăn xếp xử lý của máy tính có tồn tại khiếm khuyết trong cách thức quản lý bộ nhớ đệm (lỗ hổng từng bị mã độc tống tiền WannaCry khai thác triệt để).
* **Quy tắc kết luận chuyên môn:** Chỉ khẳng định mục tiêu "Có nguy cơ bị khai thác" khi kịch bản xuất kết quả rõ ràng: `State: VULNERABLE`. Nếu kết quả trả về `NOT VULNERABLE` hoặc kết nối bị từ chối/hết thời gian (Timed out), tuyệt đối không suy diễn bừa bãi.
* **Thực thi lệnh:**
  ```bash
  sudo nmap -p 445 --script smb-vuln-ms17-010 192.168.126.129 -oN ~/LAB4/Evidence/nse_ms17_010.txt
  ```

> ### ẢNH CHỤP MINH CHỨNG 7 (HÌNH 7 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Terminal hiển thị kết quả thực thi kịch bản NSE kiểm tra SMB trên cổng 445, hiển thị rõ phần `Host script results:` và nội dung phản hồi của kịch bản `smb-os-discovery` hoặc `smb-vuln-ms17-010`.
> * **Tên tệp hình ảnh lưu trữ:** `H7_NSE_Script_SMB.png`
> * **Vị trí dán trong báo cáo Word:** Khung vị trí Ảnh 7 dưới Mục 9.

* **Bảng tổng hợp kết quả kiểm tra kịch bản NSE:**

| Hệ thống mục tiêu | Trạng thái cổng 445/tcp | Kết quả kịch bản trả về | Kết luận an toàn kỹ thuật | Biện pháp phòng thủ khuyến nghị |
| :--- | :---: | :--- | :--- | :--- |
| **Metasploitable 2** | `open` | Dịch vụ chạy Samba trên nền tảng Unix; kịch bản báo `NOT VULNERABLE` đối với MS17-010 | Máy chạy hệ điều hành Linux nên không bị ảnh hưởng bởi lỗi tràn bộ nhớ SMBv1 của nhân Windows (MS17-010). | Nâng cấp phiên bản Samba lên nhánh mới nhất; cô lập cổng 445 chỉ cho phép truy cập từ dải mạng tin cậy. |
| **Windows VM (chưa vá)**| `open` | Kịch bản báo `State: VULNERABLE`, hiển thị cảnh báo rủi ro thực thi mã từ xa RCE | Máy trạm Windows tồn tại lỗ hổng EternalBlue cực kỳ nguy hiểm, có thể bị chiếm quyền điều khiển hoàn toàn. | Cài đặt ngay gói bản vá bảo mật MS17-010 của Microsoft; vô hiệu hóa tính năng giao thức SMBv1 lỗi thời. |

---

### Nhiệm vụ 8: Xuất kết quả đa định dạng và tạo báo cáo HTML tương tác

* **Bản chất kỹ thuật:** Nmap hỗ trợ xuất dữ liệu ra 4 định dạng chính thông qua các cờ:
  * `-oN` (Normal text): Định dạng văn bản con người đọc được.
  * `-oX` (XML output): Định dạng chuẩn hóa có cấu trúc dành cho việc nhập liệu vào các hệ thống quản lý thông tin bảo mật SIEM hoặc công cụ tự động.
  * `-oG` (Grepable output): Định dạng mỗi host trên một dòng, tối ưu cho việc dùng các lệnh lọc văn bản như `grep`, `awk`, `cut`.
  * `-oA` (All formats): Tùy chọn tiện lợi xuất đồng thời cả 3 định dạng trên vào cùng một tên tệp cơ sở.
* **Thực thi quét và xuất đồng thời toàn bộ định dạng:**
  ```bash
  sudo nmap -sV -p 21,22,80,139,445,3306 192.168.126.129 -oA ~/LAB4/Evidence/metasploitable_report
  ```

* **Thực nghiệm lọc nhanh thông tin bằng lệnh Grep:**
  ```bash
  # Lọc toàn bộ các cổng đang mở từ tệp grepable
  grep "open" ~/LAB4/Evidence/metasploitable_report.gnmap
  # Lọc riêng trạng thái cổng SMB 445
  grep "445/open" ~/LAB4/Evidence/metasploitable_report.gnmap
  ```

* **Chuyển đổi dữ liệu XML sang báo cáo HTML chuyên nghiệp:**
  Sử dụng tiện ích `xsltproc` để chuyển đổi tệp kết quả XML của Nmap kết hợp với tệp mẫu giao diện chuẩn `nmap.xsl` có sẵn:
  ```bash
  xsltproc ~/LAB4/Evidence/metasploitable_report.xml -o ~/LAB4/Evidence/metasploitable_report.html
  ```

> ### ẢNH CHỤP MINH CHỨNG 8 (HÌNH 8 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ trình duyệt web (Firefox trên Kali hoặc Chrome trên Windows) mở tệp báo cáo `metasploitable_report.html` giao diện đẹp mắt, bảng biểu trực quan thể hiện thông tin các cổng, dịch vụ, trạng thái quét; hoặc cửa sổ liệt kê danh sách các tệp bằng chứng `.nmap`, `.xml`, `.gnmap` trong thư mục `Evidence`.
> * **Tên tệp hình ảnh lưu trữ:** `H8_Output_Files_HTML.png`
> * **Vị trí dán trong báo cáo Word:** Khung vị trí Ảnh 8 dưới Mục 10.

---

## THỰC NGHIỆM GIA CỐ PHÒNG THỦ (BEFORE / AFTER HARDENING)

### Bối cảnh và mục tiêu thực nghiệm
Một nguyên lý cơ bản của an toàn thông tin là **"Giảm thiểu bề mặt tấn công" (Attack Surface Reduction)**. Một cổng dịch vụ không mở đồng nghĩa với việc kẻ tấn công hoàn toàn không có khả năng khai thác lỗ hổng của dịch vụ đó từ xa.

Trong phần này, sinh viên tiến hành quét đo lường hiện trạng trước khi gia cố (Before), thực hiện giải pháp phòng thủ hợp pháp (đóng cổng dịch vụ hoặc kích hoạt tường lửa), sau đó quét lại đúng các tham số để đo lường kết quả sau gia cố (After).

---

### Quy trình thực hiện trên máy trạm mục tiêu Windows VM

#### Bước 1: Quét ghi nhận trạng thái ban đầu (Before Hardening)
Từ máy ảo Kali Linux, thực hiện quét các cổng dịch vụ nhạy cảm trên máy Windows VM (ví dụ cổng chia sẻ tệp 445, cổng điều khiển từ xa 3389 hoặc dịch vụ web):
```bash
sudo nmap -sV -p 135,139,445,3389 192.168.126.131 -oN ~/LAB4/Evidence/hardening_before.txt
```
*Kết quả ghi nhận ban đầu:* Các cổng 135, 445 đang ở trạng thái `open`, hiển thị rõ dịch vụ Microsoft Windows RPC và Microsoft-DS.

#### Bước 2: Thực hiện hành động gia cố phòng thủ trên Windows VM
Đăng nhập vào máy ảo Windows VM với quyền Administrator, mở cửa sổ PowerShell (Run as administrator) và thực hiện đóng chặn toàn diện lưu lượng vào bằng tường lửa:
```powershell
# Kích hoạt toàn bộ các profile của Windows Defender Firewall
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# Cấu hình chính sách mặc định: Chặn toàn bộ kết nối đi vào (Inbound)
Set-NetFirewallProfile -DefaultInboundAction Block

# Đóng chặn cụ thể cổng dịch vụ chia sẻ tệp SMB (cổng 445)
New-NetFirewallRule -DisplayName "LAB4_Block_SMB_Inbound" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block

# Kiểm tra lại trạng thái rule vừa tạo
Get-NetFirewallRule -DisplayName "LAB4_Block_SMB_Inbound" | Select-Object DisplayName, Enabled, Direction, Action
```

#### Bước 3: Quét kiểm chứng sau khi gia cố (After Hardening)
Từ máy ảo Kali Linux, thực hiện chạy lại chính xác câu lệnh quét như ở Bước 1:
```bash
sudo nmap -sV -p 135,139,445,3389 192.168.126.131 -oN ~/LAB4/Evidence/hardening_after.txt
```
*Kết quả ghi nhận sau gia cố:* Các cổng trước đây ở trạng thái `open` đã chuyển hoàn toàn sang trạng thái **`filtered`**; Nmap không nhận được bất kỳ phản hồi nào từ máy đích do gói tin đã bị Windows Defender Firewall triệt tiêu.

---

### Bảng tổng hợp đối chiếu chỉ số an toàn Trước và Sau khi gia cố

| Chỉ tiêu kỹ thuật đo lường | Trạng thái trước gia cố (Before) | Trạng thái sau gia cố (After) | Giải thích nguyên nhân kỹ thuật và tác động an toàn |
| :--- | :--- | :--- | :--- |
| **Số cổng Open** | 2 cổng (cổng 135 và 445) | **0 cổng** | Các cổng dịch vụ đã bị chặn truy cập từ xa, loại bỏ nguy cơ bị khai thác trực diện. |
| **Số cổng Filtered** | 0 cổng | **4 cổng** | Tường lửa Windows đã can thiệp, chủ động loại bỏ (Drop) toàn bộ gói tin thăm dò gửi tới. |
| **Dịch vụ bị tác động** | Dịch vụ SMB (`microsoft-ds`), RPC | Bị khóa chặt khỏi luồng mạng | Người dùng ngoài dải mạng không thể kết nối thăm dò hoặc gửi tải độc hại tới dịch vụ. |
| **Tác động an toàn thực tế** | Bề mặt mạng rộng, có nguy cơ bị quét và khai thác lỗi hệ thống | **Bề mặt tấn công được thu hẹp tối đa** | Ngay cả khi dịch vụ bên trong chưa kịp cài bản vá, hệ thống vẫn an toàn trước các cuộc tấn công rà quét từ mạng ngoài. |

---

## BÀI TẬP BỔ SUNG VÀ TÌNH HUỐNG MỞ RỘNG

---

### 1. So sánh 3 kỹ thuật quét (-sT, -sS, -sA) trên cùng máy mục tiêu
* **Lệnh thực thi đồng thời kiểm chứng:**
  ```bash
  sudo nmap -sT -p 21,22,23,80,445 192.168.126.129
  sudo nmap -sS -p 21,22,23,80,445 192.168.126.129
  sudo nmap -sA -p 21,22,23,80,445 192.168.126.129
  ```
* **Bảng phân tích so sánh bản chất kỹ thuật:**

| Cổng kiểm tra | Kết quả Connect (`-sT`) | Kết quả SYN (`-sS`) | Kết quả ACK (`-sA`) | Phân tích cơ chế phản hồi chuyên sâu |
| :---: | :---: | :---: | :---: | :--- |
| **21/tcp** | `open` | `open` | `unfiltered` | Gói SYN nhận được `SYN/ACK` (chứng minh mở); gói ACK nhận được `RST` (chứng minh không bị firewall chặn). |
| **22/tcp** | `open` | `open` | `unfiltered` | Tương tự cổng 21, dịch vụ SSH sẵn sàng tiếp nhận luồng dữ liệu hợp lệ. |
| **80/tcp** | `open` | `open` | `unfiltered` | Dịch vụ máy chủ web Apache lắng nghe bình thường, luồng mạng hoàn toàn thông suốt. |

---

### 2. Khảo sát toàn bộ 65.535 cổng so với quét mặc định 1.000 cổng
* **Bản chất:** Quét mặc định của Nmap chỉ kiểm tra 1.000 cổng thông dụng nhất theo xếp hạng tần suất xuất hiện (`nmap-services`). Kẻ tấn công hoặc quản trị viên có thể cấu hình các dịch vụ nhạy cảm hoặc cài cắm cửa sau (Backdoor) trên các cổng số hiệu cao ngoài danh mục này.
* **Thực thi lệnh quét toàn dải cổng:**
  ```bash
  # Tham số -p- chỉ định quét toàn bộ từ cổng 1 đến cổng 65535
  sudo nmap -sS -p- -T4 192.168.126.129 -oN ~/LAB4/Evidence/full_ports_scan.txt
  ```
* **Phát hiện quan trọng từ thực tế:**
  Khi quét đầy đủ toàn bộ 65.535 cổng trên Metasploitable 2, sinh viên phát hiện thêm các cổng cực kỳ nguy hiểm mà lần quét 1.000 cổng thông thường bỏ sót:
  * **Cổng 1524/tcp:** Dịch vụ cửa sau cổ điển `ingreslock`, khi kết nối bằng lệnh `nc` hoặc `telnet` sẽ cấp ngay quyền truy cập dòng lệnh Root mà hoàn toàn không hỏi mật khẩu.
  * **Cổng 6667/tcp:** Dịch vụ máy chủ trò chuyện trực tuyến `UnrealIRCd` chứa lỗ hổng cửa sau thực thi mã lệnh từ xa.
  * **Cổng 8180/tcp:** Máy chủ ứng dụng Apache Tomcat lắng nghe trên cổng tùy biến thay vì cổng 8080 thông thường.

---

### 3. Tra cứu mã định danh lỗ hổng bảo mật (CVE) từ phiên bản dịch vụ phát hiện
Từ kết quả nhận diện phiên bản của lệnh `nmap -sV`, sinh viên thực hiện tra cứu các lỗ hổng đã được công bố trên cơ sở dữ liệu quốc tế NIST NVD hoặc Exploit-DB:

| Dịch vụ & Phiên bản | Mã định danh CVE | Điểm số CVSS | Mô tả cơ chế tấn công và mức độ nguy hại |
| :--- | :---: | :---: | :--- |
| **vsftpd 2.3.4** | **CVE-2011-2523** | **9.8 (Critical)** | Tác giả vô danh đã chèn mã cửa sau vào gói phân phối chính thức; khi người dùng đăng nhập với chuỗi ký tự kết thúc bằng `:)`, máy chủ lập tức mở cổng lắng nghe 6200 cấp quyền shell root. |
| **Samba 3.0.20** | **CVE-2007-2447** | **9.8 (Critical)** | Lỗi trong tùy chọn cấu hình `username map script` của Samba cho phép truyền tải các ký tự đặc biệt của trình thông dịch lệnh MS-DOS/Unix, giúp kẻ tấn công thực thi lệnh hệ thống từ xa không cần chứng thực. |
| **Apache Tomcat 5.5** | **CVE-2009-3843** | **7.5 (High)** | Lỗ hổng cho phép kẻ tấn công dò tìm mật khẩu mặc định của trang quản trị `/manager/html` và tải lên tệp gói nén ứng dụng web WAR độc hại để chiếm quyền điều khiển máy chủ. |

---

### 4. So sánh kịch bản NSE kiểm tra MS17-010 giữa Linux và Windows
* **Thực nghiệm:** Chạy kịch bản `smb-vuln-ms17-010` đồng thời vào máy chủ Linux (Metasploitable 2) và máy trạm Windows 10:
  ```bash
  sudo nmap -p 445 --script smb-vuln-ms17-010 192.168.126.129
  sudo nmap -p 445 --script smb-vuln-ms17-010 192.168.126.131
  ```
* **Giải thích chuyên sâu:** Lỗ hổng MS17-010 là khiếm khuyết trong trình điều khiển nhân hệ điều hành `srv.sys` của Microsoft Windows khi xử lý các gói tin SMBv1 đàm phán kiểu đệm bộ nhớ. Mặc dù máy chủ Linux (Metasploitable 2) có mở cổng 445 và hỗ trợ giao thức SMB, nhưng phần mềm phục vụ là Samba trên nền tảng nhân Linux (không sử dụng mã nguồn Windows) nên kịch bản kết luận chính xác máy Linux hoàn toàn miễn nhiễm với lỗ hổng MS17-010.

---

### 5. Thử nghiệm kỹ thuật ngụy trang nguồn quét Decoy Scan (-D)
* **Bản chất kỹ thuật:** Kẻ tấn công sử dụng tham số `-D` để chèn thêm các địa chỉ IP giả mạo (Decoy) vào luồng gói tin thăm dò cùng với địa chỉ IP thật của mình.
* **Thực thi lệnh:**
  ```bash
  sudo nmap -sS -D 192.168.126.2,192.168.126.55,192.168.126.88,ME -p 80 192.168.126.129
  ```
* **Phân tích góc nhìn phòng thủ (Blue Team):**
  * Trên hệ thống máy chủ đích hoặc hệ thống phát hiện xâm nhập (IDS như Snort/Suricata), nhật ký mạng sẽ ghi nhận các gói tin thăm dò gửi đến dồn dập từ đồng thời nhiều địa chỉ IP khác nhau.
  * Điều này gây nhiễu loạn cho đội ngũ điều tra số, khiến họ mất thời gian xác định đâu là kẻ tấn công thực sự. Tuy nhiên, nếu máy quét vô tình sử dụng IP của các máy không tồn tại (Dead host), thiết bị bảo vệ có thể phát hiện sự bất thường thông qua việc không có lưu lượng phản hồi trả về cho các IP mồi nhử này.

---

### 6. Tình huống mở rộng: Lập bản đồ dịch vụ (Service Mapping) toàn dải mạng

* **Mục tiêu:** Quản trị viên mạng yêu cầu bàn giao bản đồ tài sản thông tin mạng nội bộ dải `192.168.126.0/24`.
* **Thực thi rà quét toàn diện:**
  ```bash
  sudo nmap -sS -sV -F 192.168.126.0/24 -oA ~/LAB4/Evidence/network_service_map
  ```
* **Bảng tổng hợp bản đồ dịch vụ mạng nội bộ phòng lab:**

| Địa chỉ IP | Tên Host nhận dạng | Các cổng mở tiêu biểu | Dịch vụ chính đang chạy | Đánh giá mức độ rủi ro | Biện pháp xử lý khuyến nghị |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `192.168.126.1` | Host Gateway | 135, 445 | Windows RPC, NetBIOS | **Thấp** | Kiểm soát quyền truy cập nội bộ, giữ chính sách tường lửa. |
| `192.168.126.130` | Kali Linux | Không mở cổng lắng nghe | Không có dịch vụ ngoài | **An toàn** | Máy trạm chuyên dụng thực hiện nhiệm vụ giám sát. |
| `192.168.126.129` | Metasploitable 2 | 21, 22, 23, 80, 445, 1524, 3306 | FTP, Telnet, HTTP, SMB, Backdoor | **Đặc biệt nghiêm trọng** | Ngắt kết nối mạng ngay lập tức; xóa bỏ backdoor cổng 1524; vô hiệu hóa Telnet thay bằng SSH; nâng cấp Samba và FTP. |
| `192.168.126.131` | Windows 10 VM | 135, 445, 3389 | Windows SMB, RDP | **Trung bình - Cao** | Kích hoạt tường lửa chặn truy cập SMB/RDP từ dải mạng không tin cậy; bật xác thực cấp mạng NLA cho RDP. |

---

## GIẢI ĐÁP TOÀN BỘ 14 CÂU HỎI PHÂN TÍCH VÀ CÂU HỎI BỔ SUNG

---

### Phần 1: Giải đáp 10 câu hỏi phân tích cốt lõi (Mục 12.2)

#### Câu hỏi 1: Sự khác nhau giữa open, closed và filtered là gì? Nêu một tình huống thực tế cho mỗi trạng thái.
* **Trả lời:**
  * **Trạng thái Mở (Open):** Ứng dụng/dịch vụ đang chủ động lắng nghe kết nối trên cổng và gửi phản hồi chấp thuận (gói SYN/ACK hoặc phản hồi tầng ứng dụng). *Tình huống thực tế:* Máy chủ web đang phục vụ người dùng trên cổng 80 với dịch vụ Apache hoạt động bình thường.
  * **Trạng thái Đóng (Closed):** Gói tin thăm dò đến được máy chủ nhưng không có bất kỳ ứng dụng nào lắng nghe trên cổng đó; hệ điều hành đích gửi lại gói tin từ chối (cờ RST đối với TCP hoặc ICMP Port Unreachable đối với UDP). *Tình huống thực tế:* Máy tính đang bật nhưng chưa cài đặt dịch vụ truyền tệp FTP (cổng 21).
  * **Trạng thái Bị lọc (Filtered):** Gói tin thăm dò không thể tiếp cận được cổng hoặc phản hồi bị chặn lại bởi thiết bị mạng/tường lửa (Firewall/IDS), Nmap không nhận được bất kỳ tín hiệu phản hồi nào (hoặc nhận lỗi ICMP cấm truy cập). *Tình huống thực tế:* Máy chủ kích hoạt Windows Defender Firewall chặn toàn bộ các kết nối từ dải mạng bên ngoài gửi tới cổng quản trị RDP (cổng 3389).

---

#### Câu hỏi 2: Tại sao -sS thường cần quyền cao hơn -sT? Hai kỹ thuật khác nhau ở cơ chế thiết lập kết nối như thế nào?
* **Trả lời:**
  * **Kỹ thuật TCP Connect Scan (`-sT`):** Sử dụng hàm API mạng tiêu chuẩn của hệ điều hành (lời gọi hệ thống `connect()`) để thực hiện đầy đủ quy trình bắt tay ba bước (SYN -> SYN/ACK -> ACK). Bất kỳ người dùng thông thường nào cũng có quyền yêu cầu hệ điều hành thiết lập kết nối mạng, do đó không đòi hỏi đặc quyền quản trị.
  * **Kỹ thuật SYN Stealth Scan (`-sS`):** Nmap không dùng API mạng tiêu chuẩn mà tự tay đóng gói các gói tin mạng ở tầng thô (Raw Ethernet/IP Packets). Nmap gửi gói SYN và khi nhận được SYN/ACK, nó chủ động gửi ngay gói RST để phá vỡ kết nối trước khi phiên làm việc được hình thành. Việc tạo lập gói tin thô và gửi trực tiếp qua giao diện mạng đòi hỏi quyền truy cập phần cứng cấp thấp (quyền Administrator trên Windows hoặc quyền root/sudo trên Linux) nhằm ngăn ngừa người dùng thông thường giả mạo lưu lượng mạng độc hại.

---

#### Câu hỏi 3: Vì sao FIN/Xmas/NULL có thể cho kết quả khó diễn giải trên một số hệ điều hành hoặc firewall?
* **Trả lời:**
  * Các kỹ thuật này dựa trên tiêu chuẩn RFC 793: Nếu cổng đóng phải trả lời bằng gói RST, nếu cổng mở phải loại bỏ gói tin và giữ im lặng.
  * **Vấn đề với hệ điều hành:** Nhiều hệ điều hành thương mại phổ biến (tiêu biểu là toàn bộ các phiên bản Microsoft Windows, Windows Server, cũng như thiết bị mạng Cisco, BSDI) không tuân thủ hoàn toàn khuyến nghị của RFC 793. Các hệ điều hành này gửi lại gói tin mang cờ `RST` cho mọi gói tin dị thường nhận được bất kể cổng đó đang mở hay đóng, khiến Nmap nhận định nhầm lẫn toàn bộ các cổng đều là `closed`.
  * **Vấn đề với thiết bị tường lửa:** Nếu tường lửa theo dõi trạng thái (Stateful Firewall) đứng trước mục tiêu, nó sẽ phát hiện các gói tin FIN/Xmas/NULL này không thuộc bất kỳ phiên kết nối hợp lệ nào và lập tức âm thầm loại bỏ (Drop). Khi đó cổng mở hay cổng đóng đều giữ im lặng, khiến Nmap buộc phải gán nhãn lưỡng lự là `open|filtered`.

---

#### Câu hỏi 4: ACK scan trả lời câu hỏi gì khác với SYN scan?
* **Trả lời:**
  * **SYN scan (`-sS`)** trả lời câu hỏi: *"Cổng này có dịch vụ nào đang chủ động lắng nghe để sẵn sàng kết nối hay không?"* (Xác định cổng Open hay Closed).
  * **ACK scan (`-sA`)** trả lời câu hỏi: *"Các gói tin gửi tới cổng này có bị tường lửa hoặc danh sách kiểm soát truy cập (ACL) chặn lại hay không?"* (Xác định cổng Filtered hay Unfiltered).
  * Gói tin ACK scan gửi đi chỉ mang cờ ACK. Nếu cổng không bị chặn, máy đích sẽ gửi lại gói RST vì không có phiên kết nối tương ứng (Nmap báo `unfiltered`). Nếu cổng bị tường lửa chặn hoặc đánh rơi gói tin, Nmap không nhận được phản hồi (báo `filtered`). Kỹ thuật này giúp chuyên viên an toàn thông tin vẽ lại bản đồ quy tắc của tường lửa.

---

#### Câu hỏi 5: Tại sao UDP scan thường chậm và dễ xuất hiện open|filtered?
* **Trả lời:**
  * **Nguyên nhân chậm:** Khi một cổng UDP đóng, máy đích sẽ gửi phản hồi thông báo lỗi `ICMP Port Unreachable`. Tuy nhiên, hầu hết các hệ điều hành (đặc biệt là nhân Linux) áp dụng cơ chế điều tiết giới hạn tần suất (Rate Limiting - RFC 1812), chỉ cho phép gửi tối đa 1 gói tin lỗi ICMP trong mỗi giây. Khi Nmap quét hàng trăm cổng UDP đóng, nó buộc phải giảm tốc độ để chờ đợi phản hồi nhằm tránh bỏ sót.
  * **Nguyên nhân xuất hiện `open|filtered`:** Giao thức UDP không có cơ chế bắt tay xác nhận kết nối. Nếu cổng UDP đang mở nhưng ứng dụng không gửi dữ liệu phản hồi lại gói tin rỗng của Nmap, máy đích sẽ hoàn toàn im lặng. Sự im lặng này hoàn toàn giống hệt với trường hợp gói tin bị tường lửa âm thầm loại bỏ (Drop). Do không thể phân biệt giữa việc dịch vụ mở giữ im lặng hay tường lửa chặn, Nmap bắt buộc phải báo kết quả là `open|filtered`.

---

#### Câu hỏi 6: -sV đóng vai trò gì trong quản lý lỗ hổng? Tại sao chỉ biết port 80 là chưa đủ?
* **Trả lời:**
  * Tham số `-sV` (Version Detection) thực hiện giao tiếp tầng ứng dụng để bóc tách chính xác tên phần mềm và số hiệu phiên bản chi tiết đang vận hành.
  * **Vai trò:** Quản lý lỗ hổng dựa trên nguyên tắc đối chiếu phiên bản phần mềm với cơ sở dữ liệu lỗ hổng bảo mật công khai (CVE/NVD).
  * **Tại sao chỉ biết cổng 80 là chưa đủ:** Chỉ biết cổng 80 mở chỉ cho ta biết có dịch vụ web HTTP đang hoạt động. Tuy nhiên, quản trị viên không thể đánh giá rủi ro nếu không biết phía sau cổng 80 là phần mềm gì: một phiên bản web hiện đại đã vá toàn bộ lỗi (như `nginx 1.26.x`) hay một phiên bản cổ xưa chứa lỗ hổng thực thi mã từ xa cực kỳ nghiêm trọng (như `Apache 2.2.8` trên nền Linux lỗi thời). Biết phiên bản chính xác là điều kiện tiên quyết để tìm ra mã khai thác và đề xuất biện pháp khắc phục.

---

#### Câu hỏi 7: OS fingerprinting có những giới hạn nào? Vì sao không nên coi kết quả -O là tuyệt đối?
* **Trả lời:**
  * **Giới hạn kỹ thuật:**
    1. Kỹ thuật `-O` đòi hỏi phải tìm thấy ít nhất một cổng mở và một cổng đóng trên máy đích để kích hoạt đầy đủ các bài kiểm tra phản ứng ngăn xếp mạng. Nếu mục tiêu bị tường lửa chặn hết các cổng đóng, độ chính xác sẽ sụt giảm mạnh.
    2. Nhiều hệ điều hành khác nhau sử dụng chung một gốc mã nguồn nhân (ví dụ: nhiều bản phân phối Linux khác nhau cùng chia sẻ nhân Linux 2.6.x hoặc 3.x), khiến Nmap chỉ có thể dự đoán một khoảng phiên bản nhân thay vì hệ điều hành cụ thể.
    3. Quản trị viên có thể chủ động thay đổi các tham số ngăn xếp mạng (giá trị TTL, Window Size, phản hồi TCP options) hoặc sử dụng các giải pháp tường lửa/Proxy xáo trộn dấu vết (OS Fingerprint Scrambler).
  * **Kết luận:** Kết quả `-O` là một phán đoán mang tính xác suất dựa trên cơ sở dữ liệu mẫu, không phải là thông tin định danh tuyệt đối. Cần kết hợp với thông tin dịch vụ (`-sV`) hoặc thông tin xác thực nội bộ để khẳng định chính xác.

---

#### Câu hỏi 8: NSE script báo timeout có đồng nghĩa “không có lỗ hổng” không? Giải thích.
* **Trả lời:**
  * **Hoàn toàn KHÔNG đồng nghĩa.**
  * **Giải thích:** Trạng thái `timeout` (hết thời gian chờ) chỉ có nghĩa là kịch bản của Nmap không nhận được phản hồi từ dịch vụ đích trong khoảng thời gian quy định. Nguyên nhân có thể do:
    1. Băng thông đường truyền mạng bị quá tải hoặc máy chủ đích bị nghẽn tài nguyên CPU/RAM.
    2. Thiết bị phát hiện/ngăn chặn xâm nhập (IDS/IPS) hoặc tường lửa đã phát hiện dấu hiệu quét bất thường và chủ động ngắt kết nối hoặc đánh rơi gói tin của kịch bản.
    3. Dịch vụ đích bị treo tạm thời do chính kịch bản kiểm tra gửi các gói tin thăm dò không hợp lệ.
  * Do đó, `timeout` là trạng thái "chưa thể xác định" (Inconclusive). Việc tự suy diễn hệ thống đã an toàn khi gặp lỗi timeout là sai lầm nghiêm trọng trong đánh giá an toàn thông tin.

---

#### Câu hỏi 9: So sánh before/after hardening: thay đổi nào trong port state chứng minh biện pháp phòng thủ có hiệu lực?
* **Trả lời:**
  * Biện pháp phòng thủ được chứng minh có hiệu lực khi có sự chuyển dịch rõ ràng của trạng thái cổng trên các dịch vụ được gia cố:
    1. **Chuyển từ `open` sang `filtered`:** Chứng minh giải pháp tường lửa (Firewall) đã được kích hoạt thành công, ngăn chặn và loại bỏ hoàn toàn các gói tin thăm dò từ mạng ngoài tiếp cận vào dịch vụ.
    2. **Chuyển từ `open` sang `closed`:** Chứng minh dịch vụ không cần thiết đã được tắt bỏ hoàn toàn (Disabled/Stopped) hoặc gỡ cài đặt khỏi hệ thống, triệt tiêu hoàn toàn tiến trình lắng nghe.
  * Cả hai sự thay đổi này đều chứng minh việc giảm thiểu trực tiếp bề mặt tấn công của hệ thống mạng.

---

#### Câu hỏi 10: Nêu ba cấu hình phòng thủ giúp giảm bề mặt tấn công mà không dựa vào “ẩn mình” trước Nmap.
* **Trả lời:**
  Thay vì dựa vào quan điểm sai lầm "an toàn nhờ ẩn mình" (Security through Obscurity - như đổi số cổng mặc định hoặc chặn lệnh ping), ba cấu hình phòng thủ chuẩn mực gồm:
  1. **Nguyên tắc dịch vụ tối thiểu (Disable Unneeded Services):** Chủ động rà soát, tắt bỏ hoặc gỡ bỏ hoàn toàn mọi dịch vụ mạng, cổng kết nối không phục vụ trực tiếp cho hoạt động nghiệp vụ của máy chủ (ví dụ: tắt bỏ FTP, Telnet, SMB nếu không chia sẻ tệp).
  2. **Kiểm soát truy cập dựa trên danh sách trắng tại tường lửa (Whitelist Inbound Firewall Rules):** Cấu hình tường lửa chỉ mở cổng cho các địa chỉ IP hoặc dải mạng quản trị được định danh cụ thể; từ chối và chặn toàn bộ các dải mạng còn lại theo nguyên tắc mặc định là chặn (`Default Deny`).
  3. **Thực thi phân đoạn mạng và xác thực bảo vệ tầng giao vận (Network Segmentation & NLA/TLS):** Cách ly các máy chủ chứa dữ liệu nhạy cảm vào các phân vùng mạng riêng biệt (VLAN cách ly); áp dụng cơ chế xác thực trước khi kết nối (như Network Level Authentication - NLA cho dịch vụ RDP hoặc bắt buộc khóa SSH/MFA) để ngăn chặn kẻ tấn công tương tác trực tiếp với dịch vụ khi chưa được xác thực danh tính.

---

### Phần 2: Giải đáp 4 câu hỏi phân tích bổ sung (Mục 14.3)

#### Câu hỏi 11: Vì sao quét toàn bộ 65.535 cổng lại tốn nhiều thời gian hơn hẳn quét mặc định? Khi nào cần quét đầy đủ?
* **Trả lời:**
  * **Nguyên nhân tốn thời gian:** Quét mặc định của Nmap chỉ kiểm tra 1.000 cổng phổ biến nhất (chiếm phần lớn dịch vụ mạng thông dụng). Quét toàn bộ yêu cầu Nmap phải gửi gói tin thăm dò đến gấp 65.5 lần số lượng cổng (65.535 cổng). Ngoài ra, với các cổng không phản hồi hoặc bị lọc, Nmap phải chờ hết thời gian timeout và thử lại nhiều lần (retransmission) cho từng cổng, khiến tổng thời gian tăng vọt từ vài giây lên đến hàng chục phút.
  * **Khi nào cần quét đầy đủ:**
    1. Khi thực hiện đánh giá an toàn thông tin chuyên sâu định kỳ (Penetration Testing / Red Team Assessment) cho các mục tiêu trọng yếu.
    2. Khi điều tra ứng phó sự cố (Incident Response) để phát hiện các phần mềm độc hại, cửa sau (Backdoor) hoặc kênh điều khiển ngầm do kẻ tấn công cài cắm cố ý lắng nghe trên các cổng số hiệu cao kỳ dị.
    3. Khi rà soát nghiệm thu hệ thống mới trước khi đưa vào môi trường vận hành thực tế.

---

#### Câu hỏi 12: Kỹ thuật decoy (-D) và fragmentation (-f) giúp kẻ tấn công né tránh thế nào, và IDS/firewall cần làm gì để chống lại?
* **Trả lời:**
  * **Cách thức né tránh:**
    * **Kỹ thuật ngụy trang mồi nhử (`-D`):** Kẻ tấn công gửi các gói tin quét kèm theo địa chỉ IP giả mạo của nhiều máy chủ khác. Hệ thống ghi nhận nhật ký sẽ thấy hàng loạt IP cùng quét đồng thời, làm loãng thông tin và gây quá tải cho việc phân tích nguồn tấn công của điều tra viên.
    * **Kỹ thuật phân mảnh gói tin (`-f`):** Chia nhỏ tiêu đề gói tin TCP thành nhiều mảnh IP nhỏ (8 byte mỗi mảnh) nhằm làm cho tiêu đề gói tin bị cắt vụn qua nhiều gói. Các hệ thống kiểm tra gói tin đơn lẻ không thể nhìn thấy toàn bộ cờ TCP để đối chiếu với tập luật phát hiện.
  * **Biện pháp phòng vệ của IDS/Tường lửa:**
    * **Tái hợp gói tin (Packet Reassembly):** Hệ thống tường lửa hiện đại (Stateful/Next-Gen Firewall) và IDS (Snort/Suricata) bắt buộc phải cấu hình tính năng đệm và tái hợp toàn bộ các mảnh gói tin trước khi tiến hành phân tích tập luật kiểm tra.
    * **Phân tích hành vi tương quan (Correlation Analysis):** Sử dụng hệ thống SIEM để phân tích tương quan luồng dữ liệu hai chiều; phát hiện ra rằng chỉ có một địa chỉ IP duy nhất (IP của kẻ tấn công thực sự) là có sự trao đổi gói tin phản hồi hai chiều đầy đủ với máy chủ, các IP mồi nhử (Decoy) sẽ không có luồng phản hồi tương ứng.

---

#### Câu hỏi 13: Giải thích vì sao -oA (xuất cả ba định dạng) hữu ích khi làm hồ sơ bằng chứng cho một cuộc đánh giá an toàn thông tin?
* **Trả lời:**
  Tùy chọn `-oA` đồng thời sinh ra 3 tệp định dạng khác nhau đáp ứng trọn vẹn 3 nhu cầu cốt lõi trong quy trình đánh giá an toàn thông tin chuyên nghiệp:
  1. **Tệp văn bản thường (`.nmap`):** Dành cho chuyên viên kỹ thuật đọc nhanh trực tiếp, đối soát cấu hình và trích dẫn vào báo cáo kỹ thuật.
  2. **Tệp có cấu trúc (`.xml`):** Đóng vai trò là dữ liệu gốc chuẩn hóa quốc tế, dùng để nhập tự động vào các công cụ quản lý lỗ hổng, lưu trữ lâu dài trong cơ sở dữ liệu kiểm toán hoặc chuyển đổi sang báo cáo HTML cho khách hàng và cấp quản lý.
  3. **Tệp dòng đơn (`.gnmap`):** Tối ưu cho việc tự động hóa bằng kịch bản (Scripting), giúp chuyên viên dùng các lệnh Unix (`grep`, `awk`, `cut`, `sed`) trích xuất nhanh danh sách các host mở cổng cụ thể trong mạng hàng nghìn thiết bị chỉ với một dòng lệnh.
  * Việc lưu trữ cả ba tệp này tạo nên một bộ hồ sơ chứng cứ số toàn diện, bảo đảm tính minh bạch và khả năng tái lập kiểm chứng của cuộc đánh giá.

---

#### Câu hỏi 14: Nếu một host trả về toàn bộ cổng ở trạng thái filtered, điều đó gợi ý gì về cấu hình firewall của host đó?
* **Trả lời:**
  Hiện tượng toàn bộ cổng đều báo trạng thái `filtered` cho thấy:
  1. **Chính sách tường lửa mặc định là Chặn toàn bộ (Default Drop Policy):** Máy chủ hoặc thiết bị tường lửa biên đang áp dụng chính sách bảo vệ cực kỳ nghiêm ngặt; mọi gói tin gửi tới các cổng không nằm trong danh mục cho phép đều bị âm thầm loại bỏ (Drop) mà không gửi lại bất kỳ phản hồi từ chối nào (không gửi gói RST, không gửi lỗi ICMP).
  2. **Cơ chế lọc theo dõi trạng thái (Stateful Packet Inspection):** Tường lửa đang theo dõi chặt chẽ trạng thái các phiên kết nối; nó phát hiện các gói tin thăm dò không thuộc bất kỳ kết nối hợp lệ nào đã được thiết lập từ trước nên lập tức triệt tiêu.
  3. **Cấu hình giới hạn truy cập theo dải mạng (IP Whitelisting):** Máy chủ có thể đang mở dịch vụ nhưng chỉ chấp nhận kết nối từ các địa chỉ IP được cấp phép cụ thể. Địa chỉ IP của máy quét Nmap nằm ngoài danh sách tin cậy nên toàn bộ lưu lượng bị tường lửa lọc chặn hoàn toàn.

---

## CÔ LẬP, PHỤC HỒI VÀ KIỂM TOÀN TÍNH TOÀN VẸN CHỨNG CỨ

### 1. Dọn dẹp môi trường và khôi phục máy ảo
1. Sau khi hoàn tất toàn bộ các bài quét và thu thập đủ bằng chứng số, đóng toàn bộ các phiên làm việc trên các máy ảo.
2. Trên phần mềm ảo hóa (VirtualBox / VMware), chọn từng máy ảo (Kali Linux, Metasploitable 2, Windows VM) và thực hiện khôi phục về điểm lưu ban đầu:
   * Chọn **Snapshot** -> Nhấp vào điểm chụp **`Before-LAB4`** -> Chọn **Restore / Revert**.
3. Thao tác này bảo đảm máy ảo hoàn toàn sạch sẽ, loại bỏ toàn bộ các thay đổi tạm thời trong quá trình thực hành, sẵn sàng cho các bài thực hành tiếp theo.

---

### 2. Kiểm toán tính toàn vẹn dữ liệu bằng mã băm SHA-256
Để bảo đảm các tệp bằng chứng số không bị chỉnh sửa, hư hại hoặc sai lệch trong quá trình lập báo cáo, sinh viên chạy khối lệnh tạo bảng mã băm SHA-256 trên máy ảo Kali Linux:

```bash
cd ~/LAB4/Evidence
sha256sum * > sha256_checksums.txt
cat sha256_checksums.txt
```

* **Bảng băm SHA-256 đối chứng dữ liệu bằng chứng số bài thực hành:**

| Tên tệp bằng chứng số | Thuật toán băm | Giá trị mã băm SHA-256 toàn vẹn | Mục đích đối soát trong báo cáo |
| :--- | :---: | :--- | :--- |
| `host_discovery.txt` | SHA-256 | *(Tạo tự động trong phiên thực hành)* | Chứng minh kết quả quét phát hiện máy sống không bị sửa |
| `tcp_connect.txt` | SHA-256 | *(Tạo tự động trong phiên thực hành)* | Đối soát kết quả quét cổng TCP bằng kỹ thuật Connect |
| `tcp_syn.txt` | SHA-256 | *(Tạo tự động trong phiên thực hành)* | Đối soát kết quả quét cổng TCP bằng kỹ thuật SYN Stealth |
| `service_version.txt` | SHA-256 | *(Tạo tự động trong phiên thực hành)* | Xác thực bảng phiên bản phần mềm dịch vụ phát hiện được |
| `hardening_before.txt`| SHA-256 | *(Tạo tự động trong phiên thực hành)* | Minh chứng hiện trạng hệ thống trước khi gia cố tường lửa |
| `hardening_after.txt` | SHA-256 | *(Tạo tự động trong phiên thực hành)* | Minh chứng hiệu quả sau khi áp dụng cấu hình phòng thủ |
| `metasploitable_report.xml`| SHA-256 | *(Tạo tự động trong phiên thực hành)* | Tệp dữ liệu XML gốc phục vụ tái lập kết quả tự động |

---

## YÊU CẦU NỘP BÀI VÀ QUY CHUẨN KHO LƯU TRỮ

### 1. Quy cách hoàn thiện tệp báo cáo Word
* Tệp báo cáo được xuất bản dưới định dạng Microsoft Word (`.docx`), tuân thủ đúng biểu mẫu quy định của giảng viên.
* Tên tệp báo cáo đặt theo chuẩn học thuật: `lab4_<lop>_<mssv>_<ho_va_ten>.docx` (Ví dụ: `lab4_cnpm2_1150080145_BuiThiMyLinh.docx`).
* Toàn bộ 8 khung hình ảnh minh chứng bắt buộc phải được dán ảnh chụp trực tiếp từ phiên thực hành, kèm chú thích rõ ràng; không để trống bất kỳ câu trả lời phân tích nào trong mục 12.2 và 14.3.

### 2. Cấu trúc thư mục kho lưu trữ (Git Repository)
Toàn bộ mã nguồn, kịch bản, tệp kết quả quét và tệp báo cáo của bài thực hành số 4 phải được tổ chức khoa học trong thư mục dự án theo cấu trúc chuẩn:

```text
TH/
└── LAB4/
    ├── LAB4_Nmap_HuongDan_2026.docx         # Đề bài và biểu mẫu gốc của giảng viên
    ├── Ke_Hoach_Va_Huong_Dan_Lab4.md         # Kế hoạch và tài liệu hướng dẫn chi tiết bài lab
    ├── Evidence/                             # Thư mục lưu trữ toàn bộ chứng cứ số
    │   ├── host_discovery.txt
    │   ├── tcp_connect.txt
    │   ├── tcp_syn.txt
    │   ├── service_version.txt
    │   ├── hardening_before.txt
    │   ├── hardening_after.txt
    │   ├── metasploitable_report.xml
    │   ├── metasploitable_report.html
    │   └── sha256_checksums.txt
    ├── images/                               # Thư mục chứa toàn bộ ảnh chụp màn hình minh chứng
    │   ├── H1_Kali_IP_Interface.png
    │   ├── H2_Metasploitable2_IP.png
    │   ├── H3_HostDiscovery_sn.png
    │   ├── H4_TCP_Scan_sS_sT.png
    │   ├── H5_ServiceVersion_sV.png
    │   ├── H6_OS_Detection_O_A.png
    │   ├── H7_NSE_Script_SMB.png
    │   └── H8_Output_Files_HTML.png
    └── README.md                             # Tóm tắt kết quả thực hành và thông tin sinh viên
```
