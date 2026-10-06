# BÀI THỰC HÀNH 5: THIẾT LẬP VÀ QUẢN TRỊ TƯỜNG LỬA BẢO VỆ MẠNG VỚI PFSENSE
### Configuring and Managing Network Security with pfSense Stateful Firewall

---

## PHẦN 1: TỔNG QUAN VÀ MỤC TIÊU BÀI THỰC HÀNH

### 1.1. Mục tiêu bài thực hành
1. **Làm chủ mô hình phân vùng mạng phòng thủ theo chiều sâu (Defense-in-Depth Topology):** Xây dựng và quản trị hạ tầng mạng doanh nghiệp ba chân độc lập gồm: Vùng mạng ngoài (WAN), Vùng mạng nội bộ (LAN) và Vùng phi quân sự (DMZ - Demilitarized Zone) trên nền tảng tường lửa pfSense.
2. **Hiểu sâu bản chất tường lửa lọc gói có trạng thái (Stateful Packet Inspection - SPI):** Nắm vững cách thức tường lửa theo dõi ngữ cảnh các phiên giao thức TCP, UDP, ICMP qua Bảng trạng thái (State Table), phân biệt rạch ròi giữa gói tin mở phiên ban đầu và gói tin phản hồi của phiên hợp lệ.
3. **Thành thạo cơ chế quản trị tập luật (Firewall Rules):** Thực hiện cấu hình luật lọc lưu lượng theo nguyên lý ưu tiên luật trùng khớp đầu tiên (First-Match Wins), thiết lập luật mặc định chặn tất cả (Default Deny), duy trì luật chống tự khóa giao diện quản trị (Anti-Lockout Rule) và phân quyền kiểm soát truy cập hạt nhân theo từng địa chỉ máy trạm.
4. **Triển khai phân vùng cô lập an toàn cho vùng DMZ:** Thiết lập cơ chế cho phép máy chủ dịch vụ trong vùng DMZ cập nhật và tải dữ liệu từ Internet thông qua cơ chế biên dịch địa chỉ mạng (Outbound NAT), đồng thời ngăn chặn triệt để nguy cơ máy chủ DMZ bị chiếm quyền điều khiển quay ngược lại tấn công vùng mạng lõi LAN.
5. **Thiết lập dịch vụ công bố ra bên ngoài qua chuyển tiếp cổng (Port Forwarding & NAT):** Cấu hình kỹ thuật biên dịch địa chỉ cổng mạng (PAT/Inbound NAT) chuyển tiếp lưu lượng từ cổng 8080 trên giao diện WAN vào cổng dịch vụ Web 80 của máy chủ Web trong DMZ; nắm vững cách thức xử lý các bộ lọc mạng riêng tư (Private/Bogon Networks) trong môi trường phòng thí nghiệm.
6. **Thực hành phương pháp kiểm chứng đúng lớp và chặn hiện tượng "xanh giả":** Tách bạch rõ ràng giữa kiểm thử tầng mạng IP và tầng dịch vụ phân giải tên miền DNS; áp dụng quy trình kiểm thử đỏ trước xanh (chứng minh kết nối thông trước khi đặt luật chặn, sau đó xóa sạch bảng trạng thái và xác nhận kết nối bị chặn hoàn toàn).
7. **Xây dựng hồ sơ kiểm toán chứng cứ khoa học:** Ghi nhận cấu hình, trích xuất nhật ký hoạt động của tường lửa, chụp ảnh minh chứng thực tế và đối soát chuỗi tin cậy bằng bảng mã băm SHA-256.

---

### 1.2. Kiến thức nền tảng cốt lõi

#### 1. Cơ chế lọc gói tin có trạng thái (Stateful Inspection) và Bảng trạng thái (State Table)
* **Tường lửa không trạng thái (Stateless / Packet Filter cổ điển):** Chỉ kiểm tra từng gói tin riêng rẽ dựa trên thông tin tiêu đề lớp mạng và lớp truyền vận (địa chỉ IP nguồn/đích, cổng nguồn/đích, cờ giao thức). Để cho phép hai máy trao đổi dữ liệu, người quản trị bắt buộc phải tạo hai luật riêng biệt: một luật cho chiều đi và một luật cho chiều về.
* **Tường lửa có trạng thái (Stateful Inspection - ví dụ pfSense sử dụng Packet Filter - PF của FreeBSD):**
  * Khi gói tin đầu tiên khởi tạo phiên đi tới cổng mạng (ví dụ gói tin mang cờ TCP SYN), tường lửa sẽ kiểm tra tuần tự tập luật từ trên xuống dưới.
  * Nếu gói tin được phép thông qua (Pass), tường lửa lập tức tạo một mục bản ghi tương ứng trong **Bảng trạng thái (State Table)** lưu trữ: IP nguồn, cổng nguồn, IP đích, cổng đích, trạng thái giao thức và số thứ tự chuỗi dữ liệu.
  * Toàn bộ các gói tin phản hồi sau đó (như TCP SYN/ACK, ACK, Data) sẽ được đối chiếu trực tiếp với bảng trạng thái và cho phép tự động đi qua mà **không cần kiểm tra lại danh sách luật**.
  * **Hệ quả kỹ thuật đặc biệt quan trọng:** Khi người quản trị thay đổi hoặc vô hiệu hóa (Disable) một luật trên pfSense, các kết nối đang hoạt động sẽ **không bị ngắt ngay lập tức** vì mục bản ghi của chúng vẫn tồn tại trong Bảng trạng thái. Để bài kiểm tra mang tính xác thực, bắt buộc phải thực hiện thao tác **Làm sạch bảng trạng thái (Reset State Table)**.

#### 2. Nguyên tắc xử lý luật tường lửa trên pfSense
* **Thứ tự xử lý từ trên xuống dưới (First-Match Wins):** Gói tin đi vào giao diện mạng sẽ được so khớp lần lượt với từng luật trong danh sách. Ngay khi trùng khớp với luật đầu tiên, hành động của luật đó (Pass/Block/Reject) sẽ được áp dụng ngay lập tức, các luật phía dưới bị bỏ qua. Do đó, các luật định danh hẹp và ưu tiên cao phải đặt ở phía trên, các luật mở rộng đặt ở phía dưới.
* **Luật chỉ áp dụng cho chiều đi vào (Inbound on Interface):** Trên pfSense, các luật cấu hình trên một thẻ giao diện mạng (ví dụ tab LAN) chỉ kiểm soát các gói tin **từ dải mạng đó đi vào cổng của tường lửa**.
* **Luật mặc định chặn toàn bộ (Default Deny Rule):** Bất kỳ gói tin nào không trùng khớp với bất kỳ luật được cấu hình rõ ràng nào trong danh sách đều tự động bị hủy bỏ (Drop trong im lặng).
* **Luật chống tự khóa quản trị (Anti-Lockout Rule):** Được tự động kích hoạt trên giao diện quản trị (mặc định là LAN), cho phép máy trạm kết nối vào cổng dịch vụ WebGUI (HTTP/HTTPS) và SSH của pfSense nhằm ngăn người quản trị tự khóa chính mình ra khỏi hệ thống.

#### 3. Cơ chế biên dịch địa chỉ mạng tự động (Outbound NAT) và Vùng phi quân sự (DMZ)
* **Automatic Outbound NAT:** pfSense tự động tạo các quy tắc chuyển đổi địa chỉ mạng nguồn (Source NAT) để các máy trạm thuộc dải mạng nội bộ riêng (RFC 1918) có thể dùng chung địa chỉ IP công cộng của cổng WAN để truy cập Internet.
* **Quy tắc đối với vùng DMZ:** Sau khi thêm cổng DMZ và gán dải mạng hợp lệ (không khai báo cổng ngõ mạng ngoài Upstream Gateway trên giao diện này), pfSense sẽ tự động cập nhật DMZ vào danh sách Automatic Outbound NAT. Máy chủ trong DMZ chỉ cần được cấp quyền bằng một luật Pass phù hợp là có thể truy cập mạng ngoài mà không cần cấu hình NAT thủ công.

---

## PHẦN 2: THIẾT KẾ MÔ HÌNH MẠNG VÀ PHÂN BỔ TÀI NGUYÊN

### 2.1. Sơ đồ kiến trúc phân vùng mạng (Multi-zone Topology)

Mô hình phòng thí nghiệm chuẩn hóa gồm 3 phân vùng mạng vật lý/ảo hóa độc lập kết nối qua máy ảo tường lửa pfSense:

```text
       [ MÁY THẬT (HOST) / MẠNG INTERNET ]
                      |
           (Bridged / NAT Network)
                      | [WAN: em0]
               +--------------+
               |   pfSense    |  (Hệ điều hành tường lửa 2.7.2)
               +--------------+
                 /          \
       [LAN: em1]            [DMZ: em2]
     (Host-Only)            (Internal: dmz-net)
          |                          |
    +-----+-----+                    |
    |           |                    |
[Domain      [LAN-Test]         [DMZ-Web]
Controller]   (Ubuntu)        (Windows Server)
 10.0.0.2     10.0.0.3           172.16.0.2
```

---

### 2.2. Bảng quy hoạch địa chỉ IP và thông số mạng chi tiết

| Thiết bị / Máy ảo | Giao diện mạng | Tên cổng pfSense | Địa chỉ IP / Mặt nạ mạng | Cổng ngõ mặc định (Gateway) | Máy chủ DNS | Vai trò kỹ thuật trong bài thực hành |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **pfSense WAN** | Cầu nối (Bridged) | `em0` | Nhận qua DHCP hoặc IP tĩnh vật lý | Gateway của mạng ngoài | Do DHCP cấp | Cổng kết nối ra Internet và giao diện công bố dịch vụ |
| **pfSense LAN** | Mạng Host-Only | `em1` | `10.0.0.1 / 255.0.0.0` (/8) | Không khai báo | Không khai báo | Cổng ngõ mặc định cho phân vùng mạng nội bộ LAN |
| **pfSense DMZ** | Mạng nội bộ ảo (`dmz-net`) | `em2` | `172.16.0.1 / 255.255.0.0` (/16) | Không khai báo | Không khai báo | Cổng ngõ mặc định cho phân vùng dịch vụ công cộng DMZ |
| **Máy thật (Host)** | Card Host-Only VirtualBox | N/A | `10.0.0.100 / 255.0.0.0` (/8) | **ĐỂ TRỐNG** | **ĐỂ TRỐNG** | Quản trị viên truy cập WebGUI pfSense, kiểm thử dịch vụ |
| **Domain Controller** | Card Host-Only VirtualBox | N/A | `10.0.0.2 / 255.0.0.0` (/8) | `10.0.0.1` | `10.0.0.2` (Forwarder: 8.8.8.8) | Máy chủ Active Directory, DNS Server nội bộ, máy trạm LAN ưu tiên |
| **LAN-Test** | Card Host-Only VirtualBox | N/A | `10.0.0.3 / 255.0.0.0` (/8) | `10.0.0.1` | `8.8.8.8` hoặc `10.0.0.2` | Máy trạm nội bộ thứ hai dùng kiểm chứng phân quyền lọc gói tin |
| **DMZ-Web** | Mạng nội bộ ảo (`dmz-net`) | N/A | `172.16.0.2 / 255.255.0.0` (/16) | `172.16.0.1` | `8.8.8.8` (sau khi mở luật) | Máy chủ dịch vụ Web IIS chịu sự cô lập của tường lửa |

---

### 2.3. Khuyến nghị phân bổ tài nguyên phần cứng máy thật

* **Yêu cầu máy vật lý:** Bộ nhớ trong RAM từ 16 GB trở lên, dung lượng ổ đĩa trống từ 80 GB đến 100 GB, đã kích hoạt công nghệ ảo hóa phần cứng (Intel VT-x hoặc AMD-V) trong BIOS/UEFI.
* **Mức cấp phát bộ nhớ RAM cho các máy ảo:**
  * **pfSense CE:** Cấp phát 2 GB RAM (tối thiểu 1 GB nếu máy thật hạn chế).
  * **Domain Controller (Windows Server 2019/2022):** Cấp phát 2 GB RAM.
  * **DMZ-Web (Windows Server 2019/2022 + dịch vụ IIS):** Cấp phát 2 GB RAM.
  * **LAN-Test (Ubuntu Server tối giản Minimal):** Cấp phát 1 GB RAM (giúp tiết kiệm tài nguyên tối đa so với việc chạy 2 máy ảo Windows Server cùng lúc).
* **Lưu ý tối ưu vận hành:** Không cần thiết phải khởi chạy đồng thời tất cả các máy ảo trong mọi thời điểm:
  * Trong Tình huống 2 và 3: Chỉ cần chạy `pfSense` + `Domain Controller` + `LAN-Test`.
  * Trong Tình huống 4: Chỉ cần chạy `pfSense` + `Domain Controller` + `DMZ-Web`.
  * Trong Tình huống 5: Chỉ cần chạy `pfSense` + `DMZ-Web` (Máy thật đóng vai trò Client ngoài Internet).

---

### 2.4. Cảnh báo an toàn và phòng ngừa xung đột dải mạng

* **Quy tắc vàng về dải mạng WAN:** Dải mạng dùng cho cổng WAN của pfSense **tuyệt đối không được trùng lặp** với dải mạng LAN (`10.0.0.0/8`) hoặc dải mạng DMZ (`172.16.0.0/16`).
* **Tránh bẫy card mạng NAT mặc định của VirtualBox:** Chế độ NAT mặc định của Oracle VirtualBox tự động cấp dải mạng `10.0.2.0/24`. Dải mạng này nằm trọn bên trong không gian địa chỉ `10.0.0.0/8` của LAN, gây hiện tượng xung đột định tuyến nghiêm trọng khiến pfSense không thể chuyển tiếp dữ liệu ra ngoài.
* **Giải pháp xử lý:**
  * **Phương án tối ưu 1 (Ưu tiên):** Cấu hình Adapter 1 (WAN) của pfSense ở chế độ **Bridged Adapter** (Cầu nối trực tiếp với card mạng Wi-Fi hoặc Ethernet vật lý của máy thật).
  * **Phương án dự phòng 2:** Nếu mạng vật lý của máy thật không cho phép dùng Bridged, tạo một mạng ảo NAT riêng biệt không xung đột trong VirtualBox (Tools -> Network Manager -> NAT Networks -> Tạo mạng `192.168.250.0/24`), sau đó gán Adapter 1 vào mạng NAT riêng này.
* **Quy tắc đối với card mạng Host-Only trên máy thật:**
  * Đặt địa chỉ IP tĩnh: `10.0.0.100`, mặt nạ mạng: `255.0.0.0`.
  * **Tuyệt đối để trống mục Default Gateway và DNS** trên card mạng này. Nếu đặt Gateway trỏ về pfSense (`10.0.0.1`), toàn bộ lưu lượng duyệt web hàng ngày của hệ điều hành máy thật sẽ bị đổi hướng định tuyến qua máy ảo, dẫn tới mất kết nối mạng ngoài.

---

## PHẦN 3: NGUỒN TẢI CHÍNH THỨC VÀ XÁC MINH TOÀN VẸN CHUỖI TIN CẬY

### 3.1. Nguồn tải tệp cài đặt chính thức từ Netgate
* **Trang chủ tài liệu phiên bản phát hành:** `https://docs.netgate.com/pfsense/en/latest/releases/versions.html`
* **Kho lưu trữ chính thức (Mirror Netgate):** `https://atxfiles.netgate.com/mirror/downloads/`
* **Tệp nén bộ cài đặt ISO:** `pfSense-CE-2.7.2-RELEASE-amd64.iso.gz`
* **Tệp mã băm kiểm chứng chính thức:** `pfSense-CE-2.7.2-RELEASE-amd64.iso.gz.sha256`

---

### 3.2. Quy trình kiểm tra tính toàn vẹn bằng PowerShell

Chuỗi thao tác bảo đảm chuỗi tin cậy: **Tải tệp nén -> Xác thực mã băm SHA-256 -> Giải nén bằng 7-Zip -> Gắn tệp ISO vào phần mềm ảo hóa**.

1. Đặt tệp `pfSense-CE-2.7.2-RELEASE-amd64.iso.gz` đã tải vào thư mục làm việc: `d:\University\Y4-5 AT&BM HTTT\TH\LAB5\LAB5-pfSense\INSTALL_MEDIA\`.
2. Mở cửa sổ lệnh **PowerShell** trên Windows và thực thi lệnh băm:
   ```powershell
   Get-FileHash -Algorithm SHA256 "d:\University\Y4-5 AT&BM HTTT\TH\LAB5\LAB5-pfSense\INSTALL_MEDIA\pfSense-CE-2.7.2-RELEASE-amd64.iso.gz"
   ```
3. **Mã băm chuẩn mực kỳ vọng từ Netgate:**
   ```text
   883fb7bc64fe548442ed007911341dd34e178449f8156ad65f7381a02b7cd9e4
   ```
4. Có thể chạy kịch bản kiểm tra tự động đã chuẩn bị sẵn trong thư mục:
   ```powershell
   cd "d:\University\Y4-5 AT&BM HTTT\TH\LAB5\LAB5-pfSense"
   Unblock-File .\VERIFY_SHA256.ps1
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\VERIFY_SHA256.ps1
   ```
5. *Tiêu chuẩn đạt:* Giá trị băm thực tế trùng khớp 100% với chuỗi băm chuẩn. Chỉ khi băm hợp lệ mới tiến hành giải nén để lấy tệp `pfSense-CE-2.7.2-RELEASE-amd64.iso`.

---

## PHẦN 4: QUY TRÌNH THỰC HÀNH VÀ CẤU HÌNH CHI TIẾT

---

### TÌNH HUỐNG 1: KHỞI TẠO MÁY ẢO, GÁN CỔNG VÀ THIẾT LẬP KẾT NỐI BAN ĐẦU

#### Mục tiêu kỹ thuật
Cài đặt hoàn chỉnh hệ điều hành tường lửa pfSense CE 2.7.2 trên máy ảo, ánh xạ chính xác 3 card mạng tương ứng với ba phân vùng chức năng, thiết lập địa chỉ IP tĩnh trên bàn điều khiển văn bản và đăng nhập thành công vào giao diện quản trị WebGUI qua giao thức bảo mật HTTPS.

#### Bước 1: Tạo máy ảo và gắn cấu hình card mạng trên phần mềm ảo hóa
1. Mở phần mềm ảo hóa (Oracle VirtualBox hoặc VMware Workstation).
2. Tạo máy ảo mới đặt tên: `pfSense-Firewall`:
   * **Hệ điều hành:** BSD, phiên bản FreeBSD (64-bit).
   * **Bộ nhớ RAM:** 2048 MB (2 GB).
   * **Ổ cứng ảo:** 20 GB (chuẩn VDI hoặc VMDK).
3. Thiết lập thông số 3 card mạng cho máy ảo theo đúng thứ tự:
   * **Adapter 1 (WAN):** Chọn **Bridged Adapter** (trỏ tới card mạng vật lý đang kết nối Internet của máy thật).
   * **Adapter 2 (LAN):** Chọn **Host-only Adapter** (chọn mạng Host-Only kết nối với máy thật).
   * **Adapter 3 (DMZ):** Chọn **Internal Network**, đặt tên mạng nội bộ là: `dmz-net`.
4. Gắn tệp đĩa quang `pfSense-CE-2.7.2-RELEASE-amd64.iso` vào ổ CD/DVD ảo và khởi động máy ảo.

#### Bước 2: Cài đặt hệ điều hành pfSense
1. Khi màn hình khởi động xuất hiện, nhấn phím **Enter** để chấp nhận thỏa thuận bản quyền (Copyright and distribution notice).
2. Chọn tùy chọn **Install pfSense** và nhấn **OK**.
3. Chọn bố cục bàn phím: **Continue with default keymap** (bàn phím tiếng Anh chuẩn US).
4. Thiết lập phân vùng đĩa: Chọn kiểu phân vùng **Auto (ZFS)** hoặc **Auto (UFS) Guided** (khuyến nghị chọn UFS Guided cho bài thực hành ảo hóa để cài đặt nhanh chóng và đơn giản).
5. Sau khi trình cài đặt chép xong dữ liệu, xuất hiện câu hỏi "Open a shell to make manual modifications?", chọn **No**.
6. Chọn **Reboot** để hoàn tất cài đặt.
7. **Rất quan trọng:** Tháo ngay tệp ISO khỏi ổ đĩa quang ảo để tránh máy ảo tự động khởi động lại vào trình cài đặt.

#### Bước 3: Ánh xạ cổng giao tiếp và gán địa chỉ IP trên màn hình điều khiển
Sau khi pfSense khởi động lần đầu, màn hình điều khiển hiển thị cấu hình nhận diện cổng mạng:
1. Trình cài đặt hỏi: `Should VLANs be set up now [y|n]?` -> Nhập `n` và nhấn **Enter**.
2. Nhập tên cổng mạng cho giao diện WAN: Nhập `em0` (hoặc `vtnet0` nếu dùng chuẩn VirtIO) -> Nhấn **Enter**.
3. Nhập tên cổng mạng cho giao diện LAN: Nhập `em1` (hoặc `vtnet1`) -> Nhấn **Enter**.
4. Nhập tên cổng mạng cho giao diện Optional 1 (DMZ): Nhập `em2` (hoặc `vtnet2`) -> Nhấn **Enter**.
5. Xác nhận cấu hình: `Do you want to proceed [y|n]?` -> Nhập `y` và nhấn **Enter**.
6. Khi hệ thống hiển thị bảng trình đơn gồm 16 chức năng quản trị, chọn **Chức năng 2: Set interface(s) IP address**:
   * **Cấu hình giao diện LAN:**
     * Nhập số `2` (chọn interface LAN).
     * `Configure IPv4 address LAN via DHCP?` -> Nhập `n`.
     * `Enter the new LAN IPv4 address:` -> Nhập `10.0.0.1`.
     * `Enter the new LAN IPv4 subnet bit count (1 to 31):` -> Nhập `8` (tương ứng mặt nạ `255.0.0.0`).
     * `For a WAN, enter the IPv4 upstream gateway address:` -> Nhấn **Enter** để trống.
     * `Configure IPv6 address LAN via DHCP6?` -> Nhập `n` và nhấn **Enter** để trống.
     * `Do you want to enable the DHCP server on LAN?` -> Nhập `n` (để máy chủ Domain Controller sau này tự quản lý dịch vụ cấp phát nếu cần, hoặc cấu hình IP tĩnh để kiểm soát tuyệt đối).
     * `Do you want to revert to HTTP as the webConfigurator protocol?` -> Nhập `n` (duy trì giao thức bảo mật HTTPS).
   * **Cấu hình giao diện DMZ (OPT1):**
     * Chọn lại **Chức năng 2**, nhập số `3` (chọn interface OPT1).
     * Đặt địa chỉ IPv4: `172.16.0.1`.
     * Nhập số bit mặt nạ mạng: `16` (tương ứng mặt nạ `255.255.0.0`).
     * Upstream gateway: Nhấn **Enter** để trống.
     * Tắt IPv6 và không bật DHCP server.

#### Bước 4: Đăng nhập giao diện đồ họa WebGUI từ máy thật
1. Trên máy thật Windows, mở **Network Connections** (`ncpa.cpl`).
2. Nhấp chuột phải vào card mạng ảo **VirtualBox Host-Only Ethernet Adapter** -> Chọn **Properties** -> Nhấp đúp vào **Internet Protocol Version 4 (TCP/IPv4)**:
   * **IP address:** `10.0.0.100`
   * **Subnet mask:** `255.0.0.0`
   * **Default gateway:** Để trống
   * **DNS Server:** Để trống
3. Mở trình duyệt web trên máy thật, truy cập đường dẫn: `https://10.0.0.1`
4. Trình duyệt xuất hiện cảnh báo chứng chỉ số tự ký (Self-signed certificate), nhấp vào nút **Advanced** -> Chọn **Proceed to 10.0.0.1 (unsafe)**.
5. Đăng nhập bằng tài khoản quản trị mặc định của pfSense:
   * **Username:** `admin`
   * **Password:** `pfsense`
6. Hoàn thành trình hướng dẫn thiết lập ban đầu (Setup Wizard): Đặt tên máy chủ `pfsense.localdomain`, khai báo máy chủ phân giải tên miền (DNS Server: `8.8.8.8`), đổi mật khẩu quản trị mới và bấm **Reload**.
7. Vào mục **Interfaces** -> **OPT1**: Tích chọn **Enable Interface**, đổi tên mô tả từ `OPT1` thành `DMZ`, giữ nguyên các thông số IP tĩnh và nhấn **Save** -> **Apply Changes**.

---

### TÌNH HUỐNG 2: VÔ HIỆU HÓA LUẬT MẶC ĐỊNH LAN, BẢO VỆ ANTI-LOCKOUT VÀ QUẢN TRỊ BẢNG TRẠNG THÁI

#### Mục tiêu kỹ thuật
Nắm vững bản chất nguyên lý bảo mật "Mặc định chặn toàn bộ" (Default Deny), kiểm soát tập luật trên giao diện mạng nội bộ LAN, loại bỏ các luật mở rộng tự do ban đầu nhưng bảo đảm giữ nguyên luật chống tự khóa để không làm mất quyền quản trị WebGUI, đồng thời làm chủ thao tác làm sạch bảng trạng thái kết nối.

#### Cơ chế kỹ thuật cảnh báo
Mặc định khi mới cài đặt, pfSense tự động bổ sung luật `Default allow LAN to any` cho phép mọi máy tính trong dải LAN thoải mái đi ra mọi nơi trên thế giới. Trong môi trường doanh nghiệp chuẩn mực, luật này phải bị vô hiệu hóa để thiết lập các chính sách kiểm soát có mục đích.

#### Quy trình thao tác từng bước
1. Trên giao diện WebGUI, truy cập trình đơn: **Firewall** -> **Rules** -> Thẻ **LAN**.
2. Quan sát danh sách luật hiện có trên thẻ LAN:
   * **Anti-Lockout Rule:** Luật đặc quyền nằm trên cùng, có biểu tượng chiếc khiên màu đỏ/vàng, cho phép truy cập WebGUI trên cổng 80/443. **Tuyệt đối không được xóa hoặc tắt luật này**.
   * **Default allow LAN to any (IPv4):** Cho phép toàn bộ gói tin IPv4 đi bất kỳ đâu.
   * **Default allow LAN to any (IPv6):** Cho phép toàn bộ gói tin IPv6 đi bất kỳ đâu.
3. Nhấp vào biểu tượng vô hiệu hóa (nút tích xanh chuyển sang màu xám) đối với cả hai luật `Default allow LAN to any` (cả bản IPv4 và IPv6).
4. Nhấn nút **Apply Changes** ở đầu trang để cập nhật cấu hình vào nhân hệ thống.
5. **Thao tác bắt buộc xóa bảng trạng thái (Reset State Table):**
   * Truy cập trình đơn: **Diagnostics** -> **States** -> Chọn thẻ **Reset States**.
   * Nhấp chọn vào nút **Reset** và xác nhận trên hộp thoại cảnh báo.
   * *Ý nghĩa kỹ thuật:* Hành động này lập tức hủy bỏ toàn bộ các phiên kết nối đang mở sẵn từ trước, buộc toàn bộ các luồng dữ liệu mới phát sinh phải được so sánh lại từ đầu với danh sách luật mới.
6. **Tạo luật kiểm soát mạng LAN do quản trị viên tự định nghĩa:**
   * Quay trở lại **Firewall** -> **Rules** -> Thẻ **LAN**.
   * Nhấp vào nút **Add** (thêm luật xuống dưới danh sách):
     * **Action:** `Pass` (Cho phép).
     * **Interface:** `LAN`.
     * **Address Family:** `IPv4`.
     * **Protocol:** `Any`.
     * **Source:** `LAN net` (Toàn bộ các máy thuộc dải mạng LAN 10.0.0.0/8).
     * **Destination:** `any` (Đi bất kỳ địa chỉ nào ngoài Internet).
     * **Description:** `LAB-Rule: Allow LAN net to Internet`.
   * Nhấn **Save** -> **Apply Changes** -> Sau đó thực hiện lại thao tác **Reset States**.

#### Kiểm chứng đúng lớp
* Từ máy ảo Domain Controller (`10.0.0.2`), mở giao diện dòng lệnh PowerShell kiểm tra kết nối mạng tầng IP:
  ```powershell
  ping 8.8.8.8 -n 4
  ```
  *Kết quả:* Nhận phản hồi `Reply from 8.8.8.8: bytes=32 time=... TTL=...` (Chứng minh luật Pass hoạt động thành công).
* Thử nghiệm vô hiệu hóa luật `LAB-Rule: Allow LAN net to Internet`, bấm Apply Changes và Reset States, sau đó chạy lại lệnh ping:
  *Kết quả:* Màn hình báo lỗi `Request timed out` (Chứng minh cơ chế Default Deny lập tức chặn gói tin và chứng minh thao tác Reset States có hiệu lực thực sự).

---

### TÌNH HUỐNG 3: CẤU HÌNH PHÂN QUYỀN ĐẶC QUYỀN - CHỈ CHO PHÉP MỘT MÁY TRẠM LAN ĐI INTERNET

#### Mục tiêu kỹ thuật
Triển khai chính sách an ninh mạng thực tế: Trong phân vùng mạng nội bộ LAN, chỉ duy nhất máy chủ quản lý miền (Domain Controller - `10.0.0.2`) được phép kết nối ra ngoài Internet để đồng bộ thời gian và cập nhật bản vá; toàn bộ các máy trạm người dùng khác (đại diện là máy ảo LAN-Test - `10.0.0.3`) bị cấm hoàn toàn lưu lượng ra ngoài biên giới mạng.

#### Nguyên lý thiết kế luật
Áp dụng nguyên tắc ưu tiên từ trên xuống dưới (First-Match Wins):
* **Luật 1 (Nằm trên):** Cho phép máy chủ nguồn có địa chỉ IP đơn lẻ `10.0.0.2` được phép đi tới đích `any`.
* **Luật 2 (Nằm ngay bên dưới):** Chặn toàn bộ dải mạng nguồn `LAN net` đi tới đích `any`.

#### Quy trình thao tác từng bước
1. Trên giao diện WebGUI pfSense, vào **Firewall** -> **Rules** -> Thẻ **LAN**.
2. Vô hiệu hóa luật tổng quát `LAB-Rule: Allow LAN net to Internet` đã tạo ở Tình huống 2.
3. Tạo **Luật ưu tiên 1 (Pass cho Domain Controller):**
   * Nhấp nút **Add** (thêm lên đầu danh sách):
     * **Action:** `Pass`.
     * **Interface:** `LAN`.
     * **Address Family:** `IPv4`.
     * **Protocol:** `Any`.
     * **Source:** Chọn kiểu `Single host or alias`, nhập chính xác địa chỉ: `10.0.0.2`.
     * **Destination:** `any`.
     * **Description:** `LAB-Rule: Allow DC 10.0.0.2 only to Internet`.
   * Nhấn **Save**.
4. Tạo **Luật chặn 2 (Block các máy còn lại trong LAN):**
   * Nhấp nút **Add** (thêm xuống phía dưới luật vừa tạo):
     * **Action:** `Block`.
     * **Interface:** `LAN`.
     * **Address Family:** `IPv4`.
     * **Protocol:** `Any`.
     * **Source:** Chọn `LAN net`.
     * **Destination:** `any`.
     * **Description:** `LAB-Rule: Block all other LAN hosts`.
   * Nhấn **Save**.
5. Kiểm tra thứ tự hiển thị trên danh sách luật của thẻ LAN:
   * Luật `Anti-Lockout Rule` luôn nằm ở vị trí cao nhất.
   * Tiếp theo là luật `Pass: Source 10.0.0.2 -> Destination any`.
   * Tiếp theo là luật `Block: Source LAN net -> Destination any`.
6. Nhấn nút **Apply Changes**.
7. Truy cập **Diagnostics** -> **States** -> **Reset States** -> Bấm **Reset** để xóa sạch các phiên kết nối cũ.

#### Kiểm chứng đối chứng khoa học (Before / After và Đối chứng song song)
* **Phép thử trên máy chủ Domain Controller (`10.0.0.2`):**
  ```powershell
  ping 8.8.8.8 -n 4
  ```
  *Kết quả kỳ vọng:* Thành công 100%, nhận đủ 4 gói tin phản hồi vì lưu lượng khớp ngay với Luật 1 (Pass).
* **Phép thử trên máy trạm LAN-Test (`10.0.0.3`):**
  ```bash
  ping -c 4 8.8.8.8
  ```
  *Kết quả kỳ vọng:* Thất bại 100%, thông báo `Destination Host Unreachable` hoặc gói tin bị hủy hoàn toàn (100% packet loss) do gói tin không khớp Luật 1 mà bị rơi vào Luật 2 (Block).
* **Kiểm tra trên nhật ký tường lửa:**
  * Vào **Status** -> **System Logs** -> Thẻ **Firewall**.
  * Quan sát thấy các dòng bản ghi có biểu tượng dấu gạch chéo đỏ với địa chỉ nguồn `10.0.0.3` gửi tới cổng đích 53/80/443 của mạng ngoài bị chặn bởi luật `Block all other LAN hosts`.

---

### TÌNH HUỐNG 4: THIẾT LẬP VÀ CHỨNG MINH CÔ LẬP VÙNG PHI QUÂN SỰ DMZ AN TOÀN

#### Mục tiêu kỹ thuật
Vùng DMZ là nơi chứa các máy chủ công khai phục vụ người dùng bên ngoài, do đó tiềm ẩn nguy cơ cao bị tin tặc xâm nhập. Mục tiêu của tình huống này là thiết lập chính sách cho phép máy chủ Web DMZ (`172.16.0.2`) được phép đi ra Internet để cập nhật phần mềm, nhưng **tuyệt đối không được phép khởi tạo bất kỳ kết nối nào quay trở lại vùng mạng nội bộ LAN (`10.0.0.0/8`)**.

#### Quy trình chuẩn bị máy chủ DMZ-Web và kích hoạt phản hồi ICMP
1. Khởi động máy ảo **DMZ-Web** (hệ điều hành Windows Server 2019/2022, đã gắn card mạng vào `Internal Network: dmz-net`).
2. Cấu hình địa chỉ IP tĩnh trên máy DMZ-Web:
   * **IP Address:** `172.16.0.2`
   * **Subnet Mask:** `255.255.0.0`
   * **Default Gateway:** `172.16.0.1` (trỏ về cổng DMZ của pfSense)
   * **DNS Server:** Tạm thời để trống.
3. Cài đặt dịch vụ máy chủ Web IIS trên máy DMZ-Web bằng lệnh PowerShell (Run as Administrator):
   ```powershell
   Install-WindowsFeature -name Web-Server -IncludeManagementTools
   ```
4. Kiểm tra dịch vụ Web đã hoạt động tại chỗ:
   ```powershell
   curl.exe http://localhost
   ```
   *Kết quả:* Xuất ra mã nguồn HTML của trang chào mừng Microsoft IIS.

#### Áp dụng quy tắc kiểm thử "Đỏ trước khi Xanh" (Chứng minh kết nối thông trước khi chặn)
*Vấn đề kỹ thuật:* Mặc định hệ điều hành Windows Server kích hoạt tường lửa nội bộ chặn gói tin ICMP Echo Request. Nếu ta thử nghiệm lệnh ping thất bại, đó có thể là do Windows Firewall trên máy đích chặn chứ không phải do pfSense. Do đó, bắt buộc phải làm thông kết nối trước:
1. Trên máy chủ **Domain Controller (`10.0.0.2`)**, mở PowerShell với quyền Administrator và chạy lệnh mở tạm thời cổng ICMP:
   ```powershell
   netsh advfirewall firewall add rule name="LAB-Allow-ICMPv4-Echo" protocol=icmpv4:8,any dir=in action=allow
   ```
2. Trên WebGUI pfSense, vào **Firewall** -> **Rules** -> Thẻ **DMZ**:
   * Tạo một luật thử nghiệm cơ bản:
     * **Action:** `Pass`.
     * **Interface:** `DMZ`.
     * **Protocol:** `Any`.
     * **Source:** `DMZ net`.
     * **Destination:** `any`.
     * **Description:** `Baseline: Allow DMZ to all`.
   * Nhấn **Save** -> **Apply Changes** -> Thực hiện **Reset States**.
3. Từ máy chủ **DMZ-Web (`172.16.0.2`)**, thực hiện lệnh ping tới máy chủ Domain Controller trong LAN:
   ```powershell
   ping 10.0.0.2 -n 4
   ```
   *Kết quả nghiệm thu bước nền (Baseline):* Lệnh ping **bắt buộc phải nhận phản hồi thành công**. Điều này chứng minh đường truyền vật lý, định tuyến mạng và tường lửa đích đều đã thông suốt.

#### Thiết lập chính sách cô lập DMZ chuẩn mực
Bây giờ tiến hành siết chặt an ninh mạng: Đặt luật chặn DMZ truy cập LAN ở vị trí **nằm trên** luật cho phép ra Internet:
1. Trên WebGUI pfSense, vào **Firewall** -> **Rules** -> Thẻ **DMZ**.
2. Nhấp nút **Add** (thêm luật lên phía trên luật Pass hiện có):
   * **Action:** `Block`.
   * **Interface:** `DMZ`.
   * **Address Family:** `IPv4`.
   * **Protocol:** `Any`.
   * **Source:** `DMZ net` (Toàn bộ máy trong dải 172.16.0.0/16).
   * **Destination:** `LAN net` (Toàn bộ không gian mạng nội bộ 10.0.0.0/8).
   * **Description:** `LAB-Rule: Block DMZ from accessing LAN`.
3. Nhấn **Save**.
4. Kiểm tra thứ tự tập luật trên thẻ DMZ:
   * **Vị trí 1 (Trên cùng):** `Block | Source: DMZ net -> Destination: LAN net`
   * **Vị trí 2 (Bên dưới):** `Pass  | Source: DMZ net -> Destination: any`
5. Nhấn **Apply Changes**.
6. **Thực hiện thao tác tối quan trọng:** Vào **Diagnostics** -> **States** -> **Reset States** -> Bấm **Reset**.

#### Nghiệm thu kết quả cô lập
1. **Kiểm tra chiều cô lập từ DMZ vào LAN:**
   * Từ máy **DMZ-Web (`172.16.0.2`)**, chạy lệnh:
     ```powershell
     ping 10.0.0.2 -n 4
     ```
   * *Kết quả:* Lệnh ping lập tức bị dừng lại và báo `Request timed out` 100%. Gói tin đã bị luật Block số 1 chặn đứng trước khi có thể đi vào phân vùng mạng LAN.
2. **Kiểm tra chiều DMZ đi ra ngoài Internet:**
   * Từ máy **DMZ-Web (`172.16.0.2`)**, chạy lệnh:
     ```powershell
     ping 8.8.8.8 -n 4
     ```
   * *Kết quả:* Phản hồi thành công bình thường. Gói tin đi ra Internet không thuộc đích đến `LAN net`, do đó không bị chặn bởi luật 1 mà tiếp tục trôi xuống luật 2 (`Pass DMZ net to any`) và được cơ chế Outbound NAT tự động dịch địa chỉ ra ngoài.
3. Sau khi kết thúc thực hành, có thể xóa luật mở ICMP tạm thời trên Domain Controller bằng lệnh:
   ```powershell
   netsh advfirewall firewall delete rule name="LAB-Allow-ICMPv4-Echo"
   ```

---

### TÌNH HUỐNG 5: CẤU HÌNH CHUYỂN TIẾP CỔNG (PORT FORWARDING) CÔNG BỐ WEB SERVER RA NGOÀI MẠNG WAN

#### Mục tiêu kỹ thuật
Triển khai kỹ thuật biên dịch địa chỉ cổng mạng (Port Address Translation - PAT) hay còn gọi là Port Forwarding: Chuyển hướng lưu lượng truy cập từ người dùng bên ngoài vào địa chỉ IP của cổng WAN tại cổng dịch vụ `8080` tự động đi xuyên qua tường lửa vào cổng chuẩn `80` của máy chủ dịch vụ Web IIS (`172.16.0.2`) đang nằm an toàn trong vùng DMZ.

#### Điều kiện tiên quyết trước khi thực hiện
* Máy chủ `DMZ-Web` (`172.16.0.2`) đang hoạt động và dịch vụ IIS đang lắng nghe bình thường trên cổng 80.
* Xác nhận cổng WAN của pfSense đã nhận địa chỉ IP và giao tiếp bình thường với máy thật.
* *Xử lý bộ lọc mạng riêng tư (Private & Bogon Networks):* Trong môi trường thực tế, cổng WAN nối trực tiếp ra Internet nên pfSense mặc định chặn toàn bộ các địa chỉ IP nội bộ RFC 1918 (dải 10.x, 172.16.x, 192.168.x). Tuy nhiên trong môi trường bài thực hành, cổng WAN nhận IP từ card mạng Bridged/NAT của máy thật (vốn là dải IP private). Do đó, **bắt buộc phải tắt hai bộ lọc này trên cổng WAN để máy thật có thể kết nối thử nghiệm**:
  1. Trên WebGUI, vào **Interfaces** -> **WAN**.
  2. Cuộn chuột xuống cuối trang, tìm mục **Reserved Networks**.
  3. **Bỏ tích chọn** ở cả hai ô:
     * `Block private networks and loopback addresses`
     * `Block bogon networks`
  4. Nhấn **Save** -> **Apply Changes**.

#### Quy trình cấu hình Port Forwarding trên WebGUI
1. Truy cập trình đơn: **Firewall** -> **NAT** -> Thẻ **Port Forward**.
2. Nhấp vào nút **Add** để tạo quy tắc chuyển tiếp mới:
   * **Interface:** `WAN` (Cổng lắng nghe lưu lượng từ mạng ngoài).
   * **Address Family:** `IPv4`.
   * **Protocol:** `TCP` (Dịch vụ web HTTP chạy trên nền giao thức truyền vận TCP).
   * **Destination:** `WAN address` (Gói tin gửi tới chính địa chỉ IP của cổng WAN).
   * **Destination port range:**
     * `From port:` Chọn `Custom`, nhập số cổng: `8080`.
     * `To port:` Nhập số cổng: `8080`.
   * **Redirect target IP:** Nhập địa chỉ của máy chủ Web trong DMZ: `172.16.0.2`.
   * **Redirect target port:** Chọn `HTTP` (hoặc nhập số cổng: `80`).
   * **Description:** `LAB-Rule: Port Forward WAN:8080 to DMZ-Web:80`.
   * **Filter rule association:** Giữ nguyên tùy chọn mặc định là `Add associated filter rule` (pfSense sẽ tự động tạo một luật Pass tương ứng bên thẻ Firewall Rules của WAN).
3. Nhấn nút **Save**.
4. Nhấn nút **Apply Changes**.
5. Vào **Diagnostics** -> **States** -> **Reset States** -> Bấm **Reset**.

#### Nghiệm thu kết quả từ máy thật ngoài mạng
1. Xác định địa chỉ IP hiện tại của cổng WAN trên pfSense (xem tại bảng điều khiển chính Dashboard của WebGUI hoặc mục `Interfaces -> WAN`, ví dụ: `192.168.1.150` hoặc `192.168.250.10`).
2. Trên máy thật Windows (Host), mở trình duyệt web hoặc công cụ PowerShell.
3. Truy cập đường dẫn:
   ```text
   http://<ĐỊA_CHỈ_IP_WAN_PFSENSE>:8080
   ```
4. Hoặc kiểm tra bằng dòng lệnh PowerShell:
   ```powershell
   curl.exe -I "http://<ĐỊA_CHỈ_IP_WAN_PFSENSE>:8080"
   ```
5. *Tiêu chuẩn đạt:* Trình duyệt hiển thị nguyên vẹn trang chủ đồ họa của Microsoft IIS được cung cấp bởi máy chủ `172.16.0.2` trong vùng DMZ. Dòng phản hồi tiêu đề HTTP xuất hiện: `HTTP/1.1 200 OK` cùng định danh máy chủ `Server: Microsoft-IIS/...`.

---

## PHẦN 5: MA TRẬN CA KIỂM THỬ VÀ NGHIỆM THU ĐÚNG LỚP

Để bài thực hành đạt độ chính xác khoa học, người thực hành phải thực hiện đầy đủ 6 ca kiểm thử độc lập, phân định rành mạch giữa kiểm tra định tuyến tầng mạng (Network/IP) và phân giải tầng ứng dụng (DNS):

| STT | Tên ca kiểm thử | Điều kiện tiên quyết | Câu lệnh thực thi | Kết quả kỳ vọng đạt chuẩn | Ý nghĩa kỹ thuật nghiệm thu |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC1** | Xác minh toàn vẹn tệp cài đặt pfSense | Đã tải tệp nén `.iso.gz` từ mirror Netgate | `Get-FileHash -Algorithm SHA256 <tệp.iso.gz>` | Trùng khớp chuỗi: `883fb7bc64fe548442ed...` | Bảo đảm bộ cài nguyên bản, không bị mã độc chèn vào |
| **TC2** | Kiểm tra thông mạng tầng IP từ LAN ra Internet | Luật `Allow LAN net to Internet` đang bật | `ping 8.8.8.8 -n 4` (thực thi trên Domain Controller) | Phản hồi đầy đủ 4/4 gói tin, không rớt gói | Chứng minh đường truyền và cơ chế Outbound NAT hoạt động |
| **TC3** | Phân tách kiểm tra dịch vụ phân giải tên miền DNS | Đã hoàn thành thông mạng tầng IP (TC2) | `Resolve-DnsName example.com -Server 8.8.8.8` hoặc `nslookup example.com 8.8.8.8` | Trả về địa chỉ IP hợp lệ của tên miền `example.com` | Xác nhận luồng DNS truy vấn độc lập không phụ thuộc vào trạng thái ping ICMP |
| **TC4** | Kiểm thử phân quyền chọn lọc một trạm LAN | Đã kích hoạt Luật 1 (Pass 10.0.0.2) và Luật 2 (Block LAN net) | 1. Trên DC (`10.0.0.2`): `ping 8.8.8.8`<br>2. Trên LAN-Test (`10.0.0.3`): `ping 8.8.8.8` | 1. Máy DC phản hồi thành công 100%<br>2. Máy LAN-Test bị chặn, rớt gói 100% | Chứng minh hiệu lực của nguyên lý xử lý luật từ trên xuống dưới |
| **TC5** | Kiểm chứng cô lập vùng DMZ về mạng lõi LAN | Đã mở luật ICMP trên DC và đặt luật Block DMZ->LAN ở trên Pass | Từ DMZ-Web (`172.16.0.2`):<br>1. `ping 10.0.0.2`<br>2. `ping 8.8.8.8` | 1. Ping tới 10.0.0.2 báo `Timed out`<br>2. Ping tới 8.8.8.8 nhận lời đáp bình thường | Chứng minh DMZ hoàn toàn bị cô lập khỏi LAN nhưng vẫn đi được Internet |
| **TC6** | Nghiệm thu chuyển tiếp cổng Port Forwarding | Dịch vụ IIS trên DMZ-Web đang chạy, luật NAT WAN:8080 -> 172.16.0.2:80 đã lưu | Từ máy thật (Host):<br>`curl.exe -I http://<IP_WAN>:8080` | Nhận mã trạng thái `HTTP/1.1 200 OK` từ máy chủ IIS | Chứng minh tính năng chuyển tiếp cổng PAT và liên kết luật lọc tự động thành công |

---

## PHẦN 6: BÀI HỌC KINH NGHIỆM VÀ XỬ LÝ SỰ CỐ KỸ THUẬT

1. **Hiện tượng "Xanh giả" do không làm sạch Bảng trạng thái (State Table):**
   * *Triệu chứng:* Sau khi vô hiệu hóa luật cho phép mạng LAN hoặc chuyển sang luật Block, máy trạm nội bộ vẫn tiếp tục ping được ra ngoài trong vài chục giây đến vài phút.
   * *Nguyên nhân:* Tường lửa có trạng thái pfSense duy trì bản ghi của phiên cũ trong State Table. Miễn là phiên chưa hết thời gian chờ (Timeout) và các gói tin tiếp tục được gửi đều đặn, tường lửa sẽ cho qua mà không kiểm tra lại tập luật mới.
   * *Khắc phục:* Luôn luôn thực hiện thao tác **Diagnostics -> States -> Reset States** sau mỗi lần thay đổi quy tắc kiểm thử.
2. **Hiện tượng mất kết nối WebGUI do sửa đổi sai luật trên thẻ LAN:**
   * *Nguyên nhân:* Vô tình tắt hoặc xóa luật `Anti-Lockout Rule` hoặc tạo luật Block dải mạng đặt ở vị trí cao hơn luật quản trị.
   * *Khắc phục:* Đăng nhập vào cửa sổ điều khiển màn hình máy ảo (Console), chọn **Chức năng 15: Restore recent configuration** để khôi phục lại phiên bản cấu hình hợp lệ trước đó, hoặc chọn **Chức năng 11: Restart webConfigurator**.
3. **Hiện tượng Port Forward không thể truy cập từ máy thật:**
   * *Nguyên nhân 1:* Cổng WAN của pfSense đang tích chọn hai tùy chọn bảo vệ `Block private networks` và `Block bogon networks`. Vì mạng máy thật cấp cho cổng WAN thuộc dải mạng nội bộ riêng (RFC 1918), tường lửa sẽ tự động loại bỏ mọi gói tin kết nối vào từ máy thật.
   * *Nguyên nhân 2:* Chưa xóa bảng trạng thái sau khi lưu cấu hình NAT.
4. **Hiện tượng nhầm lẫn giữa lỗi đường truyền mạng và lỗi phân giải tên miền:**
   * *Triệu chứng:* Lệnh `ping google.com` thất bại, sinh viên vội vã kết luận tường lửa chặn truy cập Internet.
   * *Khắc phục:* Thử nghiệm bằng địa chỉ IP thô (`ping 8.8.8.8`). Nếu ping IP thành công nhưng ping tên miền thất bại, sự cố nằm ở cấu hình máy chủ DNS hoặc luật lọc cổng UDP 53, không phải lỗi định tuyến tường lửa.
5. **Cảnh báo không clone trực tiếp máy chủ Domain Controller để làm máy trạm:**
   * Máy ảo Domain Controller chứa các thông số định danh bảo mật duy nhất của hệ thống thư mục Active Directory (như Security Identifier - SID, cơ sở dữ liệu NTDS.dit). Nếu thực hiện nhân bản (Clone) thông thường mà không chạy tiện ích chuẩn hóa hệ thống (Sysprep) hoặc quy trình ảo hóa DC chuyên biệt của Microsoft, hệ thống mạng sẽ xảy ra xung đột định danh nghiêm trọng làm tê liệt các dịch vụ xác thực.

---

## PHẦN 7: CÂU HỎI THẢO LUẬN VÀ PHÂN TÍCH CHUYÊN SÂU

### Câu hỏi 1: Phân tích sự khác biệt căn bản giữa Tường lửa lọc gói không trạng thái (Stateless) và Tường lửa có trạng thái (Stateful)?
* **Trả lời:**
  * Tường lửa không trạng thái kiểm tra từng gói tin một cách độc lập dựa trên bảng quy tắc cố định mà không lưu giữ ký ức về các gói tin trước đó. Do đó, người quản trị bắt buộc phải tạo cả luật cho chiều gửi đi (Outbound) và luật cho chiều trả lời (Inbound), làm tăng gấp đôi số lượng luật và dễ để lọt lỗ hổng bảo mật nếu kẻ tấn công giả mạo cờ truyền vận (ví dụ tự ý bật cờ ACK để vượt qua bộ lọc).
  * Tường lửa có trạng thái (như pfSense) duy trì Bảng trạng thái trong bộ nhớ RAM để giám sát toàn bộ vòng đời của một phiên kết nối từ khi bắt đầu (SYN), truyền dữ liệu đến khi đóng phiên (FIN/RST). Khi gói tin khởi tạo hợp lệ được thông qua, toàn bộ lưu lượng phản hồi đúng quy chuẩn giao thức sẽ tự động được chấp nhận mà không cần mở thêm bất kỳ luật chiều về nào, mang lại hiệu năng cao và độ bảo mật vượt trội.

### Câu hỏi 2: Tại sao luật Anti-Lockout Rule lại được pfSense gán cố định ở vị trí trên cùng của giao diện LAN mà không cho phép thay đổi thứ tự?
* **Trả lời:**
  * pfSense vận hành theo nguyên lý "Luật đầu tiên trùng khớp sẽ quyết định" (First-Match Wins). Nếu người quản trị được phép di chuyển luật Anti-Lockout xuống dưới hoặc tạo một luật chặn toàn bộ dải mạng đặt lên trên, hệ thống sẽ ngay lập tức cắt đứt mọi kết nối vào cổng 80/443 của WebGUI.
  * Việc gán cứng luật này ở vị trí ưu tiên tối cao trên cổng quản lý mặc định là cơ chế bảo vệ dự phòng thiết yếu, giúp người quản trị không bao giờ bị rơi vào tình cảnh tự cô lập chính mình khỏi giao diện điều hành máy chủ.

### Câu hỏi 3: Phân tích cơ chế hoạt động của kỹ thuật Chuyển tiếp cổng (Port Forwarding) và sự cần thiết của việc tự động liên kết luật lọc (Filter rule association)?
* **Trả lời:**
  * Port Forwarding là sự kết hợp giữa hai cơ chế: Biên dịch địa chỉ mạng đích (Destination NAT - đổi IP đích từ WAN sang IP nội bộ của máy chủ dịch vụ) và Mở cổng trên tường lửa (Firewall Filter Rule).
  * Nếu chỉ cấu hình chuyển đổi địa chỉ NAT mà không có luật mở cổng tương ứng trên giao diện WAN, gói tin sau khi được chuyển hướng vẫn sẽ bị bộ lọc mặc định chặn lại (Default Deny). Tính năng `Add associated filter rule` giúp pfSense tự động sinh ra một luật Pass đồng bộ trên thẻ Firewall WAN, bảo đảm lưu lượng hợp lệ được đi xuyên qua mượt mà mà không đòi hỏi thao tác cấu hình thủ công rườm rà.

---

## PHẦN 8: HỒ SƠ CHỨNG CỨ VÀ BẢNG MÃ BĂM TOÀN VẸN DỮ LIỆU

### Danh mục tệp chứng cứ thực hành
Toàn bộ kết quả thực hành được lưu trữ trong thư mục `TH/LAB5/Evidence/`:
1. `TC1_sha256_verify_output.txt`: Nhật ký kiểm tra mã băm SHA-256 tệp nén bộ cài đặt pfSense.
2. `TC2_ping_internet_success.txt`: Kết quả kiểm thử thông mạng tầng IP từ máy chủ nội bộ.
3. `TC3_dns_resolution.txt`: Kết quả phân giải tên miền độc lập qua máy chủ DNS 8.8.8.8.
4. `TC4_selective_access_comparison.txt`: Nhật ký đối chứng giữa trạm được cấp quyền (10.0.0.2) và trạm bị chặn (10.0.0.3).
5. `TC5_dmz_isolation_evidence.txt`: Minh chứng kiểm thử cô lập vùng DMZ (thất bại khi ping về LAN nhưng thành công khi ping ra ngoài).
6. `TC6_port_forward_iis_result.txt`: Tiêu đề HTTP phản hồi từ máy chủ IIS khi truy cập qua cổng 8080 của WAN.
7. Thư mục ảnh chụp màn hình minh chứng các bước cấu hình: `images/` (từ H1 đến H8).
