# BÀI THỰC HÀNH 6: TÍCH HỢP TƯỜNG LỬA PFSENSE VỚI ACTIVE DIRECTORY VÀ QUẢN TRỊ CHÍNH SÁCH TRUY CẬP
### Integrating pfSense Firewall with Active Directory and Managing Network Access Policies

---

## PHẦN 1: TỔNG QUAN VÀ MỤC TIÊU BÀI THỰC HÀNH

### 1.1. Mục tiêu bài thực hành
1. **Làm chủ mô hình phân vùng mạng nâng cao cho doanh nghiệp:** Xây dựng tường lửa pfSense độc lập phục vụ Bài thực hành 6 với cấu hình 4 cổng mạng độc lập: Vùng mạng ngoài (WAN), Vùng mạng quản trị riêng biệt (MGMT), Vùng mạng miền nội bộ (LAN-DOMAIN) và Vùng phi quân sự (DMZ).
2. **Tích hợp xác thực tập trung Active Directory qua giao thức LDAP:** Kết nối pfSense với máy chủ điều khiển miền (Domain Controller - DC01) qua giao thức truy cập thư mục hạng nhẹ (LDAP cổng TCP/389), cấu hình cây định danh (Base DN, Search Scope, Authentication Containers, Bind DN) và kiểm tra xác thực người dùng miền.
3. **Triển khai Cổng xác thực mạng (Captive Portal) tầng dịch vụ:** Thiết lập cổng kiểm soát phiên người dùng trên vùng LAN, ủy quyền xác thực người dùng về cơ sở dữ liệu Active Directory, nắm vững sự khác biệt giữa phiên xác thực danh tính trên cổng và cơ chế lọc gói tin tầng mạng.
4. **Quản trị quy tắc lọc gói tin thông qua danh mục định danh (Aliases) và lập lịch thời gian (Schedules):** Nhóm máy trạm, máy chủ và cổng dịch vụ bằng Alias; thiết lập lịch kiểm soát theo khung giờ hành chính và giờ nghỉ trưa; hiểu rõ nguyên lý bắt buộc phải có luật Chặn (Block) nằm phía dưới luật Cho phép (Pass) có gắn lịch.
5. **Thực thi và kiểm chứng 7 kịch bản chính sách an toàn thông tin:**
   * Kịch bản 1: Phân quyền máy trạm riêng lẻ (Client-A bị chặn trang tuyển dụng `JOB_SITE`, truy cập bình thường trang cơ bản `GENERAL_SITE`).
   * Kịch bản 2: Áp dụng chính sách chung cho toàn nhóm máy trạm (Cấm trang độc hại/nhạy cảm `RESTRICTED_SITE` cho cả Client-A và Client-B).
   * Kịch bản 3: Kiểm soát truy cập theo thời gian (Client-B chỉ được truy cập mạng xã hội `SOCIAL_SITE` trong giờ nghỉ trưa).
   * Kịch bản 4: Giới hạn dịch vụ theo thời gian (Chỉ cho phép lưu lượng Web HTTP/HTTPS ra ngoài trong giờ hành chính, chặn toàn bộ dịch vụ khác như ping/ICMP).
   * Kịch bản 5: Phân vùng cô lập an toàn DMZ hai chiều (LAN truy cập được trang web DMZ nhưng DMZ tuyệt đối bị chặn không được khởi tạo kết nối vào LAN).
   * Kịch bản 6: Đo kiểm và đối sánh chuyên sâu giữa hai hành vi Chặn im lặng (Block/Drop) và Từ chối có phản hồi (Reject).
   * Kịch bản 7: Giám sát nhật ký tường lửa thời gian thực (Firewall Log) và kiểm tra Bảng trạng thái (State Table), thực hành kỹ thuật xóa trạng thái (Reset States) để triệt tiêu hiện tượng "xanh giả".
6. **Xây dựng báo cáo kiểm toán bảo mật chuẩn mực:** Hoàn thiện bảng đo kiểm thực tế, trả lời trọn vẹn 12 câu hỏi phân tích bản chất hệ thống và đóng gói tệp sao lưu cấu hình `config.xml` đạt chuẩn nộp bài.

---

### 1.2. Kiến thức nền tảng cốt lõi

#### 1. Giao thức LDAP và Cây thư mục Active Directory
* **Bản chất LDAP (Lightweight Directory Access Protocol):** Giao thức mạng hoạt động trên cổng TCP 389 (hoặc TCP 636 đối với LDAPS mã hóa qua TLS/SSL), dùng để truy vấn và chỉnh sửa thông tin các đối tượng người dùng, máy tính, nhóm trong cơ sở dữ liệu thư mục tập trung Active Directory Domain Services (AD DS).
* **Cấu trúc phân cấp Cây định danh (Distinguished Name - DN):**
  * **Base DN:** Gốc của không gian tên miền cần tìm kiếm (ví dụ: `DC=lab6,DC=test`).
  * **Authentication Containers:** Đơn vị tổ chức (Organizational Unit - OU) giới hạn phạm vi tìm kiếm tài khoản người dùng (ví dụ: `OU=LAB6-Users,DC=lab6,DC=test`).
  * **Search Scope:** Phạm vi tìm kiếm từ vùng chứa. Chế độ **Entire Subtree** cho phép pfSense quét đệ quy qua toàn bộ các thư mục con bên trong container, giúp tìm thấy tài khoản ngay cả khi người quản trị phân cấp nhiều OU lồng nhau.
  * **Bind DN:** Tài khoản được pfSense sử dụng để đăng nhập vào Active Directory trước khi thực hiện truy vấn danh bạ. Theo nguyên tắc đặc quyền tối thiểu (Least Privilege), bắt buộc dùng tài khoản dịch vụ thông thường (`svc_pfsense_ldap`), tuyệt đối không dùng tài khoản quản trị miền (`Administrator`).
  * **Thuộc tính ánh xạ:** Thuộc tính định danh tài khoản người dùng trong Active Directory chuẩn Microsoft là `samAccountName`, thuộc tính nhóm là `cn`, và thuộc tính thành viên nhóm là `memberOf`.

#### 2. Cơ chế Captive Portal và Giới hạn lọc gói tin trên pfSense
* **Nguyên lý hoạt động của Captive Portal:**
  * Khi máy trạm trên vùng LAN chưa được cấp quyền mở trình duyệt gửi yêu cầu HTTP (TCP cổng 80), pfSense tự động can thiệp và chuyển hướng (HTTP Redirect 302) yêu cầu đó về trang đăng nhập của Cổng xác thực.
  * Người dùng nhập tên đăng nhập và mật khẩu. pfSense đóng vai trò máy khách LDAP gửi yêu cầu xác thực về Domain Controller DC01.
  * Khi DC01 xác nhận thông tin hợp lệ, pfSense ghi nhận địa chỉ IP và địa chỉ vật lý MAC của máy trạm vào bảng phiên hợp lệ (Active Captive Portal Sessions) và mở quyền chuyển tiếp gói tin cho địa chỉ IP đó.
* **Giới hạn kỹ thuật cốt lõi cần ghi nhớ:**
  * Captive Portal chỉ đóng vai trò **cửa kiểm soát định danh tại thời điểm truy cập ban đầu**.
  * Bản thân bộ lọc gói tin lõi của pfSense (Packet Filter - PF trên FreeBSD) hoạt động ở Lớp 3 (Mạng) và Lớp 4 (Truyền vận). Bộ lọc này **hoàn toàn không hỗ trợ đưa tên tài khoản người dùng Active Directory trực tiếp vào trường Nguồn (Source) của một luật tường lửa chuẩn**.
  * Mọi chính sách phân quyền cho từng đối tượng (như cấm Client-A vào trang tuyển dụng nhưng cho phép Client-B) bắt buộc phải được ánh xạ qua **Địa chỉ IP tĩnh** hoặc gán cố định IP qua DHCP theo địa chỉ MAC.

#### 3. Bảng trạng thái (State Table) và Nguyên tắc xử lý luật First-Match
* **Bộ lọc có trạng thái (Stateful Inspection):** Khi một luồng kết nối hợp lệ được chấp thuận bởi một luật Cho phép (Pass), một mục bản ghi mới sẽ được tạo trong Bảng trạng thái (State Table). Toàn bộ các gói tin tiếp theo thuộc phiên này (kể cả chiều đi và chiều phản hồi) sẽ được cho qua tự động mà không cần kiểm tra lại danh sách luật.
* **Quy tắc khớp luật đầu tiên (First-Match Wins):**
  * Gói tin đi vào giao diện mạng sẽ được so khớp tuần tự từ trên xuống dưới.
  * Luật đầu tiên có điều kiện trùng khớp sẽ lập tức quyết định số phận gói tin (Cho phép, Chặn, hoặc Từ chối). Toàn bộ các luật phía dưới bị bỏ qua.
  * Vì vậy, luật cụ thể, phạm vi hẹp và luật Chặn đặc hiệu bắt buộc phải đặt ở **vị trí trên cùng**; luật mở rộng và luật mặc định đặt ở **dưới cùng**.
* **Ý nghĩa của thao tác Xóa trạng thái (Reset States):** Sau khi chỉnh sửa thứ tự hoặc thay đổi hành động của luật từ Cho phép sang Chặn, các kết nối đang duy trì vẫn tiếp tục thông suốt vì bản ghi trong Bảng trạng thái chưa hết hạn. Để kiểm chứng luật mới có hiệu lực ngay lập tức, bắt buộc phải vào `Diagnostics -> States -> Reset States`.

#### 4. Cơ chế Lập lịch thời gian (Time-Based Rules / Schedules)
* Khi một khung thời gian trong lịch trình không còn hiệu lực (Inactive), pfSense sẽ **loại bỏ luật đó ra khỏi tập luật xử lý** (coi như luật không tồn tại).
* Luật không tự động đảo ngược hành động từ Cho phép thành Chặn. Do đó, muốn thiết lập chính sách "Chỉ cho phép vào mạng xã hội trong giờ nghỉ, ngoài giờ thì cấm", người quản trị bắt buộc phải tạo 2 luật liền kề:
  1. Luật 1 (Ưu tiên cao hơn): `Action: Pass`, đích đến là `SOCIAL_SITE`, gắn lịch `LUNCH_WINDOW`.
  2. Luật 2 (Ưu tiên kế tiếp ngay bên dưới): `Action: Block`, đích đến là `SOCIAL_SITE`, không gắn lịch (áp dụng mọi thời điểm).

#### 5. Bản chất đối chiếu giữa Chặn (Block) và Từ chối (Reject)
* **Block (Tương đương DROP):** Tường lửa hủy bỏ gói tin trong im lặng, hoàn toàn không gửi bất kỳ phản hồi nào về cho máy nguồn. Máy trạm gửi gói tin thăm dò không nhận được phản hồi sẽ phải thử lại nhiều lần (TCP Retransmission) cho đến khi hết thời gian chờ (Connection Timeout - thường kéo dài từ 20 đến 60 giây).
* **Reject:** Tường lửa hủy bỏ gói tin nhưng chủ động gửi ngay một gói tin thông báo lỗi ngược lại cho máy nguồn:
  * Đối với giao thức TCP: Gửi lại gói tin cờ `[RST, ACK]` (Reset), làm ứng dụng máy trạm lập tức đóng kết nối và báo lỗi kết nối bị từ chối (Connection Refused) trong tích tắc (dưới 1 giây).
  * Đối với giao thức UDP/ICMP: Gửi lại gói tin ICMP báo lỗi không thể đến được cổng đích (ICMP Port Unreachable - Type 3, Code 3).

---

## PHẦN 2: THIẾT KẾ MÔ HÌNH MẠNG VÀ PHÂN BỔ TÀI NGUYÊN

### 2.1. Sơ đồ kiến trúc mạng 4 phân vùng độc lập (Topology LAB 6)

Mô hình mạng phòng thí nghiệm được tách biệt thành 4 phân vùng ảo hóa hoàn toàn riêng biệt trên Oracle VM VirtualBox nhằm bảo đảm an toàn và không gây nhiễu sang môi trường các bài thực hành khác:

```text
               +---------------------------------------------------+
               |               MÁY VẬT LÝ (HOST)                   |
               |     Giao diện Quản trị WebGUI: 192.168.56.1/24    |
               +---------------------------------------------------+
                                        | (Host-Only: 192.168.56.0/24)
                                        |
       [ MẠNG INTERNET ]                | [Adapter 2: MGMT]
              |                         | 192.168.56.254/24
      (NAT Network: LAB6-WAN)           |
              | 192.168.250.0/24        |
              | [Adapter 1: WAN]        |
       +------+-------------------------+------+
       |           TƯỜNG LỬA PFSENSE           | (pfSense CE 2.7.x)
       +------+-------------------------+------+
              | [Adapter 3: LAN]        | [Adapter 4: DMZ]
              | 10.6.0.1/24             | 172.16.6.1/24
              | (Internal: lab6-lan)    | (Internal: lab6-dmz)
              |                         |
     +--------+--------+                |
     |        |        |                |
  [DC01]  [Client-A] [Client-B]     [DMZ-WEB] (Ubuntu Server + Nginx)
 .10.6.0.10 .10.6.0.21 .10.6.0.22      |-- 172.16.6.10 (GENERAL_SITE)
 (AD DS/  (Windows) (Windows)         |-- 172.16.6.20 (JOB_SITE)
  DNS)                                |-- 172.16.6.30 (SOCIAL_SITE)
                                      +-- 172.16.6.40 (RESTRICTED_SITE)
```

---

### 2.2. Bảng quy hoạch thông số mạng và địa chỉ IP chuẩn hóa

| Thiết bị / Máy ảo | Giao diện | Card VirtualBox | Địa chỉ IPv4 / Mặt nạ | Cổng ngõ (Gateway) | Máy chủ DNS | Mục đích & Vai trò kỹ thuật |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **pfSense WAN** | `vtnet0` / `em0` | NAT Network: `LAB6-WAN` | Nhận động DHCP (`192.168.250.x/24`) | Cổng ngõ NAT Network | Theo nhà mạng/NAT | Cung cấp kết nối Internet upstream cho môi trường phòng thí nghiệm |
| **pfSense MGMT** | `vtnet1` / `em1` | Host-Only (`192.168.56.0/24`) | `192.168.56.254 / 24` | Không khai báo | Không khai báo | Giao diện quản trị WebGUI chuyên dụng, tách rời khỏi lưu lượng người dùng |
| **pfSense LAN** | `vtnet2` / `em2` | Internal: `lab6-lan` | `10.6.0.1 / 24` | Không khai báo | Không khai báo | Cổng ngõ mặc định cho máy chủ miền và các máy trạm doanh nghiệp |
| **pfSense DMZ** | `vtnet3` / `em3` | Internal: `lab6-dmz` | `172.16.6.1 / 24` | Không khai báo | Không khai báo | Cổng ngõ mặc định cho phân vùng máy chủ web mô phỏng |
| **Máy thật (Host)** | Card Host-Only | Host-Only Adapter | `192.168.56.1 / 24` | **ĐỂ TRỐNG** | **ĐỂ TRỐNG** | Truy cập giao diện quản trị WebGUI pfSense tại `https://192.168.56.254` |
| **DC01** | Card mạng 1 | Internal: `lab6-lan` | `10.6.0.10 / 24` | `10.6.0.1` | `10.6.0.10` (Forwarder: 8.8.8.8) | Máy chủ Active Directory (`lab6.test`), máy chủ DNS miền nội bộ |
| **Client-A** | Card mạng 1 | Internal: `lab6-lan` | `10.6.0.21 / 24` | `10.6.0.1` | `10.6.0.10` | Máy trạm nhân viên A, kiểm thử xác thực LDAP tài khoản `sv_a` |
| **Client-B** | Card mạng 1 | Internal: `lab6-lan` | `10.6.0.22 / 24` | `10.6.0.1` | `10.6.0.10` | Máy trạm nhân viên B, kiểm thử xác thực LDAP tài khoản `sv_b` |
| **DMZ-WEB (.10)** | Cổng vật lý | Internal: `lab6-dmz` | `172.16.6.10 / 24` | `172.16.6.1` | `8.8.8.8` | Địa chỉ IP chính: Mô phỏng website nghiệp vụ chuẩn (`GENERAL_SITE`) |
| **DMZ-WEB (.20)** | Cổng ảo phụ | Internal: `lab6-dmz` | `172.16.6.20 / 24` | `172.16.6.1` | `8.8.8.8` | Địa chỉ phụ 1: Mô phỏng nhóm website tìm việc làm (`JOB_SITE`) |
| **DMZ-WEB (.30)** | Cổng ảo phụ | Internal: `lab6-dmz` | `172.16.6.30 / 24` | `172.16.6.1` | `8.8.8.8` | Địa chỉ phụ 2: Mô phỏng nhóm website mạng xã hội (`SOCIAL_SITE`) |
| **DMZ-WEB (.40)** | Cổng ảo phụ | Internal: `lab6-dmz` | `172.16.6.40 / 24` | `172.16.6.1` | `8.8.8.8` | Địa chỉ phụ 3: Mô phỏng nhóm website bị cấm (`RESTRICTED_SITE`) |

---

### 2.3. Khuyến nghị phân bổ tài nguyên phần cứng và tối ưu vận hành

* **Yêu cầu phần cứng máy tính vật lý:**
  * Bộ nhớ trong (RAM): Tối thiểu 16 GB (khuyến nghị 24 GB nếu bật đồng thời hai máy trạm Windows Client).
  * Ổ đĩa lưu trữ: Tối thiểu 60 GB dung lượng trống chuẩn SSD.
* **Mức cấp phát bộ nhớ RAM khuyến nghị cho từng máy ảo:**
  * `pfSense-LAB6`: Cấp phát 1.5 GB - 2 GB RAM.
  * `DC01 (Windows Server)`: Cấp phát 2 GB - 3 GB RAM.
  * `DMZ-WEB (Ubuntu Server)`: Cấp phát 1 GB - 1.5 GB RAM.
  * `Client-A (Windows 10/11)`: Cấp phát 3 GB - 4 GB RAM.
  * `Client-B (Windows 10/11)`: Cấp phát 3 GB - 4 GB RAM.
* **Chiến lược tối ưu hóa để vận hành mượt mà trên máy RAM 16 GB:**
  * **Không nhất thiết phải bật đồng thời toàn bộ máy ảo trong mọi giai đoạn.**
  * *Giai đoạn cấu hình nền tảng:* Chỉ cần bật `pfSense-LAB6` + `DC01` + `DMZ-WEB` (Tổng tiêu hao khoảng 5.5 GB RAM).
  * *Giai đoạn kiểm thử Client-A:* Tắt hoặc Tạm dừng (Pause/Save State) Client-B; chỉ bật `Client-A`.
  * *Giai đoạn kiểm thử Client-B:* Tắt Client-A và khởi động `Client-B`.

---

## PHẦN 3: CÁC BƯỚC THIẾT LẬP MÔI TRƯỜNG PHÒNG THÍ NGHIỆM

### 3.1. Thiết lập hạ tầng mạng trên Oracle VirtualBox

1. **Tạo mạng NAT Network phục vụ cổng WAN:**
   * Mở VirtualBox -> Chọn **Tools** -> **Network Manager** -> Thẻ **NAT Networks**.
   * Nhấp **Create** -> Đặt tên: `LAB6-WAN`.
   * Cấu hình tham số: Subnet IPv4: `192.168.250.0/24`, tích chọn **Enable DHCP**.
2. **Kiểm tra card mạng Host-Only phục vụ quản trị:**
   * Trong **Network Manager** -> Thẻ **Host-only Networks**.
   * Xác nhận card `VirtualBox Host-Only Ethernet Adapter` mang địa chỉ IP `192.168.56.1`, mặt nạ mạng `255.255.255.0`, **tắt hoàn toàn DHCP Server** trên card này.
3. **Cấu hình 4 Adapter cho máy ảo pfSense:**
   * **Adapter 1:** Chế độ `NAT Network`, tên mạng `LAB6-WAN`.
   * **Adapter 2:** Chế độ `Host-Only Adapter`, tên card `VirtualBox Host-Only Ethernet Adapter`.
   * **Adapter 3:** Chế độ `Internal Network`, tên mạng `lab6-lan`.
   * **Adapter 4:** Chế độ `Internal Network`, tên mạng `lab6-dmz`.

---

### 3.2. Cấu hình gán giao diện mạng và địa chỉ IP trên Console pfSense

1. Khởi động máy ảo pfSense. Tại màn hình giao diện dòng lệnh chính, chọn phím `1` (**Assign Interfaces**):
   * Giao diện hỏi cấu hình VLANs: Nhập `n`.
   * Nhập tên interface cho WAN: Nhập tên cổng ứng với Adapter 1 (ví dụ: `em0` hoặc `vtnet0`).
   * Nhập tên interface cho LAN: Nhập tên cổng ứng với Adapter 2 (ví dụ: `em1` hoặc `vtnet1`) -> Tạm thời dùng cổng này làm giao diện quản trị ban đầu.
   * Cổng bổ sung Optional 1 (OPT1): Nhập cổng ứng với Adapter 3 (`em2` hoặc `vtnet2`).
   * Cổng bổ sung Optional 2 (OPT2): Nhập cổng ứng với Adapter 4 (`em3` hoặc `vtnet3`).
   * Xác nhận lưu cấu hình: Nhập `y`.
2. Đổi tên giao diện và đặt IP qua tùy chọn phím `2` (**Set interface(s) IP address**):
   * Cấu hình giao diện Quản trị (Adapter 2): Đặt IPv4: `192.168.56.254/24`, không khai báo Gateway, tắt dịch vụ DHCP.
   * Truy cập từ máy thật qua trình duyệt: Mở `https://192.168.56.254`, đăng nhập tài khoản quản trị mặc định (`admin` / `pfsense`).
   * Vào **Interfaces** -> Đổi tên các cổng đúng chuẩn thiết kế:
     * Cổng quản trị: Đổi tên thành **MGMT** (Gán vào card Host-Only `192.168.56.254/24`).
     * Cổng LAN: Gán vào Adapter 3 (`lab6-lan`), đặt IPv4 tĩnh: `10.6.0.1/24`, tắt DHCP.
     * Cổng DMZ: Gán vào Adapter 4 (`lab6-dmz`), đặt IPv4 tĩnh: `172.16.6.1/24`, tắt DHCP.
   * Nhấp **Save** và **Apply Changes**.

---

### 3.3. Chuẩn bị máy chủ điều khiển miền (DC01 - Windows Server)

1. **Thiết lập địa chỉ IP tĩnh trên DC01:**
   * Mở giao diện cấu hình mạng trên Windows Server, đặt IP tĩnh:
     * Địa chỉ IPv4: `10.6.0.10`
     * Mặt nạ mạng: `255.255.255.0` (/24)
     * Cổng ngõ mặc định (Default Gateway): `10.6.0.1` (trỏ về IP LAN của pfSense)
     * Máy chủ phân giải DNS ưu tiên (Preferred DNS): `10.6.0.10` (trỏ về chính máy chủ)
2. **Cài đặt dịch vụ Active Directory và tạo tên miền:**
   * Mở **Server Manager** -> **Add roles and features** -> Cài đặt dịch vụ **Active Directory Domain Services** và **DNS Server**.
   * Nhấp biểu tượng cảnh báo cờ vàng -> Chọn **Promote this server to a domain controller**.
   * Chọn **Add a new forest** -> Đặt tên miền gốc: `lab6.test`.
   * Thiết lập mật khẩu khôi phục dịch vụ thư mục (DSRM) và hoàn tất khởi động lại máy.
3. **Cấu hình DNS Forwarder:**
   * Mở **DNS Manager** -> Nhấp chuột phải vào tên máy chủ DC01 -> **Properties** -> Thẻ **Forwarders**.
   * Nhấp **Edit** -> Thêm địa chỉ DNS ngoài: `8.8.8.8` hoặc `1.1.1.1` -> Nhấp **OK**.
4. **Tạo Đơn vị tổ chức (OU) và Tài khoản người dùng:**
   * Mở **Active Directory Users and Computers** (`dsa.msc`).
   * Nhấp chuột phải vào tên miền `lab6.test` -> Chọn **New** -> **Organizational Unit** -> Đặt tên: `LAB6-Users`.
   * Bên trong OU `LAB6-Users`, tạo lần lượt 2 người dùng phục vụ kiểm thử:
     * Người dùng 1: Full name: `Sinh Vien A`, User logon name: `sv_a`, đặt mật khẩu: `P@ssw0rd2026!` (bỏ chọn tùy chọn bắt buộc đổi mật khẩu ở lần đăng nhập đầu).
     * Người dùng 2: Full name: `Sinh Vien B`, User logon name: `sv_b`, đặt mật khẩu: `P@ssw0rd2026!`.
5. **Tạo tài khoản dịch vụ ràng buộc LDAP (Service Account):**
   * Trong vùng chứa mặc định `CN=Users` (hoặc trong chính `OU=LAB6-Users`), tạo tài khoản:
     * User logon name: `svc_pfsense_ldap`
     * Mật khẩu: `SvcPfsense#2026` (chọn **Password never expires**).
   * **Cảnh báo bảo mật tối quan trọng:** Tài khoản này chỉ thuộc nhóm mặc định `Domain Users`, tuyệt đối **không** thêm vào nhóm `Domain Admins`.

---

### 3.4. Chuẩn bị máy chủ dịch vụ Web DMZ (DMZ-WEB - Ubuntu Server)

Máy chủ dịch vụ DMZ-WEB sử dụng 1 máy ảo Ubuntu Server duy nhất nhưng được gắn 4 địa chỉ IPv4 độc lập trên cùng một card mạng để mô phỏng 4 phân loại website doanh nghiệp:

1. **Cấu hình mạng Netplan với 4 địa chỉ IPv4:**
   * Mở tệp cấu hình Netplan bằng quyền quản trị:
     ```bash
     sudo nano /etc/netplan/01-netcfg.yaml
     ```
   * Cập nhật nội dung cấu hình với địa chỉ chính `.10` và 3 địa chỉ phụ `.20`, `.30`, `.40`:
     ```yaml
     network:
       version: 2
       renderer: networkd
       ethernets:
         enp0s3: # (Thay bằng tên cổng mạng thực tế, kiểm tra bằng lệnh ip link)
           addresses:
             - 172.16.6.10/24
             - 172.16.6.20/24
             - 172.16.6.30/24
             - 172.16.6.40/24
           routes:
             - to: default
               via: 172.16.6.1
           nameservers:
             addresses: [8.8.8.8, 1.1.1.1]
     ```
   * Áp dụng cấu hình và kiểm tra địa chỉ mạng:
     ```bash
     sudo netplan apply
     ip addr show enp0s3
     ```
2. **Cài đặt và cấu hình dịch vụ máy chủ Nginx:**
   * Cài đặt gói phần mềm máy chủ dịch vụ web:
     ```bash
     sudo apt update && sudo apt install -y nginx
     ```
   * Tạo 4 trang chỉ mục riêng biệt để dễ dàng nhận biết khi truy cập từ máy trạm:
     ```bash
     sudo mkdir -p /var/www/site10 /var/www/site20 /var/www/site30 /var/www/site40
     echo "<h1>[172.16.6.10] GENERAL_SITE - Cong Thong Tin Doanh Nghiep</h1>" | sudo tee /var/www/site10/index.html
     echo "<h1>[172.16.6.20] JOB_SITE - Trang Tuyen Dung Viec Lam</h1>" | sudo tee /var/www/site20/index.html
     echo "<h1>[172.16.6.30] SOCIAL_SITE - Mang Xa Hoi Giai Tri</h1>" | sudo tee /var/www/site30/index.html
     echo "<h1>[172.16.6.40] RESTRICTED_SITE - Noi Dung Nhay Cam Bi Cam</h1>" | sudo tee /var/www/site40/index.html
     ```
   * Tạo tệp cấu hình máy chủ ảo Nginx:
     ```bash
     sudo nano /etc/nginx/sites-available/lab6_multisite.conf
     ```
     Nội dung tệp cấu hình:
     ```nginx
     server {
         listen 172.16.6.10:80;
         root /var/www/site10;
         index index.html;
     }
     server {
         listen 172.16.6.20:80;
         root /var/www/site20;
         index index.html;
     }
     server {
         listen 172.16.6.30:80;
         root /var/www/site30;
         index index.html;
     }
     server {
         listen 172.16.6.40:80;
         root /var/www/site40;
         index index.html;
     }
     ```
   * Kích hoạt cấu hình và khởi động lại dịch vụ:
     ```bash
     sudo ln -sf /etc/nginx/sites-available/lab6_multisite.conf /etc/nginx/sites-enabled/
     sudo rm -f /etc/nginx/sites-enabled/default
     sudo nginx -t
     sudo systemctl restart nginx
     ```

---

## PHẦN 4: HƯỚNG DẪN CẤU HÌNH TÍCH HỢP HỆ THỐNG TRÊN PFSENSE

### 4.1. Cấu hình máy chủ xác thực LDAP (Authentication Server)

1. Trên giao diện WebGUI pfSense, điều hướng tới: **System** -> **User Manager** -> Thẻ **Authentication Servers** -> Nhấp nút **Add**.
2. Nhập các thông số kỹ thuật chuẩn xác theo bảng tham số:

| Trường thông tin | Giá trị cấu hình trên pfSense | Giải thích ý nghĩa kỹ thuật |
| :--- | :--- | :--- |
| **Descriptive name** | `LAB6-AD` | Tên mô tả máy chủ xác thực hiển thị trên pfSense |
| **Type** | `LDAP` | Giao thức truy vấn thư mục tiêu chuẩn |
| **Hostname or IP address** | `10.6.0.10` | Địa chỉ IP của Domain Controller DC01 |
| **Port value** | `389` | Cổng tiêu chuẩn cho giao thức LDAP không mã hóa |
| **Transport** | `TCP - Standard` | Chế độ truyền vận chuẩn trong môi trường lab cô lập |
| **Protocol version** | `3` | Phiên bản giao thức LDAPv3 hiện đại |
| **Search scope** | `Entire Subtree` | Quét đệ quy toàn bộ các nhánh con bên dưới container |
| **Base DN** | `DC=lab6,DC=test` | Gốc miền Active Directory |
| **Authentication Containers** | `OU=LAB6-Users,DC=lab6,DC=test` | Vùng chứa giới hạn tìm kiếm tài khoản sinh viên |
| **Extended Query** | Để trống | Không yêu cầu bộ lọc LDAP nâng cao |
| **Bind credentials (User DN)**| `CN=svc_pfsense_ldap,CN=Users,DC=lab6,DC=test` | Tài khoản dịch vụ dùng thực hiện kết nối ràng buộc |
| **Bind credentials (Password)**| `SvcPfsense#2026` | Mật khẩu tài khoản dịch vụ |
| **Initial Template** | `Microsoft AD` | Tải mẫu thuộc tính chuẩn hóa cho Active Directory |
| **User naming attribute** | `samAccountName` | Tên đăng nhập người dùng Windows |
| **Group naming attribute** | `cn` | Tên định danh nhóm |
| **Group member attribute** | `memberOf` | Thuộc tính xác định nhóm của tài khoản |

3. Nhấp **Save** để lưu cấu hình.
4. **Kiểm tra thông tuyến và xác thực tài khoản LDAP:**
   * Điều hướng tới: **Diagnostics** -> **Authentication**.
   * Mục **Authentication Server**: Chọn `LAB6-AD`.
   * Kiểm tra lần lượt 2 tài khoản:
     * Kiểm tra 1: Nhập Username: `sv_a`, Password: `P@ssw0rd2026!` -> Nhấp **Test**.
     * Kiểm tra 2: Nhập Username: `sv_b`, Password: `P@ssw0rd2026!` -> Nhấp **Test**.
   * *Tiêu chuẩn đạt:* Màn hình hiển thị khung màu xanh thông báo: `User sv_a authenticated successfully` kèm danh sách nhóm mà người dùng trực thuộc.

---

### 4.2. Cấu hình Cổng xác thực Captive Portal

1. Trên WebGUI, điều hướng tới: **Services** -> **Captive Portal** -> Nhấp nút **Add**.
2. Đặt tên vùng (Zone name): `LAB6_USERS`, Mô tả: `Cong xac thuc nguoi dung mien noi bo`. Nhấp **Save & Continue**.
3. Cấu hình các tham số chi tiết cho Vùng:
   * **Enable:** Tích chọn **Enable Captive Portal**.
   * **Interfaces:** Chọn giao diện `LAN`.
   * **Idle timeout:** Nhập `30` (phút).
   * **Hard timeout:** Nhập `120` (phút).
   * **Authentication method:** Chọn **Use an Authentication backend**.
   * **Authentication Server:** Tích chọn `LAB6-AD`.
4. Nhấp **Save** và **Apply Changes**.
5. **Kiểm chứng đăng nhập Captive Portal thực tế:**
   * Khởi động máy ảo **Client-A** (đã đặt IP `10.6.0.21`, DNS `10.6.0.10`).
   * Mở trình duyệt web truy cập địa chỉ HTTP: `http://172.16.6.10`.
   * pfSense lập tức chuyển hướng sang giao diện Captive Portal yêu cầu đăng nhập.
   * Nhập thông tin tài khoản: `sv_a` / `P@ssw0rd2026!` -> Nhấp đăng nhập.
   * Sau khi xác thực thành công, máy trạm chuyển hướng sang trang chủ `GENERAL_SITE` tại `http://172.16.6.10`.
   * Trên pfSense vào **Status** -> **Captive Portal** -> **LAB6_USERS**: Xác nhận sự hiện diện của bản ghi phiên gồm địa chỉ IP `10.6.0.21`, MAC của Client-A và tên tài khoản `sv_a`.

---

### 4.3. Khai báo Danh mục định danh (Aliases)

Điều hướng tới: **Firewall** -> **Aliases** để khai báo các đối tượng dùng chung:

| Thẻ (Tab) | Tên Alias | Kiểu (Type) | Giá trị địa chỉ / Cổng | Ý nghĩa kỹ thuật |
| :--- | :--- | :--- | :--- | :--- |
| **IP** | `CLIENT_A` | Host(s) | `10.6.0.21` | Định danh địa chỉ máy trạm Client-A |
| **IP** | `CLIENT_B` | Host(s) | `10.6.0.22` | Định danh địa chỉ máy trạm Client-B |
| **IP** | `POLICY_CLIENTS` | Host(s) | `10.6.0.21`, `10.6.0.22` | Nhóm gộp cả hai máy trạm chịu kiểm soát chính sách |
| **IP** | `GENERAL_SITE` | Host(s) | `172.16.6.10` | Website nghiệp vụ thông thường trong DMZ |
| **IP** | `JOB_SITE` | Host(s) | `172.16.6.20` | Website mô phỏng nhóm tìm kiếm việc làm |
| **IP** | `SOCIAL_SITE` | Host(s) | `172.16.6.30` | Website mô phỏng nhóm mạng xã hội giải trí |
| **IP** | `RESTRICTED_SITE`| Host(s) | `172.16.6.40` | Website mô phỏng nhóm nội dung nhạy cảm bị cấm |
| **Ports**| `WEB_PORTS` | Port(s) | `80, 443` | Cặp cổng dịch vụ web tiêu chuẩn HTTP và HTTPS |

---

### 4.4. Cấu hình Lịch trình kiểm soát thời gian (Schedules)

Điều hướng tới: **Firewall** -> **Schedules** -> Nhấp nút **Add** để tạo 3 lịch trình:

1. **Lịch trình giờ nghỉ trưa (`LUNCH_WINDOW`):**
   * **Schedule Name:** `LUNCH_WINDOW`
   * **Description:** Khung giờ nghỉ trưa cho phép truy cập mạng xã hội
   * **Time Range:** Chọn các ngày từ Thứ 2 đến Thứ 6 (Mon, Tue, Wed, Thu, Fri); Giờ bắt đầu: `11:30`, Giờ kết thúc: `13:00`. Nhấp **Add Time** -> **Save**.
2. **Lịch trình giờ hành chính (`WORK_HOURS`):**
   * **Schedule Name:** `WORK_HOURS`
   * **Description:** Khung giờ làm việc tiêu chuẩn
   * **Time Range:** Chọn từ Thứ 2 đến Thứ 6; Giờ bắt đầu: `08:00`, Giờ kết thúc: `17:00`. Nhấp **Add Time** -> **Save**.
3. **Lịch trình kiểm thử tức thời (`TEST_NOW`):**
   * **Mục đích:** Phục vụ kiểm tra trực tiếp trong buổi học mà không cần chờ đến 11:30 hoặc phải chỉnh đồng hồ hệ thống.
   * **Cách cấu hình:** Chọn ngày hiện tại, chọn khoảng thời gian bao phủ thời điểm thực hành (ví dụ hiện tại là 14:50 thì đặt từ `14:40` đến `15:10`). Khi kiểm thử thành công, đổi luật sang sử dụng lịch chuẩn `LUNCH_WINDOW`.

---

## PHẦN 5: CHI TIẾT 7 KỊCH BẢN CHÍNH SÁCH VÀ QUY TRÌNH THỰC HIỆN

### Kịch bản 1: Phân quyền máy Client-A (Chặn JOB_SITE, Cho phép GENERAL_SITE)

* **Yêu cầu kỹ thuật:** Máy Client-A (`10.6.0.21`) tuyệt đối không được truy cập vào trang tuyển dụng việc làm `JOB_SITE` (`172.16.6.20`), nhưng phải truy cập bình thường trang cổng thông tin `GENERAL_SITE` (`172.16.6.10`).
* **Cấu hình luật trên thẻ Firewall -> Rules -> LAN:**
  1. **Luật 1 (Chặn):**
     * Action: `Block` | Interface: `LAN` | Address Family: `IPv4` | Protocol: `TCP`
     * Source: Single host or alias -> `CLIENT_A`
     * Destination: Single host or alias -> `JOB_SITE` | Destination Port: `80 (HTTP)`
     * Extra Options: Tích chọn **Log packets handled by this rule**
     * Description: `KB1: Chan Client-A truy cap JOB_SITE`
  2. **Luật 2 (Cho phép):**
     * Action: `Pass` | Interface: `LAN` | Protocol: `TCP`
     * Source: Single host or alias -> `CLIENT_A`
     * Destination: Single host or alias -> `GENERAL_SITE` | Destination Port: `80 (HTTP)`
     * Description: `KB1: Cho phep Client-A truy cap GENERAL_SITE`
* **Quy trình kiểm chứng:**
  * Từ Client-A, mở trình duyệt truy cập: `http://172.16.6.10` -> Tải trang thành công.
  * Mở thẻ mới truy cập: `http://172.16.6.20` -> Trình duyệt quay chờ và báo lỗi không thể kết nối.
  * Trên pfSense vào **Status** -> **System Logs** -> **Firewall**, lọc IP nguồn `10.6.0.21` -> Xác nhận có dòng nhật ký màu đỏ biểu thị gói tin tới `172.16.6.20:80` bị chặn bởi luật KB1.

---

### Kịch bản 2: Cấm nhóm trang web độc hại RESTRICTED_SITE cho toàn bộ máy trạm

* **Yêu cầu kỹ thuật:** Cả hai máy Client-A và Client-B đều bị cấm truy cập vào trang nội dung nhạy cảm `RESTRICTED_SITE` (`172.16.6.40`), nhưng vẫn được phép mở trang thông tin chung `GENERAL_SITE`.
* **Cấu hình luật trên thẻ Firewall -> Rules -> LAN:**
  * Action: `Block` | Interface: `LAN` | Protocol: `TCP`
  * Source: Single host or alias -> `POLICY_CLIENTS`
  * Destination: Single host or alias -> `RESTRICTED_SITE` | Destination Port: `80 (HTTP)`
  * Extra Options: Bật **Log packets**
  * Description: `KB2: Chan toan bo Client truy cap RESTRICTED_SITE`
* **Quy trình kiểm chứng:**
  * Đặt luật này ở vị trí ưu tiên cao (phía trên các luật cho phép).
  * Kiểm thử từ Client-A: Truy cập `http://172.16.6.40` -> Bị chặn hoàn toàn.
  * Kiểm thử từ Client-B: Truy cập `http://172.16.6.40` -> Bị chặn hoàn toàn.
  * Cả hai máy đều mở được `http://172.16.6.10`.

---

### Kịch bản 3: Client-B chỉ được truy cập SOCIAL_SITE trong giờ nghỉ trưa

* **Yêu cầu kỹ thuật:** Máy trạm Client-B (`10.6.0.22`) chỉ được phép truy cập mạng xã hội `SOCIAL_SITE` (`172.16.6.30`) trong khung giờ nghỉ trưa (`11:30 - 13:00`). Ngoài khung giờ này, truy cập phải bị chặn.
* **Cấu hình cặp luật trên thẻ Firewall -> Rules -> LAN:**
  1. **Luật 1 (Cho phép theo lịch):**
     * Action: `Pass` | Interface: `LAN` | Protocol: `TCP`
     * Source: `CLIENT_B` | Destination: `SOCIAL_SITE` | Destination Port: `80`
     * Schedule: Chọn `LUNCH_WINDOW` (hoặc tạm gán `TEST_NOW` khi kiểm thử trực tiếp)
     * Description: `KB3: Cho phep Client-B vao SOCIAL_SITE gio nghi`
  2. **Luật 2 (Chặn ngoài giờ - đặt ngay phía dưới Luật 1):**
     * Action: `Block` | Interface: `LAN` | Protocol: `TCP`
     * Source: `CLIENT_B` | Destination: `SOCIAL_SITE` | Destination Port: `80`
     * Schedule: `None` (áp dụng mọi thời điểm)
     * Extra Options: Bật **Log packets**
     * Description: `KB3: Chan Client-B vao SOCIAL_SITE ngoai gio nghi`
* **Quy trình kiểm chứng:**
  * *Bước 1 (Kiểm tra trong giờ cho phép):* Gán lịch `TEST_NOW` bao phủ thời gian hiện tại vào Luật 1. Biểu tượng đồng hồ hiển thị màu xanh (Active). Từ Client-B truy cập `http://172.16.6.30` -> Tải trang thành công.
  * *Bước 2 (Kiểm tra ngoài giờ):* Chỉnh sửa thời gian `TEST_NOW` lệch khỏi giờ hiện tại (hoặc tạm thời Disable Luật 1). Biểu tượng đồng hồ chuyển sang màu xám mờ.
  * *Bước 3:* Trên pfSense, vào **Diagnostics** -> **States** -> Nhấp **Reset States** để xóa sạch phiên cũ.
  * *Bước 4:* Từ Client-B mở lại phiên mới tới `http://172.16.6.30` -> Kết nối bị Luật 2 chặn lập tức.
  * *Bước 5:* Sau khi hoàn tất kiểm chứng, gắn lại lịch chuẩn `LUNCH_WINDOW` cho Luật 1.

---

### Kịch bản 4: Giới hạn lưu lượng Web Internet trong giờ hành chính

* **Yêu cầu kỹ thuật:** Trong khung giờ làm việc (`WORK_HOURS`), các máy trạm thuộc `POLICY_CLIENTS` chỉ được phép sử dụng dịch vụ Web (HTTP cổng 80 và HTTPS cổng 443) ra Internet; các dịch vụ khác (như ping kiểm tra mạng, truyền tệp FTP...) bị chặn hoàn toàn.
* **Cấu hình cặp luật trên thẻ Firewall -> Rules -> LAN:**
  1. **Luật 1 (Cho phép Web theo giờ hành chính):**
     * Action: `Pass` | Interface: `LAN` | Protocol: `TCP`
     * Source: `POLICY_CLIENTS` | Destination: `Any` | Destination Port: `WEB_PORTS` (Alias cổng 80, 443)
     * Schedule: `WORK_HOURS`
     * Description: `KB4: Cho phep luu luong Web trong gio hanh chinh`
  2. **Luật 2 (Chặn các dịch vụ khác - Explicit Deny):**
     * Action: `Block` | Interface: `LAN` | Protocol: `Any`
     * Source: `POLICY_CLIENTS` | Destination: `Any`
     * Extra Options: Bật **Log packets**
     * Description: `KB4: Chan toan bo luu luong khac cua Client`
* **Quy trình kiểm chứng:**
  * Lưu ý đặc biệt: Máy trạm Client-A và Client-B sử dụng DNS trỏ về DC01 (`10.6.0.10`). Do DC01 nằm cùng phân vùng mạng con LAN (`10.6.0.0/24`), gói tin DNS giữa máy trạm và DC01 được trao đổi trực tiếp ở Lớp 2 qua chuyển mạch ảo (Switching/ARP) mà **không đi qua pfSense**, do đó không bị ảnh hưởng bởi luật trên pfSense.
  * Khi `WORK_HOURS` đang kích hoạt:
    * Mở trình duyệt truy cập website ngoài Internet (ví dụ: `http://example.com` hoặc `https://www.google.com`) -> Tải trang bình thường.
    * Mở Command Prompt thực hiện lệnh ping ra ngoài: `ping 8.8.8.8` -> Bị chặn (`Request timed out`).

---

### Kịch bản 5: Phân vùng cô lập an toàn DMZ hai chiều

* **Yêu cầu kỹ thuật:** Máy chủ trong vùng DMZ (`172.16.6.0/24`) bị nghiêm cấm tuyệt đối không được chủ động khởi tạo bất kỳ kết nối nào vào vùng mạng nội bộ LAN (`10.6.0.0/24`). Ngược lại, máy trạm từ vùng LAN vẫn được phép truy cập vào các dịch vụ công bố trong DMZ theo đúng chính sách.
* **Cấu hình luật trên thẻ Firewall -> Rules -> DMZ:**
  1. **Luật 1 (Chặn DMZ sang LAN):**
     * Action: `Block` | Interface: `DMZ` | Protocol: `Any`
     * Source: `DMZ net` | Destination: `LAN net`
     * Extra Options: Bật **Log packets**
     * Description: `KB5: Ngan cach DMZ khong duoc ket noi vao LAN`
  2. **Luật 2 (Cho phép DMZ ra ngoài nếu cần cập nhật):**
     * Action: `Pass` | Interface: `DMZ` | Protocol: `Any`
     * Source: `DMZ net` | Destination: `Any`
* **Quy trình kiểm chứng:**
  * *Chiều 1 (LAN sang DMZ):* Từ Client-A truy cập `http://172.16.6.10` -> Tải trang thành công.
  * *Chiều 2 (DMZ sang LAN):* Đăng nhập vào máy ảo Ubuntu DMZ-WEB, chạy lệnh gửi gói tin thăm dò hoặc kiểm tra cổng dịch vụ về máy chủ DC01:
    ```bash
    ping -c 4 10.6.0.10
    curl -m 3 http://10.6.0.10
    ```
    *Kết quả:* Toàn bộ gói tin đều thất bại do bị Luật 1 trên giao diện DMZ chặn lại. Kiểm tra nhật ký tường lửa trên giao diện DMZ thấy rõ bản ghi chặn từ IP nguồn `172.16.6.10` tới đích `10.6.0.10`.

---

### Kịch bản 6: Đo kiểm và đối chiếu hành vi giữa Block và Reject

* **Yêu cầu kỹ thuật:** Thực hiện kiểm chứng khoa học sự khác biệt về phản ứng ngăn xếp mạng giữa hành động `Block` và `Reject` khi áp dụng cho cùng một máy nguồn và đích.
* **Thiết lập bài đo kiểm:**
  * Mục tiêu kiểm tra: Truy cập từ Client-A tới cổng TCP 80 của `JOB_SITE` (`172.16.6.20`).
  * Sử dụng công cụ đo thời gian bằng lệnh PowerShell trên Client-A:
    ```powershell
    Measure-Command { Test-NetConnection -ComputerName 172.16.6.20 -Port 80 }
    ```
* **Thực hiện Lần 1 với hành động Block:**
  1. Cấu hình luật trên pfSense: Action = `Block`.
  2. Xóa bảng trạng thái trên pfSense (`Diagnostics -> States -> Reset States`).
  3. Thực thi lệnh đo trên Client-A.
  4. *Kết quả:* Lệnh mất khoảng **21 đến 42 giây** mới kết thúc; báo lỗi `TcpTestSucceeded: False` do hết thời gian chờ (Timeout).
* **Thực hiện Lần 2 với hành động Reject:**
  1. Sửa luật trên pfSense: Đổi Action từ `Block` thành `Reject`. Nhấp **Save** và **Apply Changes**.
  2. Xóa bảng trạng thái trên pfSense.
  3. Thực thi lại lệnh đo trên Client-A.
  4. *Kết quả:* Lệnh kết thúc ngay lập tức chỉ sau **dưới 1 giây (vài chục mili-giây)**; hệ điều hành nhận được gói tin cờ `[RST, ACK]` và báo lỗi từ chối kết nối tức thì.

---

### Kịch bản 7: Giám sát nhật ký tường lửa và Bảng trạng thái kết nối

* **Yêu cầu kỹ thuật:** Làm chủ kỹ thuật đọc nhật ký lọc gói (Firewall Log) và truy vấn Bảng trạng thái (State Table) để giải quyết dứt điểm hiện tượng kết nối ảo hoặc lưu lượng không rõ nguyên nhân.
* **Các bước vận hành chuẩn mực:**
  1. **Kích hoạt ghi nhật ký:** Trên các luật Chặn quan trọng (Kịch bản 1, 2, 3, 5), luôn tích chọn mục **Log packets handled by this rule**.
  2. **Truy vấn nhật ký:**
     * Điều hướng tới: **Status** -> **System Logs** -> **Firewall** -> Thẻ **Normal View**.
     * Sử dụng thanh lọc (Filter): Nhập IP nguồn `10.6.0.21` hoặc IP đích `172.16.6.20`.
     * Đối chiếu 6 trường thông tin: Biểu tượng hành động (Chặn/Cho phép), Giao diện mạng tiếp nhận (`LAN` hoặc `DMZ`), Thời gian chính xác, Địa chỉ IP/Cổng nguồn, Địa chỉ IP/Cổng đích và Giao thức truyền vận.
  3. **Tra cứu Bảng trạng thái:**
     * Điều hướng tới: **Diagnostics** -> **States**.
     * Nhập địa chỉ IP của Client vào ô tìm kiếm để kiểm tra phiên đang mở.
     * Khi thực hiện thay đổi luật mà máy trạm vẫn truy cập được dịch vụ cũ: Nhấp vào thẻ **Reset States** -> Chọn **Reset** để ép tường lửa giải phóng toàn bộ bảng phiên.

---

## PHẦN 6: BẢNG TỔNG HỢP THỨ TỰ TẬP LUẬT CHUẨN TRÊN GIAO DIỆN LAN

Để toàn bộ 7 kịch bản hoạt động chính xác và không bị triệt tiêu lẫn nhau, thứ tự các luật trên thẻ **Firewall -> Rules -> LAN** bắt buộc phải tuân thủ nghiêm ngặt nguyên lý **First-Match Wins** từ trên xuống dưới theo bảng sau:

| Thứ tự ưu tiên | Hành động (Action) | Nguồn (Source) | Đích (Destination) | Cổng đích | Lịch trình (Schedule) | Ghi nhật ký (Log) | Ý nghĩa nghiệp vụ trong hệ thống |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **1** | **Block** | `CLIENT_A` | `JOB_SITE` | `80` (HTTP) | None | Bật (Log) | **KB1:** Chặn Client-A vào trang tuyển dụng việc làm |
| **2** | **Block** | `POLICY_CLIENTS` | `RESTRICTED_SITE` | `80` (HTTP) | None | Bật (Log) | **KB2:** Chặn toàn bộ máy trạm vào trang độc hại/nhạy cảm |
| **3** | **Pass** | `CLIENT_B` | `SOCIAL_SITE` | `80` (HTTP) | `LUNCH_WINDOW` | Tùy chọn | **KB3:** Cho phép Client-B vào mạng xã hội trong giờ nghỉ |
| **4** | **Block** | `CLIENT_B` | `SOCIAL_SITE` | `80` (HTTP) | None | Bật (Log) | **KB3:** Chặn Client-B vào mạng xã hội ngoài giờ nghỉ |
| **5** | **Pass** | `POLICY_CLIENTS` | `GENERAL_SITE` | `80` (HTTP) | None | Tùy chọn | Cho phép toàn bộ máy trạm vào trang thông tin doanh nghiệp |
| **6** | **Pass** | `POLICY_CLIENTS` | `Any` | `WEB_PORTS` | `WORK_HOURS` | Tùy chọn | **KB4:** Cho phép truy cập Web Internet trong giờ hành chính |
| **7** | **Block** | `POLICY_CLIENTS` | `Any` | Any | None | Bật (Log) | **KB4:** Luật chặn mặc định rõ ràng (Explicit Deny) cuối ruleset |

> **Cảnh báo sống còn về thứ tự luật:** Nếu người quản trị bất cẩn đưa Luật 5 hoặc Luật 6 lên phía trên Luật 1 hoặc Luật 2, thì gói tin đi tới các trang tuyển dụng hoặc nhạy cảm sẽ bị khớp ngay với luật Cho phép ở trên, khiến cho toàn bộ các luật Chặn đặt phía dưới hoàn toàn mất tác dụng.

---

## PHẦN 7: BẢNG KỊCH BẢN KIỂM THỬ VÀ ĐỐI SOÁT NGHIỆM THU

| STT | Nguồn kiểm thử | Đích kiểm thử | Kết quả kỳ vọng trong lịch | Kết quả kỳ vọng ngoài lịch | Trạng thái đo kiểm |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **01** | Máy Client-A | `GENERAL_SITE` (`172.16.6.10`) | Cho phép (Pass) | Cho phép (Pass) | Đạt |
| **02** | Máy Client-A | `JOB_SITE` (`172.16.6.20`) | Chặn (Block) | Chặn (Block) | Đạt |
| **03** | Máy Client-A | `RESTRICTED_SITE` (`172.16.6.40`) | Chặn (Block) | Chặn (Block) | Đạt |
| **04** | Máy Client-B | `GENERAL_SITE` (`172.16.6.10`) | Cho phép (Pass) | Cho phép (Pass) | Đạt |
| **05** | Máy Client-B | `SOCIAL_SITE` (`172.16.6.30`) | Cho phép (Pass trong `LUNCH`) | Chặn (Block ngoài `LUNCH`) | Đạt |
| **06** | Máy Client-B | `RESTRICTED_SITE` (`172.16.6.40`) | Chặn (Block) | Chặn (Block) | Đạt |
| **07** | Máy Client-A/B | Lưu lượng Web Internet (Cổng 80/443) | Cho phép (Pass trong `WORK`) | Chặn (Block ngoài `WORK`) | Đạt |
| **08** | Máy Client-A/B | Gói tin thăm dò ICMP Ping ra ngoài | Chặn (Block) | Chặn (Block) | Đạt |
| **09** | Máy DMZ-WEB | Máy chủ DC01 (`10.6.0.10`) | Chặn (Block) | Chặn (Block) | Đạt |
| **10** | pfSense LDAP | Kiểm tra xác thực `sv_a` và `sv_b` | Xác thực thành công | Xác thực thành công | Đạt |

---

## PHẦN 8: CẨM NANG XỬ LÝ SỰ CỐ THEO TRÌNH TỰ CHUẨN (TROUBLESHOOTING)

### 1. Sự cố 1: Không thể truy cập WebGUI quản trị pfSense
* **Hiện tượng:** Máy thật mở trình duyệt vào `https://192.168.56.254` báo lỗi không kết nối được.
* **Trình tự xử lý:**
  1. Kiểm tra card mạng máy thật: Mở Command Prompt trên máy thật, chạy `ipconfig`. Đảm bảo card `VirtualBox Host-Only Ethernet Adapter` mang địa chỉ `192.168.56.1/24`.
  2. Ping kiểm tra cổng tường lửa: Thực hiện lệnh `ping 192.168.56.254`.
  3. Kiểm tra console máy ảo pfSense: Chọn phím `2` để xác nhận IP cổng MGMT đã đặt đúng `192.168.56.254/24`.
  4. Khôi phục quyền truy cập nếu bị tường lửa chặn: Tại console pfSense, chọn phím `8` (Shell) và chạy lệnh:
     ```sh
     pfctl -d
     ```
     Lệnh này sẽ tạm thời vô hiệu hóa bộ lọc tường lửa để người quản trị đăng nhập vào giao diện web kiểm tra lại cấu hình.

### 2. Sự cố 2: Kiểm tra LDAP trên pfSense thất bại (LDAP Test Failed)
* **Hiện tượng:** Vào `Diagnostics -> Authentication` kiểm tra báo lỗi kết nối hoặc sai thông tin.
* **Trình tự xử lý:**
  1. Kiểm tra định tuyến giữa pfSense và DC01: Vào `Diagnostics -> Ping`, ping tới địa chỉ `10.6.0.10` xuất phát từ giao diện LAN.
  2. Kiểm tra dịch vụ LDAP trên DC01: Đảm bảo dịch vụ Active Directory đang chạy và cổng 389 đang lắng nghe kết nối.
  3. Rà soát thông số cấu hình LDAP:
     * Kiểm tra `Search scope`: Bắt buộc phải là `Entire Subtree`.
     * Kiểm tra `Base DN`: Đúng định dạng `DC=lab6,DC=test`.
     * Kiểm tra `Authentication Containers`: Đúng `OU=LAB6-Users,DC=lab6,DC=test`.
     * Kiểm tra tài khoản Bind DN: Khai báo đầy đủ tên phân cấp `CN=svc_pfsense_ldap,CN=Users,DC=lab6,DC=test` và mật khẩu tương ứng.
     * Kiểm tra trạng thái tài khoản `svc_pfsense_ldap` trên DC01 xem có bị khóa (Locked) hoặc hết hạn hay không.

### 3. Sự cố 3: Captive Portal không tự động hiển thị trang đăng nhập
* **Hiện tượng:** Máy trạm mở trình duyệt không thấy trang Captive Portal xuất hiện.
* **Trình tự xử lý:**
  1. Kiểm tra phân giải tên miền DNS: Đảm bảo máy trạm đã nhận đúng DNS `10.6.0.10`.
  2. Truy cập bằng địa chỉ HTTP thuần túy: Không truy cập các trang HTTPS ở lần đầu tiên vì trình duyệt sẽ chặn cảnh báo chứng chỉ SSL trước khi chuyển hướng. Bắt buộc gõ địa chỉ HTTP thuần (ví dụ: `http://172.16.6.10` hoặc `http://neverssl.com`).
  3. Kiểm tra trạng thái phiên cũ: Vào `Status -> Captive Portal -> LAB6_USERS`, nếu địa chỉ IP hoặc MAC của máy trạm đã có trong danh sách phiên thì Cổng xác thực sẽ cho qua mà không hiện lại trang đăng nhập. Nhấp biểu tượng thùng rác để ngắt phiên cũ.

### 4. Sự cố 4: Luật tường lửa cấu hình đúng nhưng không có tác dụng
* **Hiện tượng:** Đã tạo luật Chặn nhưng máy trạm vẫn mở được trang web.
* **Trình tự xử lý:**
  1. **Kiểm tra Bảng trạng thái (State Table):** Đây là nguyên nhân phổ biến nhất. Phiên kết nối cũ vẫn đang tồn tại trong Bảng trạng thái. Bắt buộc vào `Diagnostics -> States -> Reset States` để giải phóng toàn bộ bảng phiên.
  2. **Kiểm tra thứ tự luật (First-Match):** Kiểm tra xem có luật Cho phép nào đặt ở phía trên luật Chặn hay không.
  3. **Kiểm tra đối tượng Alias:** Vào `Diagnostics -> Tables`, kiểm tra xem bảng của Alias tương ứng đã nạp đúng danh sách địa chỉ IP hay chưa.
  4. Đảm bảo đã nhấp nút **Apply Changes** sau khi lưu cấu hình luật.

### 5. Sự cố 5: Lịch trình thời gian (Schedule) chạy sai lệch
* **Hiện tượng:** Đến giờ quy định nhưng luật không tự động kích hoạt hoặc bị ngắt không đúng lúc.
* **Trình tự xử lý:**
  1. Kiểm tra múi giờ trên pfSense: Vào `System -> General Setup`, kiểm tra mục **Timezone** đã đặt đúng `Asia/Ho_Chi_Minh` hay chưa.
  2. Kiểm tra đồng hồ thời gian thực: Quan sát góc trên bên phải màn hình WebGUI để đối chiếu giờ hệ thống pfSense với giờ thực tế của máy tính.
  3. Quan sát biểu tượng trạng thái Schedule trên trang Firewall Rules: Biểu tượng đồng hồ màu xanh là Active, màu xám là Inactive.

### 6. Sự cố 6: Máy trạm không truy cập được các trang web trong DMZ
* **Hiện tượng:** Mở địa chỉ `http://172.16.6.10` báo lỗi không tìm thấy máy chủ.
* **Trình tự xử lý:**
  1. Kiểm tra dịch vụ Nginx trên máy ảo Ubuntu DMZ-WEB: Chạy lệnh `sudo systemctl status nginx`.
  2. Kiểm tra các địa chỉ IP phụ: Chạy lệnh `ip addr show` trên Ubuntu để xác nhận cả 4 địa chỉ `.10`, `.20`, `.30`, `.40` đã được gán vào card mạng.
  3. Kiểm tra tường lửa nội bộ Ubuntu: Tắt UFW bằng lệnh `sudo ufw disable` để tránh xung đột lọc gói tin.
  4. Kiểm tra luật trên tab LAN của pfSense: Đảm bảo có luật Pass cho phép nguồn `POLICY_CLIENTS` tới các địa chỉ của DMZ.

### 7. Sự cố 7: Không thấy bản ghi xuất hiện trong Firewall Log
* **Hiện tượng:** Gói tin bị chặn nhưng kiểm tra trong System Logs -> Firewall không có dữ liệu.
* **Trình tự xử lý:**
  1. Kiểm tra tùy chọn ghi nhật ký trên luật: Mở luật cần theo dõi, đảm bảo mục **Log packets handled by this rule** đã được tích chọn.
  2. Tạo lưu lượng mới: Phát sinh gói tin mới từ máy trạm sau khi lưu luật.
  3. Kiểm tra bộ lọc giao diện: Đảm bảo đang xem nhật ký trên đúng giao diện tiếp nhận lưu lượng (giao diện `LAN` cho chiều máy trạm gửi đi).

---

## PHẦN 9: ĐÁP ÁN PHÂN TÍCH CHUYÊN SÂU 12 CÂU HỎI LÝ THUYẾT BÀI THỰC HÀNH 6

#### Câu 1: Vì sao LAB 6 phải dùng topology riêng thay vì tiếp tục sử dụng trực tiếp topology LAB 5?
* **Đáp án:**
  * Topology của LAB 5 được thiết kế với dải mạng LAN rộng `10.0.0.0/8` và DMZ rộng `172.16.0.0/16`, sử dụng chung card mạng Host-Only với máy thật cho toàn bộ lưu lượng dữ liệu và quản trị.
  * LAB 6 yêu cầu một kiến trúc mạng chuẩn mực doanh nghiệp với 4 phân vùng độc lập: tách biệt hoàn toàn giữa mạng quản trị cô lập MGMT (`192.168.56.0/24`) và mạng người dùng LAN-DOMAIN (`10.6.0.0/24`). Việc tách riêng này nhằm ngăn chặn nguy cơ người dùng nội bộ hoặc Cổng xác thực Captive Portal can thiệp vào giao diện cấu hình WebGUI của tường lửa.
  * Đồng thời, LAB 6 quy hoạch lại không gian mạng con rõ ràng (`10.6.0.0/24` và `172.16.6.0/24`) nhằm phục vụ việc gán nhiều địa chỉ IP ảo mô phỏng phân loại website và tránh mọi xung đột định tuyến với các bài thực hành khác.

#### Câu 2: LDAP được dùng cho chức năng nào trên pfSense? Firewall rule chuẩn có thể dùng username AD làm Source trực tiếp không?
* **Đáp án:**
  * Trên pfSense, LDAP đóng vai trò là một cơ chế chứng thực người dùng từ xa (External Authentication Backend). Nó được sử dụng để xác thực danh tính quản trị viên đăng nhập vào WebGUI/SSH, xác thực người dùng truy cập mạng qua Captive Portal, và xác thực người dùng kết nối mạng riêng ảo VPN (IPsec/OpenVPN).
  * **Firewall rule chuẩn của pfSense KHÔNG THỂ sử dụng trực tiếp username Active Directory làm điều kiện Nguồn (Source).** Bản chất bộ lọc gói tin lõi của pfSense (Packet Filter) hoạt động tại Lớp 3 (IP) và Lớp 4 (Cổng/Giao thức) của mô hình OSI. Tiêu đề gói tin IP truyền trên mạng chỉ chứa địa chỉ IP nguồn/đích chứ không mang thông tin định danh tài khoản người dùng Lớp 7. Để áp dụng chính sách cho từng người dùng, người quản trị bắt buộc phải ánh xạ gián tiếp thông qua địa chỉ IP tĩnh hoặc thông qua bảng phiên gán IP của Captive Portal.

#### Câu 3: Vì sao Captive Portal được đặt trên LAN nhưng WebGUI quản trị lại tách sang MGMT?
* **Đáp án:**
  * Captive Portal hoạt động bằng cơ chế bắt giữ (intercept) và chuyển hướng toàn bộ lưu lượng HTTP cổng 80 của người dùng chưa xác thực về giao diện cổng chào. Do đó, nó bắt buộc phải được kích hoạt trên giao diện LAN nơi các máy trạm người dùng kết nối trực tiếp.
  * Nếu WebGUI quản trị đặt chung trên giao diện LAN, người dùng nội bộ chưa đăng nhập có thể quét thấy cổng dịch vụ quản trị (80/443), tiềm ẩn nguy cơ bị tấn công dò quét mật khẩu hoặc khai thác lỗ hổng giao diện web.
  * Việc tách WebGUI sang phân vùng quản trị riêng biệt MGMT (`192.168.56.0/24`) tuân thủ nghiêm ngặt nguyên lý **Phân tách mặt phẳng dữ liệu (Data Plane) và mặt phẳng quản trị (Management Plane)**. Khi đó, người dùng tại LAN hoàn toàn không thể định tuyến hoặc chạm tới giao diện cấu hình của thiết bị tường lửa.

#### Câu 4: Search Scope Entire Subtree có ý nghĩa gì khi pfSense truy vấn Active Directory?
* **Đáp án:**
  * Thuộc tính `Search Scope` xác định chiều sâu không gian tìm kiếm đối tượng trong cây thư mục thư mục Active Directory tính từ điểm xuất phát (Base DN hoặc Authentication Container).
  * Chế độ **Entire Subtree** (Toàn bộ cây con đệ quy) chỉ thị cho pfSense quét toàn bộ nhánh thư mục xuất phát cùng tất cả các Đơn vị tổ chức con (Child OUs) lồng bên trong nó.
  * Ý nghĩa: Trong các tổ chức doanh nghiệp lớn, tài khoản người dùng thường được phân bổ trong nhiều OU con khác nhau (ví dụ: `OU=KyThuat`, `OU=KinhDoanh` nằm bên trong `OU=NhanVien`). Chế độ này bảo đảm pfSense luôn tìm kiếm và xác thực thành công người dùng mà không phụ thuộc vào việc tài khoản nằm ở cấp thư mục con nào.

#### Câu 5: Tại sao nên dùng service account thay vì Domain Administrator làm LDAP bind?
* **Đáp án:**
  * Tuân thủ triệt để **Nguyên tắc đặc quyền tối thiểu (Principle of Least Privilege)** và **Phòng thủ theo chiều sâu (Defense-in-Depth)**.
  * Tài khoản Bind DN chỉ cần quyền đọc danh bạ thư mục (Read/Search objects) để tra cứu thông tin tài khoản người dùng.
  * Cấu hình LDAP trên pfSense bắt buộc phải lưu trữ thông tin đăng nhập (gồm tên tài khoản và mật khẩu) trong tệp cấu hình hệ thống `config.xml`. Nếu sử dụng tài khoản `Domain Administrator`, trong trường hợp tường lửa bị chiếm quyền kiểm soát hoặc tệp sao lưu cấu hình bị lộ, kẻ tấn công sẽ lập tức có được quyền quản trị cao nhất trên toàn bộ hệ thống mạng miền Active Directory. Việc sử dụng tài khoản dịch vụ chuyên dụng với đặc quyền giới hạn sẽ cô lập hoàn toàn thiệt hại nếu xảy ra sự cố an toàn thông tin.

#### Câu 6: Trong Kịch bản 3, vì sao cần một rule Block SOCIAL_SITE nằm dưới rule Pass có Schedule?
* **Đáp án:**
  * Cơ chế lập lịch (Schedule) trên pfSense hoạt động theo nguyên lý: Khi khung giờ trong lịch trình hết hiệu lực (Inactive), pfSense sẽ **xem như luật đó không tồn tại** và bỏ qua nó trong danh sách xử lý. Luật không có khả năng tự động đảo ngược hành động từ Cho phép thành Chặn.
  * Nếu không có một luật `Block SOCIAL_SITE` đặt ngay phía dưới, khi ngoài giờ nghỉ trưa, gói tin truy cập mạng xã hội sẽ tiếp tục trôi xuống các luật bên dưới và bị khớp với các luật Cho phép rộng hơn (ví dụ luật cho phép duyệt web Internet trong Kịch bản 4), dẫn đến việc máy trạm vẫn truy cập được mạng xã hội ngoài giờ quy định.
  * Do đó, luật Block đặt liền kề phía dưới đóng vai trò là "chốt chặn an toàn" bắt buộc để xử lý triệt để lưu lượng khi luật theo lịch phía trên biến mất.

#### Câu 7: Vì sao Client-A/B dùng DNS 10.6.0.10 nhưng rule Internet của client không cần cho DNS tới 10.6.0.10?
* **Đáp án:**
  * Cả máy trạm Client-A (`10.6.0.21`), Client-B (`10.6.0.22`) và máy chủ DC01/DNS (`10.6.0.10`) đều nằm chung trong cùng một phân vùng mạng con Lớp 3 là `10.6.0.0/24` (kết nối qua cùng một chuyển mạch ảo Internal Network `lab6-lan`).
  * Theo nguyên lý truyền thông mạng TCP/IP, khi hai thiết bị thuộc cùng một mạng con trao đổi dữ liệu với nhau, chúng sẽ sử dụng giao thức phân giải địa chỉ ARP để xác định địa chỉ MAC của nhau và truyền gói tin trực tiếp qua Lớp 2 (Data Link).
  * Gói tin truy vấn DNS từ máy trạm tới DC01 **hoàn toàn không đi qua Cổng ngõ mặc định (Default Gateway - 10.6.0.1) của pfSense**. Vì gói tin không đi vào giao diện của pfSense, nên tập luật tường lửa trên pfSense không bao giờ nhìn thấy và không cần cấu hình luật cho luồng dữ liệu này.

#### Câu 8: Giải thích first-match bằng một ví dụ cụ thể trong ruleset tổng hợp.
* **Đáp án:**
  * **Định nghĩa First-Match:** Bộ xử lý luật của pfSense duyệt gói tin tuần tự từ trên xuống dưới theo thứ tự xuất hiện trong danh sách. Ngay khi gói tin thỏa mãn toàn bộ tiêu chí (Nguồn, Đích, Giao thức, Cổng, Lịch trình) của một luật nào đó, hành động của luật đó sẽ được thực thi ngay lập tức và quá trình duyệt luật dừng lại toàn bộ.
  * **Ví dụ thực tế trong ruleset:**
    * Giả sử trên tab LAN có 2 luật:
      * Luật 1 (Vị trí trên): `Block Source: CLIENT_A -> Destination: JOB_SITE:80`.
      * Luật 5 (Vị trí dưới): `Pass Source: POLICY_CLIENTS -> Destination: GENERAL_SITE:80` (hoặc luật cho phép Web Any ở Luật 6).
    * Khi Client-A gửi gói tin tới `JOB_SITE` (`172.16.6.20:80`): Gói tin đi vào giao diện LAN và được so khớp với Luật 1 đầu tiên. Do trùng khớp chính xác Nguồn (`10.6.0.21`) và Đích (`172.16.6.20:80`), hành động `Block` lập tức được thực thi và gói tin bị hủy bỏ ngay. pfSense không bao giờ duyệt tiếp xuống các luật Cho phép phía dưới.
    * Ngược lại, nếu người quản trị vô tình hoán đổi vị trí, đưa Luật 6 (`Pass Any WEB_PORTS`) lên trên Luật 1, gói tin tới `JOB_SITE` sẽ bị khớp ngay với Luật 6 và được cho qua, làm mất tác dụng hoàn toàn của Luật 1.

#### Câu 9: Vì sao sau khi đổi rule cần tạo kết nối mới hoặc Reset States?
* **Đáp án:**
  * pfSense là một tường lửa lọc gói có trạng thái (Stateful Firewall). Khi một kết nối ban đầu được chấp thuận, thông tin phiên làm việc được ghi nhận trong **Bảng trạng thái (State Table)**.
  * Toàn bộ các gói tin tiếp theo thuộc phiên này được kiểm tra đối chiếu trực tiếp với Bảng trạng thái và cho qua tự động ở mức phần cứng/nhân hệ điều hành mà **không kiểm tra lại danh sách luật tường lửa**.
  * Khi người quản trị thay đổi một luật từ Cho phép sang Chặn, phiên kết nối đang hoạt động của người dùng vẫn tiếp tục thông suốt vì bản ghi trạng thái trong bảng phiên vẫn còn hạn sử dụng.
  * Vì vậy, để luật mới có hiệu lực ngay lập tức, bắt buộc phải thực hiện thao tác **Reset States** (xóa sạch bảng trạng thái) và tạo một phiên kết nối mới để ép gói tin khởi tạo phiên (TCP SYN) phải trải qua quá trình so khớp lại với danh sách luật mới.

#### Câu 10: Mô hình JOB_SITE/SOCIAL_SITE/RESTRICTED_SITE trong DMZ khác Web Category Filtering thật như thế nào?
* **Đáp án:**
  * **Mô hình mô phỏng trong bài thực hành (L3/L4 Filtering):** Lọc dựa hoàn toàn trên Địa chỉ IPv4 tĩnh và Cổng dịch vụ Lớp 3/L4. pfSense chỉ kiểm tra địa chỉ IP đích trên tiêu đề gói tin để quyết định chặn hay cho phép. Nhược điểm là trong thực tế Internet hiện đại, hàng triệu website cùng chia sẻ chung một dải IP (thông qua hạ tầng đám mây CDN, Cloudflare, Akamai) và một website có thể liên tục thay đổi IP.
  * **Bộ lọc phân loại danh mục Web thực tế (Next-Generation Web Category Filtering / Secure Web Gateway):**
    * Hoạt động tại Lớp 7 (Application Layer) bằng cơ chế kiểm tra gói tin sâu (Deep Packet Inspection - DPI) và Proxy phân tích nội dung.
    * Đọc trường máy chủ Server Name Indication (SNI) trong quá trình bắt tay mã hóa TLS/SSL hoặc kiểm tra tiêu đề `Host` của giao thức HTTP.
    * Tự động tra cứu tên miền vào cơ sở dữ liệu phân loại đám mây thời gian thực chứa hàng tỷ trang web được gán nhãn tự động (như Cờ bạc, Khiêu dâm, Mạng xã hội, Tin tức) mà không cần quan tâm website đó đang sử dụng địa chỉ IP nào.

#### Câu 11: Block và Reject khác nhau ra sao về hành vi phía client?
* **Đáp án:**
  * **Hành vi với Block (Hủy bỏ im lặng):**
    * Tường lửa âm thầm hủy gói tin, không gửi bất kỳ phản hồi nào về cho máy gửi.
    * Phía máy khách (Client): Ứng dụng hoặc trình duyệt không biết gói tin bị chặn nên tiếp tục gửi lại nhiều gói tin thăm dò (TCP Retransmission). Người dùng sẽ thấy trình duyệt xoay vòng chờ đợi trong thời gian dài (khoảng 20 đến 60 giây) trước khi hiển thị thông báo lỗi hết hạn thời gian chờ (`Connection Timed Out`).
  * **Hành vi với Reject (Từ chối chủ động):**
    * Tường lửa hủy gói tin đồng thời lập tức tạo và gửi ngược lại một gói tin báo lỗi tường minh cho máy gửi (gói tin mang cờ `[RST, ACK]` đối với giao thức TCP, hoặc gói tin `ICMP Port Unreachable` đối với UDP).
    * Phía máy khách (Client): Ngay khi nhận được gói tin phản hồi này, ngăn xếp mạng của hệ điều hành lập tức chấm dứt phiên kết nối. Trình duyệt hoặc ứng dụng hiển thị thông báo lỗi ngay lập tức trong tích tắc (`Connection Refused` hoặc `Unable to connect`).

#### Câu 12: Nếu một rule Block có log nhưng Firewall Log không xuất hiện bản ghi, cần kiểm tra theo thứ tự nào?
* **Đáp án:**
  Trình tự kiểm tra chuẩn mực gồm 6 bước:
  1. **Kiểm tra trạng thái kích hoạt ghi nhật ký:** Mở luật Block đó ra, kiểm tra xem mục **Log packets handled by this rule** đã được tích chọn hay chưa.
  2. **Kiểm tra thứ tự luật (First-Match):** Kiểm tra xem có luật nào đặt phía trên đã khớp gói tin trước hay không (nếu gói tin đã bị khớp bởi một luật phía trên thì nó không bao giờ chạm tới luật Block này).
  3. **Kiểm tra sự tồn tại của phiên cũ trong Bảng trạng thái:** Nếu kết nối đã được thiết lập từ trước khi tạo luật Block, gói tin sẽ đi qua bảng trạng thái mà không kích hoạt luật mới. Bắt buộc phải vào `Diagnostics -> States -> Reset States`.
  4. **Kiểm tra tính chính xác của tiêu chí so khớp:** Đối chiếu kỹ lưỡng địa chỉ IP nguồn, IP đích, giao thức (TCP/UDP/ICMP) và cổng dịch vụ của gói tin thực tế gửi đi từ máy khách xem có khớp hoàn toàn với định nghĩa trong luật hay không.
  5. **Kiểm tra bộ lọc hiển thị (Log Filter):** Trong giao diện `System Logs -> Firewall`, kiểm tra xem có đang đặt điều kiện lọc (Filter) làm ẩn mất bản ghi hay không; kiểm tra xem có chọn đúng thẻ giao diện mạng (`LAN` hay `DMZ`) nơi gói tin đi vào hay không.
  6. **Kiểm tra dung lượng bộ đệm nhật ký tròn (Circular Log Buffer):** Trên pfSense, nhật ký được ghi vào bộ đệm cố định dạng vòng tròn (`clog`). Nếu hệ thống có lượng log quá lớn, bản ghi có thể bị ghi đè rất nhanh. Cần tăng kích thước bộ đệm log trong `System Logs -> Settings`.

---

## PHẦN 10: QUY CÁCH ĐÓNG GÓI HỒ SƠ NỘP BÀI VÀ SAO LƯU

1. **Quy chuẩn đặt tên tệp nộp bài:**
   * Tệp báo cáo chính thức dạng Word: `[MãLớp]-Lab6_MSSV-TenSV.docx` (Ví dụ: `CNPM2-Lab6_1150080145-BuiThiMyLinh.docx`).
   * Tệp sao lưu cấu hình toàn bộ hệ thống tường lửa: `config-pfSense-LAB6.xml`.
2. **Danh mục ảnh chụp minh chứng bắt buộc có trong báo cáo:**
   * **Hình 1:** Sơ đồ 4 card mạng trên Oracle VirtualBox của máy ảo `pfSense-LAB6`.
   * **Hình 2:** Kết quả kiểm tra xác thực LDAP thành công cho cả 2 tài khoản `sv_a` và `sv_b` trong `Diagnostics -> Authentication`.
   * **Hình 3:** Giao diện đăng nhập Captive Portal và danh sách phiên hoạt động trong `Status -> Captive Portal`.
   * **Hình 4:** Danh sách toàn bộ các đối tượng Danh mục định danh trong `Firewall -> Aliases`.
   * **Hình 5:** Danh sách cấu hình Lịch trình kiểm soát trong `Firewall -> Schedules`.
   * **Hình 6:** Tập luật hoàn chỉnh trên giao diện LAN (`Firewall -> Rules -> LAN`) thể hiện đúng thứ tự First-Match.
   * **Hình 7:** Minh chứng Kịch bản 1 (Client-A vào được `.10`, bị chặn ở `.20` kèm nhật ký tường lửa).
   * **Hình 8:** Minh chứng Kịch bản 2 (Cả Client-A và Client-B đều bị chặn ở `.40`).
   * **Hình 9:** Minh chứng Kịch bản 3 (Client-B vào được `.30` trong giờ nghỉ và bị chặn ngoài giờ nghỉ).
   * **Hình 10:** Minh chứng Kịch bản 4 (Lưu lượng Web thông suốt, lưu lượng khác bị chặn kèm nhật ký).
   * **Hình 11:** Minh chứng Kịch bản 5 (Client vào được web DMZ, DMZ ping/curl vào DC01 bị chặn).
   * **Hình 12:** Minh chứng Kịch bản 6 (Đối soát thời gian đáp ứng giữa Block và Reject bằng lệnh đo kiểm).
   * **Hình 13:** Bảng trạng thái kết nối trong `Diagnostics -> States` trước và sau khi làm sạch.
3. **Quy trình xuất tệp sao lưu cấu hình `config.xml`:**
   * Trên WebGUI pfSense, điều hướng tới: **Diagnostics** -> **Backup & Restore**.
   * Thẻ **Backup Configuration**:
     * Backup area: Chọn `ALL`.
     * Tích chọn: **Do not backup RRD data** (giúp tệp sao lưu nhỏ gọn và tập trung vào cấu hình luật).
   * Nhấp nút **Download configuration as XML**.
   * Đổi tên tệp tải về thành `config-pfSense-LAB6.xml` và lưu trữ vào thư mục minh chứng nộp bài.

---
*Tài liệu được biên soạn và chuẩn hóa phục vụ học phần An toàn và Bảo mật Hệ thống Thông tin - Năm học 2026.*
