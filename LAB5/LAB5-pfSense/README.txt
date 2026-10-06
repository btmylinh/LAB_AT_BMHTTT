LAB 3 - pfSense FIREWALL CONFIGURATION - v6 FINAL (TEXT-ONLY FIX)
=================================================================

MỤC ĐÍCH GÓI
------------
Gói này chuẩn hóa môi trường thực hành trên pfSense CE 2.7.2-RELEASE (amd64)
để tất cả sinh viên sử dụng cùng một giao diện và cùng quy trình cài đặt offline.
Phiên bản 2.7.2 chỉ dùng cho mạng lab ảo hóa/cô lập; không dùng cho production
hoặc làm firewall Internet-facing.

Không ghi cứng "phiên bản CE mới nhất" trong gói vì phiên bản hiện hành có thể thay đổi.
Khi cần bản mới, kiểm tra tài liệu chính thức:
  https://docs.netgate.com/pfsense/en/latest/releases/versions.html

QUAN TRỌNG VỀ HÌNH ẢNH TRONG TÀI LIỆU
-------------------------------------
Bản v6 này chỉ sửa nội dung hướng dẫn. Toàn bộ hình/giao diện đã chốt ở v4 được giữ nguyên.
Tên interface hoặc lựa chọn mạng hiển thị trong ảnh có thể khác môi trường thực tế; luôn làm theo
chú thích bằng chữ ngay dưới/bên cạnh hình của v6. Hai điểm dễ nhầm: Hình 1 còn mang nhãn topology
cũ cho Host/WAN/DMZ; Hình 10 có thể hiện Alternate DNS 8.8.8.8. Trong v6, bảng IP và phần chữ là
nguồn cấu hình chuẩn: WAN ưu tiên Bridged; Host-only của máy thật không Gateway/DNS; Domain Controller
chỉ dùng DNS 10.0.0.2 trên NIC và đặt DNS công cộng ở DNS Manager -> Forwarders.


YÊU CẦU MÁY THẬT VÀ PHÂN BỔ TÀI NGUYÊN
---------------------------------------
Bài lab hiện dùng nhiều máy ảo. Khuyến nghị máy thật có:
  RAM:            16 GB trở lên
  Đĩa trống:      khoảng 100 GB trở lên (VM + snapshot + bộ cài)
  Ảo hóa CPU:     VT-x/AMD-V đã bật

Phân bổ RAM gợi ý:
  pfSense:        2 GB
  Domain Controller (Windows Server 2019/2022): 2 GB
  DMZ-Web (Windows Server 2019/2022 + IIS):      2 GB
  LAN-Test:       1 GB, dùng Ubuntu Server 22.04/24.04 LTS 64-bit bản minimal

Không cần bật tất cả VM cùng lúc:
  - Tình huống 2: pfSense + Domain Controller + LAN-Test.
  - Tình huống 3: pfSense + Domain Controller + DMZ-Web.
  - Tình huống 4: pfSense + DMZ-Web; Domain Controller có thể tắt vì không tham gia phép thử Port Forward.

KHÔNG clone trực tiếp VM Domain Controller để làm LAN-Test. LAN-Test phải được tạo mới hoặc
dùng template chưa promote thành Domain Controller/chưa join domain. Microsoft có quy trình
cloning DC riêng với các điều kiện hỗ trợ (VM-Generation ID, chuẩn bị nguồn clone, cấu hình
DCCloneConfig.xml...); thao tác clone VM thông thường không được dùng để tạo máy trạm thử nghiệm.

1. NGUỒN TẢI VÀ CHUỖI TIN CẬY
------------------------------
Mirror Netgate:
  https://atxfiles.netgate.com/mirror/downloads/

Tệp cài đặt nén:
  https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.7.2-RELEASE-amd64.iso.gz

Tệp checksum do mirror cung cấp:
  https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.7.2-RELEASE-amd64.iso.gz.sha256

Chuỗi thao tác bắt buộc:
  tải .iso.gz -> kiểm tra SHA-256 -> giải nén -> gắn .iso vào VirtualBox

Không gắn trực tiếp file .iso.gz vào VirtualBox.

2. SHA-256 - KIỂM TRA TRƯỚC KHI GIẢI NÉN
----------------------------------------
Tệp cần kiểm tra:
  pfSense-CE-2.7.2-RELEASE-amd64.iso.gz

SHA-256 mong đợi:
  883fb7bc64fe548442ed007911341dd34e178449f8156ad65f7381a02b7cd9e4

Cách khuyến nghị trên Windows PowerShell (không phụ thuộc ExecutionPolicy):
  Get-FileHash -Algorithm SHA256 .\INSTALL_MEDIA\pfSense-CE-2.7.2-RELEASE-amd64.iso.gz

Nếu muốn dùng script VERIFY_SHA256.ps1, chạy trực tiếp bằng lệnh sau từ thư mục gốc của gói:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\VERIFY_SHA256.ps1

Nếu file tải từ Internet vẫn bị Windows đánh dấu là blocked, có thể chạy:
  Unblock-File .\VERIFY_SHA256.ps1
sau đó chạy lại lệnh Bypass ở trên.

Chỉ tiếp tục khi hash thực tế trùng hoàn toàn với giá trị mong đợi.
Gói này không dùng SHA-256 của file .iso làm giá trị kiểm chứng chính thức vì mirror
công bố checksum cho file .iso.gz.

3. GIẢI NÉN BẰNG 7-ZIP
----------------------
1) Click phải pfSense-CE-2.7.2-RELEASE-amd64.iso.gz.
2) Chọn 7-Zip -> Extract Here (hoặc Extract to...).
3) Sau khi giải nén phải có:
     pfSense-CE-2.7.2-RELEASE-amd64.iso
4) Giữ lại file .iso.gz cho tới khi hoàn tất thực hành để có thể kiểm tra lại nguồn.

4. GẮN ISO VÀO VIRTUALBOX
-------------------------
1) Tắt máy ảo pfSense nếu đang chạy.
2) Mở Oracle VirtualBox Manager.
3) Chọn máy ảo pfSense -> Settings -> Storage.
4) Chọn ổ đĩa quang Empty / Optical Drive.
5) Bấm biểu tượng đĩa quang -> Choose a disk file...
6) Chọn:
     INSTALL_MEDIA\pfSense-CE-2.7.2-RELEASE-amd64.iso
7) Bấm OK và Start máy ảo.
8) Cài theo tài liệu Lab 3.
9) Sau khi cài xong, tháo ISO khỏi ổ đĩa quang để tránh boot lại trình cài đặt.

5. KIỂM TRA XUNG ĐỘT ĐỊA CHỈ TRƯỚC KHI CẤU HÌNH MẠNG
----------------------------------------------------
Bài lab giữ địa chỉ của mô hình gốc:
  LAN: 10.0.0.0/8
  DMZ: 172.16.0.0/16

Trước khi tạo WAN, chạy ipconfig và route print trên máy thật. Kiểm tra Wi-Fi/Ethernet, VPN và các
adapter/route ảo đang hoạt động. WAN và các route đang hoạt động không được overlap với LAN
10.0.0.0/8 hoặc DMZ 172.16.0.0/16.

KHÔNG dùng VirtualBox NAT mặc định 10.0.2.0/24 cho WAN của pfSense vì 10.0.2.0/24
nằm trong LAN 10.0.0.0/8 và sẽ gây chồng lấn subnet.

Thiết lập khuyến nghị:
  Adapter 1 (WAN): Bridged Adapter
  Adapter 2 (LAN): Host-Only
  Adapter 3 (DMZ): Internal Network, Name = dmz-net

Nếu Bridged không dùng được nhưng mạng vật lý của máy thật KHÔNG thuộc 10.0.0.0/8 hoặc
172.16.0.0/16, có thể tạo một NAT Network riêng không chồng lấn, ví dụ 192.168.250.0/24.

Nếu mạng vật lý của máy thật đang dùng 10.x.x.x/8 thì chính Host-only 10.0.0.100/8 cũng
overlap với mạng thật. Trường hợp này KHÔNG được tiếp tục với địa chỉ /8 của bài; phải đổi
LAN lab sang một subnet khác theo hướng dẫn của giảng viên và đổi đồng bộ toàn bộ địa chỉ.

6. CẤU HÌNH HOST-ONLY TRÊN MÁY THẬT
-----------------------------------
Trong VirtualBox Manager:
  File/Tools -> Network Manager -> Host-Only Networks

Chọn host-only network dùng cho LAN và đặt:
  IPv4 host interface: 10.0.0.100
  Mask:                255.0.0.0
  DHCP Server:         Disabled

Card Host-only trên máy thật chỉ dùng để quản trị lab:
  Default Gateway: để trống
  DNS:             để trống

Không đặt Gateway = 10.0.0.1 hoặc DNS = 10.0.0.2 trên card phụ Host-only vì có thể
làm thay đổi route hoặc DNS của hệ điều hành host.

7. TÊN CARD MẠNG TRÊN CONSOLE pfSense
-------------------------------------
Tên card phụ thuộc loại NIC ảo:
  VirtIO:            vtnet0, vtnet1, vtnet2
  Intel PRO/1000:    thường là em0, em1, em2

Không xác định vai trò WAN/LAN/DMZ chỉ bằng tên card. Đối chiếu MAC address và thứ tự:
  Adapter 1 = WAN
  Adapter 2 = LAN
  Adapter 3 = DMZ

8. OUTBOUND NAT VÀ DMZ - ĐIỂM DỄ NHẦM
-------------------------------------
Trong Automatic Outbound NAT và Hybrid Outbound NAT, pfSense duy trì Automatic Rules
cho các mạng nội bộ. Sau khi DMZ được gán đúng và không có Upstream Gateway, kiểm tra
Firewall -> NAT -> Outbound -> Automatic Rules.

Không cần tạo manual Outbound NAT chỉ để LAN/DMZ ra Internet trong phần cơ bản.
DMZ mới tạo không ra Internet chủ yếu vì tab Firewall -> Rules -> DMZ chưa có rule Pass.

Khi có rule Pass DMZ -> Internet phù hợp:
  - DMZ có thể ra Internet nhờ automatic NAT.
  - DMZ-Web có thể đặt DNS 8.8.8.8 để kiểm thử.
  - Nếu cần cô lập DMZ khỏi LAN, đặt Block DMZ net -> LAN net ở TRÊN Pass DMZ net -> Any.

Nếu không thấy automatic NAT cho DMZ, kiểm tra lại interface DMZ không có Upstream Gateway,
Save/Apply rồi xem lại Automatic Rules trước khi tự tạo manual rule.

9. DEFAULT LAN RULE VÀ STATE TABLE - BẮT BUỘC TRƯỚC KHI TEST FIREWALL
--------------------------------------------------------------------
pfSense mặc định có:
  - Default allow LAN to any (IPv4)
  - Default allow LAN to any (IPv6)
  - Anti-Lockout Rule

Trước khi làm bài bật/tắt rule:
1) Firewall -> Rules -> LAN.
2) Disable cả hai Default allow LAN to any IPv4/IPv6.
3) GIỮ Anti-Lockout Rule để không tự khóa WebGUI.
4) Apply Changes.
5) Diagnostics -> States -> Reset States.
6) Chọn State Table -> Reset -> xác nhận.
7) Sau đó mới tạo rule LAN net -> Any do sinh viên tự quản lý.

Khi thay đổi rule/NAT để kiểm thử:
  - Dừng ping -t hoặc đóng kết nối cũ.
  - Apply Changes.
  - Reset States.
  - Tạo kết nối/ping mới.

pfSense là stateful firewall; nếu không xóa state, một kết nối cũ có thể tiếp tục hoạt động
sau khi rule đã bị Disable và làm sinh viên rút ra kết luận sai.

Lưu ý: Diagnostics -> Ping chạy từ chính pfSense chỉ kiểm tra firewall/WAN có ra Internet hay không.
Nó không đi qua rule trên tab LAN. Muốn chứng minh rule LAN, phải test từ Domain Controller
hoặc LAN-Test.

10. DOMAIN CONTROLLER - TÁCH TEST IP VÀ DNS
------------------------------------------
Domain Controller:
  IP:      10.0.0.2/8
  Gateway: 10.0.0.1
  DNS:     10.0.0.2

Sau khi cài AD DS/DNS, trong DNS Manager cấu hình Forwarder, ví dụ 8.8.8.8 hoặc DNS upstream
được môi trường cho phép.

Khi kiểm thử:
  ping 8.8.8.8
    -> kiểm tra kết nối IP qua firewall

  Resolve-DnsName example.com -Server 8.8.8.8
  hoặc nslookup example.com 8.8.8.8
    -> kiểm tra trực tiếp rule DNS ra upstream (thay 8.8.8.8 nếu lớp dùng DNS upstream khác)

  curl.exe -4 https://example.com
    -> kiểm tra HTTPS IPv4

Không dùng duy nhất ping google.com để kết luận lỗi firewall vì nó đồng thời phụ thuộc DNS.

11. DỰNG MÁY DMZ-WEB - BẮT BUỘC CHO TÌNH HUỐNG 3 VÀ 4
------------------------------------------------------
Tạo VM tên DMZ-Web:
  OS: Windows Server 2019/2022 (không join domain)
  RAM: 2 GB
  NIC: Internal Network, Name = dmz-net
  IP: 172.16.0.2
  Mask: 255.255.0.0
  Gateway: 172.16.0.1
  DNS: để trống lúc dựng; đặt 8.8.8.8 sau khi có Pass DMZ -> Internet

Bật IIS trên DMZ-Web bằng PowerShell Administrator:
  Install-WindowsFeature Web-Server -IncludeManagementTools

Kiểm tra ngay trên DMZ-Web:
  curl.exe http://localhost

Phải xác nhận IIS hoạt động trước khi làm Port Forward.

12. TÌNH HUỐNG CÔ LẬP DMZ - CÁCH CHỨNG MINH ĐÚNG
------------------------------------------------
Windows Server có thể chặn ICMP inbound, vì vậy ping thất bại chưa đủ để kết luận pfSense chặn.

Trước khi test, trên Domain Controller chạy với quyền Administrator:
  netsh advfirewall firewall add rule name="LAB-Allow-ICMPv4-Echo" protocol=icmpv4:8,any dir=in action=allow

Baseline:
1) Trên tab DMZ chỉ bật Pass DMZ net -> Any.
2) Apply Changes và Reset States.
3) Từ DMZ-Web ping 10.0.0.2.
4) Bắt buộc phải nhận reply trước khi thêm Block.

Test cô lập:
1) Thêm Block DMZ net -> LAN net ở TRÊN Pass DMZ net -> Any.
2) Apply Changes và Reset States.
3) Chạy ping 10.0.0.2 mới từ DMZ-Web: phải thất bại.
4) Ping 8.8.8.8 / DNS Internet từ DMZ-Web vẫn hoạt động nếu rule Pass Internet đang bật.

Sau bài có thể xóa rule ICMP tạm trên DC:
  netsh advfirewall firewall delete rule name="LAB-Allow-ICMPv4-Echo"

13. TÌNH HUỐNG CHỈ CHO MỘT HOST LAN RA INTERNET
-----------------------------------------------
Không dùng máy thật 10.0.0.100 làm host thứ hai vì card Host-only của máy thật không có
Default Gateway qua pfSense.

Tạo thêm VM nhẹ LAN-Test:
  OS:      Ubuntu Server 22.04/24.04 LTS 64-bit (minimal)
  RAM:     1 GB
  IP:      10.0.0.3/8
  Gateway: 10.0.0.1

Không clone trực tiếp từ VM Domain Controller để tạo LAN-Test; hãy tạo VM độc lập hoặc dùng
template chưa promote thành DC/chưa join domain.

Disable rule nền tảng LAN net -> Any rồi tạo theo thứ tự:
  1) Pass  10.0.0.2 -> Any
  2) Block LAN net  -> Any

Apply Changes + Reset States.

Kiểm thử:
  10.0.0.2 ping 8.8.8.8 -> thành công
  10.0.0.3 ping 8.8.8.8 -> thất bại

14. PORT FORWARD WAN -> DMZ
---------------------------
Điều kiện trước:
  - DMZ-Web 172.16.0.2 đang chạy IIS.
  - curl.exe http://localhost trên DMZ-Web thành công.

Cách khuyến nghị: WAN = Bridged Adapter.
Nếu WAN nhận IP private của mạng vật lý, trong Interfaces -> WAN của pfSense bỏ tick:
  Block private networks
  Block bogon networks
trong môi trường lab để cho phép máy thật kiểm thử vào WAN. Save/Apply.
Không áp dụng cách này cho firewall Internet-facing thực tế.

Tạo pfSense Port Forward:
  Interface:              WAN
  Protocol:               TCP
  Destination:            WAN address
  Destination port:       8080
  Redirect target IP:     172.16.0.2
  Redirect target port:   80
  Filter rule association: Add associated filter rule

Save -> Apply Changes -> Reset States.
Từ máy thật truy cập:
  http://<IP-WAN-pfSense>:8080

Phải thấy trang IIS của DMZ-Web.

Nếu Bridged không dùng được:
1) Tạo VirtualBox NAT Network riêng, ví dụ 192.168.250.0/24.
2) Gắn Adapter 1 của pfSense vào NAT Network đó.
3) Vì WAN này vẫn là private network, trên Interfaces -> WAN bỏ tick Block private networks và
   Block bogon networks trong lúc kiểm thử lab.
4) Ghi lại IP WAN pfSense nhận trong 192.168.250.0/24.
5) Network Manager -> NAT Networks -> Port Forwarding:
     Host TCP 18080 -> <IP-WAN-pfSense>:8080
6) Từ máy thật truy cập:
     http://127.0.0.1:18080

Không dùng NAT mặc định 10.0.2.0/24 cho bài này vì overlap LAN 10.0.0.0/8.

15. PHẠM VI HƯỚNG DẪN
---------------------
Hướng dẫn trong Lab 3 áp dụng cho ISO offline pfSense CE 2.7.2. Các bản pfSense hiện hành
có thể dùng quy trình cài đặt/giao diện khác. Không thay bộ cài bằng phiên bản khác rồi làm
rập khuôn theo ảnh 2.7.2 mà không đối chiếu tài liệu Netgate.

16. CẤU TRÚC GÓI
----------------
Gói READY_FOR_MEDIA được phát kèm tài liệu và công cụ kiểm tra; binary cài đặt không được
coi là đã có cho tới khi thư mục INSTALL_MEDIA thực sự chứa file tải từ mirror Netgate.

Lab3-pfSense_STUDENT_PACKAGE_v6_FINAL_TEXT_ONLY/
  Lab3-pfSense_SAMPLE_STYLE_SPLIT_FIGURES_v6_FINAL_TEXT_ONLY.docx
  README.txt
  SHA256SUMS.txt
  VERIFY_SHA256.ps1
  DOWNLOAD_OFFICIAL_ARCHIVE.url
  DOWNLOAD_OFFICIAL_SHA256.url
  INSTALL_MEDIA/
    PLACE_INSTALL_MEDIA_HERE.txt

Sau khi sinh viên/giảng viên tải và kiểm tra đúng checksum, thư mục INSTALL_MEDIA sẽ có:
  pfSense-CE-2.7.2-RELEASE-amd64.iso.gz   (file tải và kiểm tra SHA-256)
  pfSense-CE-2.7.2-RELEASE-amd64.iso      (file sinh ra sau giải nén; dùng để gắn VirtualBox)

Không được hiểu file .iso là có sẵn trong ZIP READY_FOR_MEDIA nếu chưa tự tải/giải nén.

CẢNH BÁO BẢO MẬT
----------------
pfSense CE 2.7.2 là bản cũ. Chỉ dùng cho bài lab cô lập. Không nối trực tiếp máy ảo này
vào hạ tầng production và không dùng làm firewall bảo vệ hệ thống thật.
