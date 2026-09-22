# BÀI THỰC HÀNH 3: NHẬN DIỆN VÀ ỨNG PHÓ CÁC MỐI ĐE DỌA ĐẾN AN TOÀN THÔNG TIN
### Identifying and Responding to Information Security Threats

---

## TỔNG QUAN

### Mục tiêu
1. Phân biệt đúng bốn khái niệm cốt lõi: Điểm yếu/Lỗ hổng (Vulnerability), Mối đe dọa (Threat), Rủi ro (Risk) và Tấn công (Attack), đồng thời liên hệ chúng với tài sản cụ thể trên một máy trạm Windows.
2. Nhận diện năm nhóm nguồn đe dọa: Hành động vô ý, hành động cố ý, thảm họa tự nhiên, lỗi kỹ thuật và lỗi quản lý.
3. Quan sát và thu thập bằng chứng cho các nhóm kỹ thuật: Mã độc, tấn công mật khẩu, ghi thao tác bàn phím (keylogging), cửa sau và duy trì khởi động (backdoor/persistence), tấn công từ chối dịch vụ (DoS/DDoS), dội bom hộp thư (mail bombing), nghe lén gói tin (sniffing), kẻ đứng giữa (man-in-the-middle), giả mạo (spoofing) và tấn công tâm lý lừa đảo (social engineering/phishing).
4. Sử dụng thành thạo các công cụ giám sát: Microsoft Defender, Windows Event Log, Sysmon, Autoruns, Process Explorer và Wireshark để thu thập bằng chứng từ máy trạm và đường truyền mạng.
5. Thực hiện nghiêm ngặt chu trình chuẩn: Baseline (Lấy chuẩn) -> Observe (Quan sát) -> Detect (Phát hiện) -> Contain (Cô lập) -> Recover (Phục hồi) -> Verify (Kiểm chứng).
6. Tạo báo cáo có thể tái lập: Ghi rõ phiên bản môi trường, câu lệnh đã chạy, kết quả quan sát, ảnh chụp trực tiếp từ máy tính/máy ảo, tệp nhật ký và bảng băm SHA-256 của toàn bộ bằng chứng.

---

### Kiến thức nền

| Khái niệm | Định nghĩa áp dụng trong bài thực hành |
| :--- | :--- |
| **Lỗ hổng (Vulnerability)** | Điểm yếu của tổ chức, hệ thống công nghệ thông tin hoặc mạng có thể bị một mối đe dọa khai thác. |
| **Mối đe dọa (Threat)** | Yếu tố hoặc sự kiện có khả năng gây thiệt hại cho tổ chức, hệ thống công nghệ thông tin hoặc mạng. |
| **Rủi ro (Risk)** | Khả năng mối đe dọa khai thác lỗ hổng của tài sản và gây ra tổn thất cụ thể. |
| **Tấn công (Attack)** | Hành động khai thác một điểm yếu đã xác định nhằm gây thiệt hại hoặc đánh cắp thông tin. |

Năm nhóm nguồn đe dọa cần phân loại trong báo cáo gồm:
* Hành động vô ý.
* Hành động cố ý.
* Thảm họa tự nhiên.
* Lỗi kỹ thuật (phần cứng hoặc phần mềm).
* Lỗi quản lý.

---

### Kịch bản thực hành
Một máy trạm Windows thuộc mạng đào tạo xuất hiện nhiều dấu hiệu bất thường cần đánh giá:
* Cảnh báo từ phần mềm phòng vệ điểm cuối.
* Các lần đăng nhập thất bại liên tiếp.
* Một mục tự khởi động không được phê duyệt xuất hiện trong hệ thống.
* Một tiến trình lạ đang mở cổng lắng nghe kết nối cục bộ.
* Lưu lượng mạng HTTP chứa dữ liệu đọc được dưới dạng văn bản rõ.
* Lưu lượng mạng HTTPS được mã hóa bảo vệ.
* Một thông điệp thư điện tử mang dấu hiệu lừa đảo.

Người thực hành đóng vai trò nhân sự an toàn thông tin, tiến hành phân loại sự cố (triage), thu thập bằng chứng số, nhận diện mối đe dọa, đánh giá rủi ro và khôi phục máy trạm về trạng thái an toàn chuẩn.

---

### Môi trường và công cụ chuẩn hóa trong bài thực hành

| Thành phần | Phiên bản đề bài yêu cầu | Cấu hình thực tế tận dụng từ nhật ký | Vai trò trong bài thực hành |
| :--- | :--- | :--- | :--- |
| **Ảo hóa** | VMware Workstation Pro | VMware Workstation Pro đã cài trên máy thật | Dùng chức năng chụp điểm lưu (Snapshot); card mạng Host-only là mặc định. |
| **Máy ảo máy trạm** | Windows 11 25H2 x64 | **Windows 10 Enterprise LTSC 64-bit** (`Windows10.vmx`) | Đã có sẵn trong nhật ký cài đặt; tích hợp sẵn Microsoft Defender, Event Log, PowerShell 5.1; đáp ứng trọn vẹn 100% các tình huống của bài lab. |
| **Bảo vệ điểm cuối** | Microsoft Defender Antivirus | Microsoft Defender Antivirus tích hợp sẵn trong máy ảo | Tính năng bảo vệ thời gian thực (Real-time protection) và Tamper Protection luôn giữ bật. |
| **Môi trường lệnh** | Windows PowerShell 5.1 | Windows PowerShell 5.1 tích hợp sẵn | Mở chế độ quản trị viên (Run as administrator) cho các bước cần quyền hệ thống. |
| **Sysmon** | 15.22 | Bộ Microsoft Sysinternals Sysmon64 | Cấu hình schema tối thiểu 4.90 ghi nhận sự kiện tiến trình, mạng, tệp tin. |
| **Autoruns** | 14.3 | Bộ Microsoft Sysinternals Autoruns64 | Quét và kiểm tra các điểm cắm tự khởi động (Persistence). |
| **Process Explorer**| 17.14 | Bộ Microsoft Sysinternals procexp64 | Định danh cây tiến trình, chữ ký số và ánh xạ cổng mạng mở. |
| **Wireshark** | 4.6.8 Stable + Npcap | Wireshark 4.6.8 đã có sẵn | Thu thập gói tin trên giao tiếp nội bộ (Loopback) và card mạng máy ảo. |
| **Python** | 3.14 / 3.x | Python 3.x tích hợp | Dùng làm máy chủ HTTP cục bộ và chạy kịch bản thử tải giới hạn trên `127.0.0.1`. |
| **Gói dữ liệu bài lab**| `LAB3_Threats_Assets.zip` | Thư mục `lab3_assets` giải nén sẵn | Chứa đầy đủ dữ liệu mẫu, kịch bản Python và tệp cấu hình. |

---

## NGUỒN TẢI VÀ CÁCH DỰNG MÔI TRƯỜNG

### Bước 1: Chuẩn bị máy ảo và thiết lập mạng cách ly
1. Mở phần mềm **VMware Workstation Pro**.
2. Nạp máy ảo máy trạm có sẵn từ đường dẫn: `D:\University\Y4-5 AT&BM HTTT\Tools\VM-Windows10-Lab\Windows10.vmx`.
3. Trong giao diện VMware, chọn **VM** -> **Settings...** -> chọn mục **Network Adapter** -> tích chọn chế độ **Host-only: A private network shared with the host**.
4. Khởi động máy ảo (Tài khoản: `win10` / Mật khẩu: `win10`).
5. Trong máy ảo, nhấn tổ hợp phím **Windows + R**, gõ lệnh `winver` và nhấn Enter để mở hộp thoại thông tin phiên bản Windows.
6. Trước khi can thiệp bất kỳ lệnh nào, tạo ngay một điểm chụp hệ thống sạch trên VMware: Chọn **VM** -> **Snapshot** -> **Take Snapshot...**, đặt tên là `LAB3_CLEAN_BASELINE`.

> ### ẢNH CHỤP BẮT BUỘC 1 (HÌNH 1 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ VMware Workstation Pro thể hiện rõ cấu hình Network Adapter của máy ảo là **Host-only**; bên cạnh mở cửa sổ tiện ích **winver** hiển thị phiên bản hệ điều hành của máy ảo.
> * **Tên tệp hình ảnh lưu trữ:** `H1_VM_WindowsVersion.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH 1 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 1.

---

### Bước 2: Tạo cấu trúc thư mục bài lab
Mở **Windows PowerShell** với quyền quản trị viên (**Run as administrator**) trên máy ảo và chạy các lệnh sau (chỉ nhập phần lệnh):

```powershell
$Lab = 'C:\LAB3'
New-Item -ItemType Directory -Force "$Lab\Evidence", "$Lab\Tools", "$Lab\Downloads", "$Lab\Assets" | Out-Null
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz' | Out-File "$Lab\Evidence\start_time.txt"
```

---

### Bước 3: Đưa gói dữ liệu bài lab vào máy ảo
1. Chuyển tệp nén hoặc thư mục tài nguyên `lab3_assets` (nằm tại máy thật `D:\University\Y4-5 AT&BM HTTT\TH\LAB3\LAB3_Threats_Assets`) vào thư mục `C:\LAB3\Downloads` hoặc `C:\LAB3\lab3_assets` trên máy ảo.
2. Kiểm tra mã băm gói tài nguyên bằng lệnh PowerShell nếu sử dụng tệp nén `LAB3_Threats_Assets.zip`:
   ```powershell
   Get-FileHash C:\LAB3\Downloads\LAB3_Threats_Assets.zip -Algorithm SHA256
   Expand-Archive C:\LAB3\Downloads\LAB3_Threats_Assets.zip -DestinationPath C:\LAB3 -Force
   ```
3. Đảm bảo thư mục `C:\LAB3\lab3_assets` chứa đầy đủ các thư mục con: `data`, `samples`, `scripts`, `www` và tệp cấu hình `sysmon-lab.xml`.

---

### Bước 4: Cài đặt hoặc xác nhận Python và Wireshark
Kiểm tra tính sẵn sàng của Python và công cụ dòng lệnh Wireshark trên máy ảo:

```powershell
python --version
& 'C:\Program Files\Wireshark\tshark.exe' --version | Select-Object -First 1
```
*(Nếu máy ảo chưa có, tiến hành cài đặt Python và Wireshark kèm Npcap để đảm bảo tính năng bắt gói tin cục bộ).*

---

### Bước 5: Bố trí bộ công cụ Sysinternals và kiểm tra phiên bản
1. Giải nén các công cụ `Sysmon.zip`, `Autoruns.zip`, `ProcessExplorer.zip` vào đường dẫn `C:\LAB3\Tools`:
   * `C:\LAB3\Tools\Sysmon\Sysmon64.exe`
   * `C:\LAB3\Tools\Autoruns\Autoruns64.exe`
   * `C:\LAB3\Tools\ProcessExplorer\procexp64.exe`
2. Chạy khối lệnh xác nhận phiên bản của tất cả các công cụ thực hành:
   ```powershell
   $T = 'C:\LAB3\Tools'
   python --version
   & 'C:\Program Files\Wireshark\tshark.exe' --version | Select-Object -First 1
   (Get-Item "$T\Sysmon\Sysmon64.exe").VersionInfo | Select-Object FileVersion, ProductVersion
   (Get-Item "$T\Autoruns\Autoruns64.exe").VersionInfo | Select-Object FileVersion, ProductVersion
   (Get-Item "$T\ProcessExplorer\procexp64.exe").VersionInfo | Select-Object FileVersion, ProductVersion
   ```

> ### ẢNH CHỤP BẮT BUỘC 2 (HÌNH 2 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ PowerShell hiển thị đầy đủ kết quả phiên bản của Python, Wireshark (tshark), Sysmon, Autoruns và Process Explorer sau khi thực thi các lệnh ở Bước 5.
> * **Tên tệp hình ảnh lưu trữ:** `H2_ToolVersions.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH 2 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 5.

---

## NỘI DUNG BÀI HỌC VÀ TÌNH HUỐNG THỰC HÀNH

### Bảng tương quan giữa bài học và các tình huống thực nghiệm

| Nội dung bài học | Tình huống áp dụng | Bằng chứng và chức năng chính |
| :--- | :--- | :--- |
| **Vulnerability – Threat – Risk – Attack** | Tình huống 1: Baseline và risk register | Phân loại tài sản, điểm yếu, mối đe dọa, rủi ro. |
| **5 nhóm nguồn đe dọa** | Tình huống 1 | Phân loại 5 nguồn đe dọa bằng các tình huống cụ thể. |
| **Malware (Mã độc)** | Tình huống 2 | Chuỗi kiểm thử EICAR và cơ chế Defender detection/quarantine. |
| **Password attacks & Keylogging** | Tình huống 3 | Bản ghi sự kiện 4624/4625/4648, xoay vòng mật khẩu, phân tích keylogger. |
| **Backdoor & Persistence** | Tình huống 4 | Cơ chế khởi động lành tính và dịch vụ lắng nghe loopback qua Autoruns/Sysmon/Process Explorer. |
| **Sniffing / MITM / Spoofing** | Tình huống 5 | Bắt gói HTTP loopback, so sánh với TLS, phân tích các biến thể MITM. |
| **DoS / DDoS** | Tình huống 6 | Đo tải cục bộ giới hạn trên loopback và phân tích tập dữ liệu DDoS TEST-NET. |
| **Mail bombing** | Tình huống 6 | Phân tích tệp nhật ký thư điện tử ngoại tuyến, thống kê tần suất và dung lượng. |
| **Social Engineering / Phishing** | Tình huống 7 | Phân tích mẫu thư điện tử ngoại tuyến và phân loại 6 trường hợp thực tế. |

### Quy ước bằng chứng số
* Mọi hình ảnh trong báo cáo bắt buộc phải là ảnh chụp màn hình trực tiếp từ máy ảo/máy thật của sinh viên trong quá trình thực hành.
* Các lệnh thực thi phải lưu trữ kết quả đầu ra vào thư mục `C:\LAB3\Evidence` bằng lệnh `Tee-Object` hoặc `Out-File`.
* Tuyệt đối không nhập tài khoản thật, mật khẩu cá nhân hay dữ liệu nhạy cảm vào môi trường thực hành.
* Trình bảo vệ Microsoft Defender và Tamper Protection luôn duy trì trạng thái bật trong suốt bài lab.

---

## THỰC HÀNH

---

### Baseline trước khi tạo tình huống
Lấy dữ liệu đối chứng ban đầu để phân biệt những thay đổi do bài thực hành tạo ra so với trạng thái gốc của hệ điều hành.

* **Thực thi trong cửa sổ PowerShell (Administrator):**
  ```powershell
  $E = 'C:\LAB3\Evidence'
  Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture | Format-List | Tee-Object "$E\baseline_os.txt"
  Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureVersion | Format-List | Tee-Object "$E\baseline_defender.txt"
  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -Auto | Tee-Object "$E\baseline_firewall.txt"
  Get-NetIPConfiguration | Format-List | Out-File "$E\baseline_network.txt" -Width 220
  Get-Process | Sort-Object ProcessName | Select-Object ProcessName, Id, Path | Out-File "$E\baseline_processes.txt" -Width 220
  ```

> ### ẢNH CHỤP BẮT BUỘC 3 (HÌNH H3 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ PowerShell hiển thị kết quả của lệnh `Get-MpComputerStatus` có giá trị `RealTimeProtectionEnabled = True`, `AntivirusEnabled = True` và bảng trạng thái tường lửa đang bật bảo vệ.
> * **Tên tệp hình ảnh lưu trữ:** `H3_Baseline_Defender_Firewall.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H3 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới mục Baseline.

---

### Tình huống 1 – Xác định tài sản, lỗ hổng, mối đe dọa và rủi ro

Sinh viên hoàn thành bảng Risk Register cho tối thiểu 5 tài sản cốt lõi trên máy trạm và phân loại 5 tình huống nguồn đe dọa.

#### 1. Bảng hồ sơ quản lý rủi ro (Risk Register) mẫu hoàn chỉnh

| STT | Tài sản (Asset) | Lỗ hổng (Vulnerability) | Mối đe dọa (Threat) | Rủi ro (Risk) | Biện pháp kiểm soát (Control) |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | Thông tin xác thực tài khoản quản trị máy trạm | Mật khẩu ngắn, dùng chung hoặc bị gõ trên máy nghi có mã độc | Tấn công dò mật khẩu vét cạn, lừa đảo (Phishing), phần mềm ghi phím (Keylogger) | Mất quyền kiểm soát máy trạm, bị leo thang đặc quyền quản trị | Chính sách mật khẩu phức tạp, kích hoạt kiểm toán đăng nhập, xác thực FIDO2/Passkey |
| **2** | Dữ liệu chứng cứ số trong thư mục `C:\LAB3` | Thư mục chưa giới hạn quyền truy cập, thiếu chính sách sao lưu tự động | Mã độc tống tiền (Ransomware), thao tác xóa nhầm của người dùng | Mất tính toàn vẹn hoặc mất hoàn toàn dữ liệu bằng chứng điều tra | Phân quyền đặc quyền tối thiểu, tạo bản sao lưu định kỳ, lưu trữ bảng băm SHA-256 |
| **3** | Dịch vụ web cục bộ mở trên cổng 8080 | Ứng dụng thiếu cơ chế xác thực, mã nguồn không kiểm soát đầu vào | Cửa sau (Backdoor), tấn công làm tràn tài nguyên (DoS) | Dịch vụ bị khai thác trái phép hoặc bị tê liệt gián đoạn | Giới hạn chỉ lắng nghe trên giao tiếp nội bộ `127.0.0.1`, cấu hình tường lửa chỉ mở cổng khi cần |
| **4** | Kênh truyền thông tin dữ liệu mạng | Sử dụng giao thức văn bản rõ HTTP không mã hóa | Nghe lén gói tin (Sniffing), tấn công kẻ đứng giữa (MITM) | Bị trích xuất lộ lọt thông tin nhạy cảm và tham số phiên làm việc | Chuyển dịch sang sử dụng giao thức HTTPS/TLS, bật cơ chế HSTS trên máy chủ |
| **5** | Hộp thư điện tử và người dùng cuối | Người dùng thiếu kỹ năng nhận diện thư mạo danh | Thư lừa đảo (Phishing), lừa đảo có chủ đích (Spear Phishing) | Người dùng vô tình cung cấp mã xác thực hoặc tải mã độc về máy | Đào tạo nâng cao nhận thức an toàn thông tin, triển khai bộ lọc thư rác, xác thực đa yếu tố |

#### 2. Bài tập phân loại 5 tình huống nguồn đe dọa

| Mã | Tình huống cần phân loại | Nhóm nguồn đe dọa tương ứng | Căn cứ giải thích |
| :---: | :--- | :--- | :--- |
| **1** | Nhân viên xóa nhầm tệp cấu hình đang dùng. | **Hành động vô ý** | Do sơ suất, bất cẩn trong thao tác của con người nội bộ mà hoàn toàn không có động cơ phá hoại. |
| **2** | Người có ác ý cài phần mềm thu thập dữ liệu. | **Hành động cố ý** | Có mục đích rõ ràng, chủ động xâm nhập nhằm đánh cắp thông tin bí mật và gây hại cho hệ thống. |
| **3** | Mất điện kéo dài làm dịch vụ dừng và file chưa ghi bị mất. | **Thảm họa tự nhiên / Môi trường** | Biến cố hạ tầng vật lý ngoại cảnh bất khả kháng, nằm ngoài khả năng kiểm soát trực tiếp của phần mềm. |
| **4** | Ổ đĩa hỏng hoặc dịch vụ treo do lỗi phần mềm. | **Lỗi kỹ thuật** | Bắt nguồn từ sự suy hao cơ học của thiết bị phần cứng hoặc khiếm khuyết trong mã lệnh phần mềm. |
| **5** | Tổ chức không áp dụng chính sách sao lưu/vá lỗi dù đã có quy định. | **Lỗi quản lý** | Thiếu sót trong công tác giám sát, thực thi chính sách và kiểm soát quy trình vận hành của cấp lãnh đạo. |

---

### Tình huống 2 – Mã độc: kiểm chứng chu trình phát hiện bằng EICAR

Chuỗi kiểm thử EICAR là tệp mẫu an toàn tiêu chuẩn quốc tế giúp kiểm tra phản ứng của trình bảo vệ chống mã độc mà không gây bất kỳ rủi ro nào cho máy tính.

* **Bước 1: Xác minh Microsoft Defender đang bật bảo vệ thời gian thực**
  ```powershell
  Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected
  ```

* **Bước 2: Tạo tệp kiểm thử EICAR trong thư mục bằng chứng**
  Thực thi trong PowerShell (Administrator):
  ```powershell
  $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  try {
      Set-Content -Path C:\LAB3\Evidence\eicar.com.txt -Value $eicar -NoNewline -Encoding Ascii
  } catch {
      $_ | Out-File C:\LAB3\Evidence\eicar_write_error.txt
  }
  Start-Sleep -Seconds 5
  Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5 ThreatID, InitialDetectionTime, Resources, ActionSuccess | Format-List | Tee-Object C:\LAB3\Evidence\defender_eicar.txt
  ```

* **Bước 3: Mở giao diện Windows Security kiểm tra lịch sử ngăn chặn**
  1. Vào **Start** -> mở **Windows Security**.
  2. Chọn mục **Virus & threat protection** -> nhấn vào liên kết **Protection history**.
  3. Bấm vào bản ghi phát hiện có tên liên quan đến `EICAR` để xem chi tiết thời gian, đường dẫn tệp và hành động xử lý (Blocked/Quarantined).
  4. *Cảnh báo:* Tuyệt đối không chọn hành động "Allow on device".

> ### ẢNH CHỤP BẮT BUỘC 4 (HÌNH H4 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Giao diện Windows Security mục Protection history hiển thị rõ ràng bản ghi phát hiện chuỗi thử nghiệm EICAR bị chặn/cách ly; ảnh thể hiện rõ thời gian, tên nhận diện mối đe dọa khớp với kết quả trích xuất dòng lệnh.
> * **Tên tệp hình ảnh lưu trữ:** `H4_ProtectionHistory_EICAR.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H4 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Tình huống 2.

---

### Tình huống 3 – Tấn công mật khẩu và nguy cơ keylogging

Sinh viên tạo danh tính thử nghiệm cục bộ, sinh các sự kiện đăng nhập hợp lệ và không hợp lệ, phân tích dấu vết trong Security Log và thực hiện xoay vòng mật khẩu.

* **Bước 1: Bật kiểm toán đăng nhập và tạo tài khoản thử nghiệm `lab3user`**
  ```powershell
  auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
  $pw = Read-Host 'Nhap mat khau chi dung cho LAB3' -AsSecureString
  New-LocalUser -Name 'lab3user' -Password $pw -FullName 'LAB3 Test User' -Description 'Temporary account for authentication logging lab'
  Get-LocalUser -Name 'lab3user'
  ```

* **Bước 2: Sinh lần đăng nhập thành công**
  Chạy lệnh chuyển quyền:
  ```powershell
  runas /user:.\lab3user cmd.exe
  ```
  Nhập chính xác mật khẩu đã đặt khi cửa sổ yêu cầu. Trong cửa sổ Command Prompt mới hiện ra, chạy lệnh `whoami` để xác nhận rồi đóng cửa sổ.

* **Bước 3: Sinh hai lần đăng nhập thất bại có kiểm soát**
  Chạy lại lệnh sau hai lần liên tiếp và cố ý gõ sai mật khẩu ở cả hai lần:
  ```powershell
  runas /user:.\lab3user cmd.exe
  ```

* **Bước 4: Trích xuất nhật ký bảo mật trong hai mươi phút gần nhất**
  ```powershell
  $start = (Get-Date).AddMinutes(-20)
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648; StartTime=$start} |
      Where-Object { $_.Message -match 'lab3user' } |
      Select-Object TimeCreated, Id, Message |
      Out-File C:\LAB3\Evidence\auth_events_before_rotation.txt -Width 260
  ```

* **Bước 5: Mở Trình xem sự kiện (Event Viewer) để kiểm tra bằng giao diện**
  1. Nhấn **Windows + R**, gõ `eventvwr.msc` và nhấn Enter.
  2. Mở theo nhánh: **Windows Logs** -> **Security**.
  3. Chọn **Filter Current Log...** ở cột bên phải, nhập các mã: `4624, 4625, 4648`.
  4. Chọn bản ghi sự kiện có mã **4625** liên quan đến tài khoản `lab3user` để xem chi tiết thẻ General.

> ### ẢNH CHỤP BẮT BUỘC 5 (HÌNH H5 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Event Viewer tại mục Security hiển thị sự kiện Event ID 4625 liên quan đến tài khoản `lab3user`; phần General phải hiển thị rõ tên tài khoản, thời gian và lý do xác thực thất bại.
> * **Tên tệp hình ảnh lưu trữ:** `H5_Event4625.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H5 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Tình huống 3.

* **Bước 6: Đổi mật khẩu của `lab3user` và kiểm chứng vô hiệu hóa mật khẩu cũ**
  ```powershell
  $newPw = Read-Host 'Nhap mat khau LAB3 sau khi doi' -AsSecureString
  Set-LocalUser -Name 'lab3user' -Password $newPw

  # Kiem chung 1: Dung mat khau CU (Phai that bai - sinh them Event 4625)
  runas /user:.\lab3user cmd.exe

  # Kiem chung 2: Dung mat khau MOI (Phai thanh cong - sinh Event 4624)
  runas /user:.\lab3user cmd.exe
  ```

* **Nội dung phân tích về nguy cơ ghi nhận thao tác bàn phím (Keylogging):**
  * *Bản chất:* Phần mềm ghi nhận bàn phím đánh cắp thông tin ngay tại điểm nhập liệu của người dùng trước khi mật khẩu được mã hóa gửi đi.
  * *Hạn chế của mật khẩu dài:* Dù mật khẩu dài và phức tạp đến đâu, người dùng vẫn phải nhập từng ký tự qua bàn phím vật lý; do đó mật khẩu phức tạp không thể tự ngăn ngừa được việc bị đánh cắp bởi keylogger.
  * *Giải pháp phòng vệ:* Phải kết hợp giải pháp phòng vệ điểm cuối (EDR) để ngăn chặn mã độc móc hàm hệ thống, áp dụng cơ chế phân quyền tối thiểu, định kỳ xoay vòng mật khẩu khi nghi ngờ rò rỉ và áp dụng các phương thức xác thực mạnh không dùng mật khẩu như FIDO2/Passkey.

---

### Tình huống 4 – Backdoor: nhận diện persistence và dịch vụ lắng nghe không được phê duyệt

Sinh viên học cách phát hiện các kỹ thuật duy trì quyền kiểm soát (khóa Run, tác vụ hẹn giờ) và dịch vụ mở cổng bằng công cụ Sysmon, Autoruns và Process Explorer.

* **Cài đặt Sysmon và thu thập dữ liệu khởi động ban đầu bằng Autoruns**
  ```powershell
  # Cai dat Sysmon voi tep cau hinh mau cua bai thuc hanh
  C:\LAB3\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\LAB3\lab3_assets\sysmon-lab.xml
  C:\LAB3\Tools\Sysmon\Sysmon64.exe -c

  # Trich xuat danh muc khoi dong bang cong cu Autoruns dong lenh
  C:\LAB3\Tools\Autoruns\autorunsc64.exe -a * -c -h -s > C:\LAB3\Evidence\autoruns_before.csv
  ```

* **Bước 1: Mở Event Viewer để xác nhận Sysmon đang hoạt động**
  1. Vào **Event Viewer** -> **Applications and Services Logs** -> **Microsoft** -> **Windows** -> **Sysmon** -> **Operational**.
  2. Mở thử một ứng dụng (ví dụ: gõ `notepad.exe` trong PowerShell) rồi làm mới danh sách sự kiện.
  3. Kiểm tra thấy sự kiện mang mã **Event ID 1 (Process Create)** ghi nhận tiến trình Notepad vừa được tạo.

> ### ẢNH CHỤP BẮT BUỘC 6 (HÌNH H6 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Event Viewer tại đường dẫn Microsoft-Windows-Sysmon/Operational hiển thị một sự kiện Event ID 1 ghi nhận hành vi tạo tiến trình mới.
> * **Tên tệp hình ảnh lưu trữ:** `H6_Sysmon_Event1.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H6 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 1 của Tình huống 4.

* **Tạo persistence lành tính và kiểm tra sau khi khởi động lại**
  ```powershell
  # 1. Tao muc khoi dong trong Registry
  $run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
  New-ItemProperty -Path $run -Name 'LAB3_Run_Demo' -PropertyType String -Value 'notepad.exe' -Force | Out-Null

  # 2. Tao tac vu hen gio khoi chay khi dang nhap
  $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo LAB3_TASK_OK>>C:\LAB3\Evidence\task_ran.txt'
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  Register-ScheduledTask -TaskName 'LAB3_Persistence_Demo' -Action $action -Trigger $trigger -Description 'Benign LAB3 persistence demonstration' -Force | Out-Null

  # Kiem tra thong tin da thiet lap
  Get-ItemProperty $run -Name LAB3_Run_Demo
  Get-ScheduledTask -TaskName LAB3_Persistence_Demo
  ```
  * Lưu công việc, khởi động lại máy ảo (Restart VM), đăng nhập lại đúng tài khoản người dùng vừa thao tác.
  * Sau khi đăng nhập, kiểm tra tệp `C:\LAB3\Evidence\task_ran.txt` đã xuất hiện dòng chữ `LAB3_TASK_OK`.

* **Bước 2: Mở giao diện Autoruns kiểm tra mục khởi động**
  1. Chạy `C:\LAB3\Tools\Autoruns\Autoruns64.exe` bằng quyền quản trị viên.
  2. Chọn thẻ **Logon**, tìm mục có tên `LAB3_Run_Demo`.
  3. Kiểm tra các trường Entry, Description, Publisher và Image Path trỏ về `notepad.exe`.

> ### ẢNH CHỤP BẮT BUỘC 7 (HÌNH H7 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Giao diện công cụ Autoruns thẻ Logon hiển thị rõ ràng mục tự khởi động `LAB3_Run_Demo` với đường dẫn thực thi là `notepad.exe`.
> * **Tên tệp hình ảnh lưu trữ:** `H7_Autoruns_LAB3_Run_Demo.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H7 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 2 của Tình huống 4.

* **Bước 3: Truy vấn Sysmon cho Registry và tiến trình liên quan**
  ```powershell
  $ids = 1, 11, 12, 13, 14
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=$ids; StartTime=(Get-Date).AddMinutes(-30)} |
      Where-Object { $_.Message -match 'LAB3_Run_Demo|LAB3_Persistence_Demo|notepad.exe|task_ran.txt' } |
      Select-Object TimeCreated, Id, Message |
      Out-File C:\LAB3\Evidence\sysmon_persistence.txt -Width 300
  ```

* **Bước 4: Khởi chạy dịch vụ web nội bộ trên giao tiếp loopback**
  Mở một cửa sổ PowerShell mới (không cần quyền quản trị) và chạy lệnh:
  ```powershell
  Set-Location C:\LAB3\lab3_assets\www
  python -m http.server 8080 --bind 127.0.0.1
  ```
  *(Giữ cửa sổ này mở liên tục cho các tình huống tiếp theo).*

* **Bước 5: Xác minh cổng lắng nghe và mã định danh tiến trình (PID)**
  Ở một cửa sổ PowerShell quản trị viên khác, kiểm tra kết nối mạng:
  ```powershell
  $tcp = Get-NetTCPConnection -LocalPort 8080 -State Listen
  $tcp | Format-Table LocalAddress, LocalPort, State, OwningProcess -Auto
  Get-Process -Id $tcp.OwningProcess | Select-Object Id, ProcessName, Path
  ```

* **Bước 6: Mở Process Explorer định danh tiến trình mở cổng**
  1. Chạy `C:\LAB3\Tools\ProcessExplorer\procexp64.exe` bằng quyền quản trị viên.
  2. Tìm tiến trình `python.exe` có mã số PID trùng khớp với giá trị `OwningProcess` vừa tìm được ở Bước 5.
  3. Nhấp đúp vào tiến trình để kiểm tra Image Path, Command Line và tài khoản thực thi.

> ### ẢNH CHỤP BẮT BUỘC 8 (HÌNH H8 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Giao diện Process Explorer hiển thị tiến trình `python.exe` với mã PID trùng khớp hoàn toàn với kết quả từ lệnh `Get-NetTCPConnection`.
> * **Tên tệp hình ảnh lưu trữ:** `H8_ProcessExplorer_Python.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H8 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 6 của Tình huống 4.

---

### Tình huống 5 – Sniffing, MITM và Spoofing: quan sát HTTP so với HTTPS

Sinh viên sử dụng Wireshark bắt gói tin cục bộ, phân tích sự phơi bày dữ liệu của giao thức văn bản rõ (HTTP) và đối chiếu với kênh truyền mã hóa bảo vệ (HTTPS qua cổng 443).

* **Bước 1: Mở Wireshark chọn giao diện bắt gói tin loopback**
  1. Mở phần mềm **Wireshark** trên máy ảo.
  2. Chọn giao diện mạng: **Adapter for loopback traffic capture** (hoặc giao diện mạng gắn với địa chỉ `127.0.0.1`) và bắt đầu phiên bắt gói tin.

* **Bước 2: Gửi yêu cầu HTTP văn bản rõ chứa tham số thử nghiệm**
  Trong cửa sổ PowerShell, chạy lệnh:
  ```powershell
  curl.exe "http://127.0.0.1:8080/?lab_user=lab3_student&lab_code=TRAINING_ONLY"
  ```

* **Bước 3: Lọc và quan sát chi tiết gói tin HTTP trên Wireshark**
  1. Tại thanh bộ lọc hiển thị (Display Filter) của Wireshark, nhập:
     ```text
     http.request || tcp.port == 8080
     ```
  2. Bấm vào gói tin `GET`, xem chi tiết thẻ **Hypertext Transfer Protocol** để thấy rõ đường dẫn chứa chuỗi tham số `TRAINING_ONLY`.

> ### ẢNH CHỤP BẮT BUỘC 9 (HÌNH H9 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Giao diện Wireshark bắt được gói tin HTTP GET tới `127.0.0.1:8080`, phần Packet Details thể hiện rõ chuỗi văn bản không mã hóa `TRAINING_ONLY`.
> * **Tên tệp hình ảnh lưu trữ:** `H9_HTTP_Plaintext.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H9 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 3 của Tình huống 5.

* **Bước 4: Bắt gói tin đối chứng với giao thức mã hóa HTTPS**
  1. Tạm thời chuyển card mạng của máy ảo trên VMware sang chế độ **NAT** để có kết nối ra bên ngoài.
  2. Trong Wireshark, chọn card mạng Ethernet thực của máy ảo và nhập bộ lọc:
     ```text
     tls || tcp.port == 443
     ```
  3. Trong PowerShell, chạy lệnh gửi yêu cầu mã hóa:
     ```powershell
     curl.exe -I "https://example.com/?lab_user=lab3_student&lab_code=TRAINING_ONLY"
     ```
  4. Quan sát trên Wireshark: Chỉ nhìn thấy các thông tin siêu dữ liệu (IP nguồn/đích, cổng, bản tin bắt tay TLS), toàn bộ nội dung đường dẫn và dữ liệu người dùng bên trong đều bị biến thành chuỗi mã hóa ngẫu nhiên.
  5. *Lưu ý quan trọng:* Chuyển ngay card mạng máy ảo trở lại chế độ **Host-only** sau khi thực hiện xong bước này.

> ### ẢNH CHỤP BẮT BUỘC 10 (HÌNH H10_TLS TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Giao diện Wireshark hiển thị các gói tin giao thức TLS trên cổng 443 sau khi thực hiện lệnh kết nối tới `example.com`, chứng minh nội dung dữ liệu đã được bảo vệ mã hóa.
> * **Tên tệp hình ảnh lưu trữ:** `H10_TLS_443.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H10 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới Bước 4 của Tình huống 5.

---

### Tình huống 6 – DoS, DDoS và Mail Bombing

Sinh viên tiến hành thử nghiệm tải nội bộ an toàn trên cổng 8080 và phân tích các tập dữ liệu ngoại tuyến về tấn công phân tán và dội bom hộp thư.

* **Bước 1 & 2: Thực hiện thử nghiệm tải nội bộ có giới hạn**
  1. Đảm bảo dịch vụ web Python trên cổng 8080 ở Tình huống 4 vẫn đang chạy.
  2. Mở PowerShell và chạy kịch bản đo đạc tải:
     ```powershell
     python C:\LAB3\lab3_assets\scripts\local_load_test.py | Tee-Object C:\LAB3\Evidence\local_load_test.txt
     ```
  3. Kịch bản tạo 50 yêu cầu qua 5 luồng worker cục bộ; ghi nhận các thông số `ok`, `failures`, `elapsed_s` và `avg_latency_s`.

* **DDoS – Phân tích tập dữ liệu tấn công phân tán ngoại tuyến**
  Chạy lệnh phân tích nguồn phát tán từ tệp CSV:
  ```powershell
  Import-Csv C:\LAB3\lab3_assets\data\ddos_sample.csv |
      Group-Object SourceIP |
      Sort-Object Count -Descending |
      Select-Object Count, Name |
      Tee-Object C:\LAB3\Evidence\ddos_sources.txt
  ```

* **Mail bombing – Phân tích nhật ký thư điện tử ngoại tuyến**
  Chạy lệnh thống kê các nguồn gửi và tổng dung lượng thư rác:
  ```powershell
  $log = Import-Csv C:\LAB3\lab3_assets\data\mailbomb_sample.csv
  $log | Group-Object Sender | Sort-Object Count -Descending | Select-Object Count, Name | Tee-Object C:\LAB3\Evidence\mail_sender_counts.txt
  $log | Measure-Object SizeBytes -Sum -Average | Tee-Object C:\LAB3\Evidence\mail_volume.txt
  ```

> ### ẢNH CHỤP BẮT BUỘC 11 (HÌNH H10_LOAD VÀ LOG TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ PowerShell thể hiện kết quả chạy kịch bản thử tải `local_load_test.py` nhắm vào địa chỉ cục bộ `127.0.0.1:8080` kèm theo kết quả thống kê các nguồn tấn công từ tệp dữ liệu DDoS và dội bom thư.
> * **Tên tệp hình ảnh lưu trữ:** `H10_Load_and_Log_Analysis.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H10 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới mục Tình huống 6.

---

### Tình huống 7 – Social Engineering, Phishing và Spear Phishing

Sinh viên phân tích mẫu thư lừa đảo ngoại tuyến để chỉ ra các dấu hiệu nhận biết và hoàn thiện bảng phân loại 6 trường hợp tấn công tâm lý xã hội.

* **Bước 1: Mở và phân tích mẫu thư điện tử lừa đảo ngoại tuyến**
  Chạy lệnh mở tệp mẫu bằng Notepad:
  ```powershell
  notepad.exe C:\LAB3\lab3_assets\samples\phishing_email.txt
  ```
  * **Năm chỉ dấu lừa đảo cốt lõi được bóc tách từ mẫu:**
    1. *Tạo áp lực khẩn cấp và đe dọa hậu quả:* "Tài khoản của bạn sẽ bị khóa nếu không xác minh trong 15 phút".
    2. *Mạo danh định danh đáng tin cậy:* Tên hiển thị là `"IT Support - Training"` nhằm tạo vỏ bọc chuyên môn kỹ thuật nội bộ.
    3. *Tên miền người gửi đáng ngờ:* Sử dụng địa chỉ `helpdesk@security-training.example` không thuộc hạ tầng quản trị chính thức.
    4. *Địa chỉ phản hồi (Reply-To) lệch với địa chỉ người gửi (From):* Gửi từ `helpdesk@...` nhưng yêu cầu gửi phản hồi về `verify@account-check.example`.
    5. *Thúc ép truy cập liên kết ngoài để chiếm đoạt thông tin định danh:* Dẫn dụ người dùng bấm vào đường link `https://account-check.example/verify` để nhập tên đăng nhập và mã xác minh.

* **Bước 2: Phân loại 6 kịch bản tấn công phi kỹ thuật trong tệp CSV**
  Chạy lệnh xem nội dung tệp CSV trong PowerShell:
  ```powershell
  Import-Csv C:\LAB3\lab3_assets\samples\social_engineering_cases.csv | Format-Table -Wrap
  ```

  * **Bảng phân loại chuẩn xác các trường hợp:**

| CaseID | Kịch bản tình huống thực tế | Hình thức tấn công tương ứng | Dấu hiệu đặc trưng | Biện pháp phòng tránh đề xuất |
| :---: | :--- | :--- | :--- | :--- |
| **SE01** | Email gửi đồng loạt giả mạo công ty dịch vụ, yêu cầu bấm liên kết đăng nhập. | **Phishing** | Gửi hàng loạt đại trà, nội dung không cá nhân hóa, dẫn tới trang đăng nhập giả mạo. | Trang bị bộ lọc thư rác thông minh, xác thực đa yếu tố chống lừa đảo. |
| **SE02** | Email được cá nhân hóa bằng tên, chức danh và đồng nghiệp của một nhân viên cụ thể. | **Spear Phishing** | Nội dung cá nhân hóa sâu sắc, sử dụng chính xác thông tin công việc của mục tiêu. | Quy trình xác thực thông tin chéo qua kênh liên lạc phụ, kiểm tra chữ ký số của thư. |
| **SE03** | Kẻ xấu tạo bối cảnh giả là nhân viên hỗ trợ kỹ thuật gọi điện xin mã xác minh. | **Pretexting** | Đóng vai nhân vật có thẩm quyền/kỹ thuật viên đáng tin cậy để tạo niềm tin khai thác thông tin. | Quy định nghiêm ngặt: Tuyệt đối không cung cấp mã OTP/mật khẩu qua điện thoại trong mọi tình huống. |
| **SE04** | USB dán nhãn 'Lương-thưởng-2026' để ở khu vực công cộng kích thích cắm vào máy. | **Baiting** | Dùng vật phẩm vật lý đánh trúng lòng tham và tính tò mò của người nhặt được. | Vô hiệu hóa tính năng tự chạy (AutoRun), khóa cổng USB đối với thiết bị lưu trữ lạ. |
| **SE05** | Kẻ xấu hứa tặng quà/ưu đãi nếu người dùng cung cấp thông tin hoặc thực hiện hành động. | **Quid Pro Quo** | Hứa hẹn trao đổi một lợi ích dịch vụ hoặc vật chất để đổi lấy thông tin bí mật. | Đào tạo nhận thức: Không có dịch vụ hợp pháp nào yêu cầu đánh đổi mật khẩu lấy quà tặng. |
| **SE06** | Website nhóm mục tiêu hay vào bị chèn nội dung độc hại để lợi dụng lượt truy cập. | **Watering Hole** | Tấn công đầu độc trang web trung gian uy tín mà cộng đồng mục tiêu thường xuyên truy cập. | Giám sát duyệt web qua proxy an toàn, luôn cập nhật các bản vá bảo mật cho trình duyệt. |

> ### ẢNH CHỤP BẮT BUỘC 12 (HÌNH H10_PHISHING TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ Notepad mở tệp `phishing_email.txt` hiển thị nội dung phân tích bên cạnh cửa sổ PowerShell hiển thị bảng các trường hợp tấn công tâm lý xã hội `social_engineering_cases.csv`.
> * **Tên tệp hình ảnh lưu trữ:** `H10_Phishing_Offline.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H10 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới mục Tình huống 7.

---

## CÔ LẬP, CLEANUP, PHỤC HỒI VÀ KIỂM TRA LẠI

Quy trình loại bỏ toàn bộ các dấu vết thử nghiệm, khôi phục hệ điều hành về trạng thái chuẩn sạch ban đầu và lưu vết chứng cứ số.

### Các bước dọn dẹp và kiểm tra xác nhận
Thực thi toàn bộ khối lệnh trong cửa sổ PowerShell (Administrator):

```powershell
# 1. Xoa bo cac muc khoi dong LAB3
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'LAB3_Run_Demo' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'LAB3_Persistence_Demo' -Confirm:$false -ErrorAction SilentlyContinue

# 2. Dung tien trinh may chu HTTP dang lang nghe tren cong 8080
$serverPid = (Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }

# 3. Xoa tai khoan thu nghiem da tao
Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Out-Null
Remove-LocalUser -Name 'lab3user' -ErrorAction SilentlyContinue

# 4. Kiem tra xac nhan lai toan bo he thong da sach
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'LAB3_Run_Demo' -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName 'LAB3_Persistence_Demo' -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected
```

> ### ẢNH CHỤP BẮT BUỘC 13 (HÌNH H11 TRONG BÁO CÁO)
> * **Nội dung cần chụp:** Cửa sổ PowerShell hiển thị kết quả kiểm tra lại ở mục số 4: Các lệnh kiểm tra mục Run, Task và cổng 8080 đều không trả về giá trị (đã xóa sạch), và lệnh `Get-MpComputerStatus` xác nhận Microsoft Defender vẫn duy trì trạng thái bật bảo vệ thời gian thực.
> * **Tên tệp hình ảnh lưu trữ:** `H11_Recovery_Verification.png`
> * **Vị trí dán trong báo cáo Word:** Dán ảnh vào khung **"VỊ TRÍ HÌNH H11 – ẢNH CHỤP TRỰC TIẾP TỪ VM/PC SINH VIÊN"** ngay dưới mục Dọn dẹp và phục hồi.

---

### Các bước kiểm tra đối chứng và lưu vết bằng chứng

* **Bước 1: Thu thập danh mục khởi động sau dọn dẹp và so sánh sai khác**
  ```powershell
  C:\LAB3\Tools\Autoruns\autorunsc64.exe -a * -c -h -s > C:\LAB3\Evidence\autoruns_after.csv
  Compare-Object (Get-Content C:\LAB3\Evidence\autoruns_before.csv) (Get-Content C:\LAB3\Evidence\autoruns_after.csv) |
      Out-File C:\LAB3\Evidence\autoruns_diff.txt -Width 240
  ```

* **Bước 2: Tính toán mã băm SHA-256 cho toàn bộ bằng chứng**
  ```powershell
  Get-ChildItem C:\LAB3\Evidence -File |
      Get-FileHash -Algorithm SHA256 |
      Export-Csv C:\LAB3\Evidence\evidence_sha256.csv -NoTypeInformation -Encoding UTF8
  ```

* **Bước 3: Khôi phục máy ảo về điểm sao lưu sạch ban đầu (Revert Snapshot)**
  * Tắt máy ảo.
  * Trong giao diện VMware: Chọn **VM** -> **Snapshot** -> Chọn điểm sao lưu `LAB3_CLEAN_BASELINE` đã tạo ở Bước 1 và nhấn **Revert**.
  * Máy ảo hoàn toàn sạch sẽ, sẵn sàng cho các buổi thực hành tiếp theo.

---

## CÂU HỎI VÀ ĐÁP ÁN MẪU (20 CÂU HỎI LÝ THUYẾT)

Dưới đây là đáp án chi tiết, bám sát các tiêu chuẩn kỹ thuật trong bài giảng phục vụ việc đưa thẳng vào phần trả lời câu hỏi của báo cáo:

#### Câu 1: Dùng một ví dụ từ máy ảo để phân biệt rõ Điểm yếu (Vulnerability), Mối đe dọa (Threat), Rủi ro (Risk) và Tấn công (Attack). Không dùng cùng một câu mô tả cho Threat và Risk.
* **Tài sản (Asset):** Dịch vụ ứng dụng web nội bộ đang mở trên cổng 8080 của máy trạm.
* **Lỗ hổng (Vulnerability):** Dịch vụ web sử dụng giao thức HTTP thuần văn bản rõ, hoàn toàn không có mã hóa và không có cơ chế xác thực người dùng khi truy cập.
* **Mối đe dọa (Threat):** Hành vi của kẻ xấu bắt trộm các gói tin trên đường truyền mạng nội bộ nhằm đánh cắp thông tin bí mật.
* **Rủi ro (Risk):** Nguy cơ toàn bộ chuỗi thông tin định danh và tham số phiên làm việc bị lộ lọt, dẫn đến việc kẻ xấu mạo danh người dùng hợp lệ để chiếm đoạt tài nguyên.
* **Tấn công (Attack):** Hành động kẻ tấn công chủ động vận hành phần mềm Wireshark bắt luồng dữ liệu trên cổng 8080 và trích xuất thành công chuỗi giá trị bí mật `TRAINING_ONLY`.

#### Câu 2: Phân loại năm tình huống ở Tình huống 1 và giải thích tiêu chí phân loại.
* *Tình huống 1 (Xóa nhầm tệp cấu hình):* Hành động vô ý. Tiêu chí: Lỗi xuất phát từ sơ suất của con người nội bộ, hoàn toàn không có chủ đích gây thiệt hại.
* *Tình huống 2 (Cài phần mềm thu thập dữ liệu):* Hành động cố ý. Tiêu chí: Có chủ đích phá hoại rõ ràng từ đối tượng có ác ý nhằm chiếm đoạt tài nguyên thông tin.
* *Tình huống 3 (Mất điện kéo dài gây mất dữ liệu):* Thảm họa tự nhiên / sự cố môi trường. Tiêu chí: Biến cố hạ tầng khách quan từ môi trường ngoài tầm kiểm soát của ứng dụng.
* *Tình huống 4 (Hỏng đĩa hoặc dịch vụ treo do lỗi phần mềm):* Lỗi kỹ thuật. Tiêu chí: Xuất phát từ sự hao mòn vật lý của linh kiện phần cứng hoặc khiếm khuyết trong mã lệnh phần mềm.
* *Tình huống 5 (Không áp dụng quy trình sao lưu và vá lỗi):* Lỗi quản lý. Tiêu chí: Sự yếu kém trong công tác hoạch định, giám sát và thực thi chính sách của cấp lãnh đạo.

#### Câu 3: Chuỗi EICAR trong Tình huống 2 chứng minh được điều gì về Defender và không chứng minh được điều gì về mã độc thật?
* **Chứng minh được:** Microsoft Defender đang hoạt động bình thường, tính năng bảo vệ theo thời gian thực hoạt động nhạy bén và chu trình tự động nhận diện chữ ký, chặn và cách ly tệp độc hại diễn ra chuẩn xác.
* **Không chứng minh được:** Không chứng minh được hệ thống có khả năng phòng ngừa tất cả các biến chủng mã độc trong thực tế, đặc biệt là các cuộc tấn công chưa có chữ ký (Zero-day), mã độc không dùng tệp (Fileless malware) hoặc mã độc sử dụng kỹ thuật che giấu nâng cao.

#### Câu 4: Vì sao không được tắt Microsoft Defender/EDR để “cho mẫu chạy”? Quy trình xử lý phần mềm hợp lệ bị chặn nhầm trong doanh nghiệp?
* Không được tắt trình bảo vệ vì hành động này sẽ vô hiệu hóa toàn bộ lớp khiên phòng vệ của máy trạm, biến máy tính thành mục tiêu phơi nhiễm hoàn toàn trước các cuộc tấn công thật từ mạng.
* **Quy trình xử lý chặn nhầm (False Positive) chuẩn doanh nghiệp:**
  1. *Ghi nhận và cô lập:* Tiếp nhận cảnh báo từ người dùng, giữ nguyên trạng thái cách ly của tệp nghi vấn.
  2. *Thẩm định nguồn gốc:* Kiểm tra tính toàn vẹn qua mã băm SHA-256, kiểm tra chữ ký số của nhà phát triển phần mềm và nguồn cung cấp tệp.
  3. *Phân tích hành vi trong môi trường cô lập:* Chạy tệp trong môi trường hộp cát (Sandbox) chuyên dụng để quan sát các kết nối mạng và thay đổi hệ thống.
  4. *Phê duyệt ngoại lệ có kiểm soát:* Nếu xác định là phần mềm an toàn nghiệp vụ, ban quản trị an ninh mạng sẽ tạo chính sách loại trừ (Exclusion) cụ thể cho mã băm hoặc đường dẫn tệp đó trên máy chủ quản trị tập trung, tuyệt đối không tắt phần mềm bảo vệ trên máy trạm.

#### Câu 5: So sánh Tấn công dò vét cạn (Brute Force), Tấn công từ điển (Dictionary) và Phần mềm nghe lén bàn phím (Keylogger).
* **Dữ liệu đầu vào:**
  * *Brute Force:* Thử nghiệm ngẫu nhiên mọi tổ hợp ký tự có thể xảy ra theo độ dài tăng dần.
  * *Dictionary:* Danh sách tập hợp các từ ngữ, cụm từ hoặc mật khẩu thông dụng được thu thập sẵn từ các vụ rò rỉ dữ liệu.
  * *Keylogger:* Thu thập trực tiếp chuỗi ký tự do người dùng gõ từ bàn phím vật lý theo thời gian thực.
* **Cách thức phát hiện:**
  * *Brute Force / Dictionary:* Xuất hiện đột biến hàng loạt các sự kiện đăng nhập thất bại (Mã 4625) từ cùng một nguồn trong một khoảng thời gian rất ngắn.
  * *Keylogger:* Phát hiện qua hành vi móc hàm hệ thống (API Hooking), chữ ký tệp của phần mềm diệt virus hoặc tiến trình lạ tự khởi động gửi gói tin ra ngoài.
* **Biện pháp giảm thiểu:**
  * *Brute Force / Dictionary:* Áp dụng chính sách khóa tài khoản tạm thời sau nhiều lần nhập sai (Account Lockout Policy), giới hạn tần suất gửi yêu cầu xác thực, sử dụng CAPTCHA.
  * *Keylogger:* Ứng dụng giải pháp xác thực đa yếu tố không dùng mật khẩu (FIDO2 / Passkey), triển khai phần mềm bảo vệ điểm cuối EDR, sử dụng bàn phím ảo chống chụp phím.

#### Câu 6: Dùng các mã sự kiện 4624, 4625, 4648 để giải thích trạng thái xác thực trước và sau khi đổi mật khẩu của `lab3user`.
* **Mã sự kiện 4624 (Đăng nhập thành công):** Được ghi lại khi tài khoản xác thực thành công bằng mật khẩu chính xác qua công cụ chuyển quyền `runas`.
* **Mã sự kiện 4625 (Đăng nhập thất bại):** Được ghi nhận khi cố ý gõ sai mật khẩu; bản ghi chỉ rõ nguyên nhân xác thực thất bại do sai mật khẩu.
* **Mã sự kiện 4648 (Cố gắng đăng nhập bằng thông tin xác thực tường minh):** Xuất hiện khi một tiến trình yêu cầu đăng nhập bằng việc truyền thông tin định danh của người dùng khác một cách rõ ràng (đặc trưng của lệnh `runas`).
* *Trạng thái sau khi xoay vòng mật khẩu:* Khi đã đổi sang mật khẩu mới, việc cố gắng đăng nhập bằng mật khẩu cũ sẽ ngay lập tức kích hoạt mã sự kiện thất bại 4625, chứng minh mật khẩu cũ đã bị vô hiệu hóa hoàn toàn trên hệ thống.

#### Câu 7: Vì sao mật khẩu dài/phức tạp không tự ngăn được Keylogger? Vai trò và giới hạn của MFA, Push MFA và FIDO2/Passkey?
* Mật khẩu dù dài và phức tạp bao nhiêu thì người dùng vẫn bắt buộc phải gõ từng ký tự đó từ bàn phím; Keylogger bắt trực tiếp tín hiệu phần cứng hoặc móc vào luồng xử lý phím bấm của hệ điều hành nên mật khẩu càng dài chỉ càng cung cấp đầy đủ chuỗi ký tự chính xác cho kẻ tấn công.
* **Vai trò và giới hạn của các cơ chế xác thực hiện đại:**
  * *MFA truyền thống (Mã gửi qua SMS/Email):* Ngăn được kẻ tấn công đăng nhập nếu chúng chỉ có mật khẩu. *Giới hạn:* Vẫn có thể bị đánh lừa qua các trang web lừa đảo trung gian (Phishing Proxy) dụ người dùng nhập mã OTP.
  * *Push MFA (Thông báo xác nhận trên điện thoại):* Tiện lợi và nhanh chóng. *Giới hạn:* Dễ bị tấn công quấy rối liên tục nhằm ép người dùng bấm chấp thuận trong vô thức (MFA Fatigue Attack).
  * *FIDO2 / Passkey:* Giải pháp an toàn nhất hiện nay nhờ sử dụng cặp khóa mã hóa bất đối xứng gắn liền chặt chẽ với tên miền của dịch vụ và lưu giữ khóa riêng trong phần cứng an toàn; người dùng không cần nhập mật khẩu, vô hiệu hóa hoàn toàn cả Keylogger lẫn Phishing.

#### Câu 8: Một cổng đang lắng nghe (Listen) có đủ để kết luận có backdoor không? Bốn nguồn chứng cứ cần liên kết đối chứng?
* Một cổng mở ở trạng thái `Listen` hoàn toàn **chưa đủ** để khẳng định hệ thống bị cài backdoor, vì rất nhiều dịch vụ hệ thống và ứng dụng hợp lệ cần mở cổng để phục vụ hoạt động bình thường.
* **Bốn nguồn chứng cứ bắt buộc phải liên kết đối chứng:**
  1. *Tiến trình sở hữu cổng (PID và đường dẫn thực thi):* Kiểm tra tệp thực thi nào đang mở cổng và vị trí tệp có nằm ở thư mục hệ thống chuẩn hay không.
  2. *Chữ ký số của tệp (Verified Signer):* Xác minh tệp chương trình có được ký số hợp lệ bởi nhà phát triển phần mềm uy tín hay không.
  3. *Dòng lệnh khởi chạy (Command Line Argument):* Xem cách thức tiến trình được kích hoạt từ đâu và nhận các tham số điều khiển nào.
  4. *Cơ chế tự khởi động đi kèm (Persistence Mechanism):* Kiểm tra xem tệp có cài cắm vào Registry Run, Tác vụ hẹn giờ hoặc Dịch vụ hệ thống để tự động hoạt động sau khởi động hay không.

#### Câu 9: Run value và Scheduled Task tạo persistence như thế nào? Vì sao phải kiểm tra kỹ trước khi xóa một entry?
* **Cơ chế hoạt động:**
  * *Khóa Registry Run:* Được hệ điều hành tự động quét và kích hoạt ứng dụng trỏ tới ngay sau khi người dùng đăng nhập vào màn hình làm việc.
  * *Tác vụ hẹn giờ (Scheduled Task):* Được dịch vụ Task Scheduler kích hoạt tự động theo lịch biểu thời gian hoặc gắn với sự kiện hệ thống (như khi khởi động máy hoặc người dùng đăng nhập).
* **Nguyên nhân phải kiểm tra kỹ trước khi xóa:** Rất nhiều dịch vụ hệ thống, trình điều khiển phần cứng và phần mềm bảo vệ hợp lệ cũng sử dụng các cơ chế này để khởi chạy. Việc xóa tùy tiện mà không đối chiếu tên, nhà phát hành và đường dẫn có thể làm hỏng hệ điều hành hoặc làm ngừng trệ các tính năng quan trọng.

#### Câu 10: So sánh DoS và DDoS bằng kết quả `local_load_test.py` và `ddos_sample.csv`. Vì sao DDoS khó chặn chỉ bằng một rule IP đơn giản?
* *DoS (Từ chối dịch vụ đơn nguồn):* Toàn bộ các yêu cầu gây tải đều xuất phát từ một máy duy nhất (như script thử nghiệm nội bộ chạy trên địa chỉ loopback). Trường hợp này có thể dễ dàng ngăn chặn bằng cách tạo một quy tắc tường lửa chặn duy nhất địa chỉ IP nguồn đó.
* *DDoS (Từ chối dịch vụ phân tán):* Các yêu cầu tấn công xuất phát từ hàng trăm, hàng nghìn địa chỉ IP nguồn khác nhau rải rác trên toàn cầu (như tập dữ liệu `ddos_sample.csv` thể hiện rất nhiều dải mạng TEST-NET).
* *Lý do khó chặn bằng rule IP đơn giản:* Kẻ tấn công liên tục thay đổi địa chỉ nguồn qua mạng lưới thiết bị ma (Botnet); việc chặn thủ công từng địa chỉ IP riêng lẻ không thể theo kịp tốc độ của cuộc tấn công và rất dễ dẫn đến nguy cơ chặn nhầm địa chỉ mạng của người dùng hợp lệ.

#### Câu 11: Mail bombing ảnh hưởng chủ yếu tới thuộc tính nào? Nêu hai chỉ số phù hợp để phát hiện hành vi bất thường từ `mailbomb_sample.csv`.
* Mail bombing nhắm thẳng vào **Tính sẵn sàng (Availability)** của dịch vụ thư điện tử và tài nguyên máy chủ (làm cạn kiệt dung lượng đĩa lưu trữ, nghẽn băng thông đường truyền và gây treo tiến trình máy chủ thư).
* **Hai chỉ số phù hợp để nhận diện từ tập dữ liệu:**
  1. *Tần suất gửi thư đột biến từ một địa chỉ nguồn:* Số lượng thư gửi đến cùng một đích trong một khoảng thời gian ngắn vượt xa mức sinh hoạt bình thường.
  2. *Tổng dung lượng và dung lượng tệp đính kèm:* Tổng số byte dữ liệu dồn về hòm thư tăng vọt bất thường làm cạn kiệt hạn ngạch lưu trữ (Mailbox Quota).

#### Câu 12: Sniffing được dùng hợp pháp và bất hợp pháp như thế nào? Dùng hai capture của Tình huống 5 để minh họa sự khác nhau giữa HTTP và HTTPS.
* *Hợp pháp:* Quản trị viên mạng sử dụng để chẩn đoán sự cố mạng, đo lường hiệu năng đường truyền, điều tra dấu vết vi phạm an ninh và phát hiện lưu lượng độc hại.
* *Bất hợp pháp:* Kẻ tấn công bí mật nghe lén gói tin trên mạng nội bộ hoặc Wi-Fi công cộng nhằm đánh cắp tài khoản, mật khẩu và dữ liệu nhạy cảm.
* *Minh họa khác biệt thực nghiệm:*
  * Trong gói tin HTTP: Wireshark đọc được trọn vẹn toàn bộ đường dẫn URL và tham số bí mật `TRAINING_ONLY` ở dạng chữ rõ hoàn toàn không được che giấu.
  * Trong gói tin HTTPS: Wireshark chỉ nhìn thấy các bản tin bắt tay TLS và các khối dữ liệu ứng dụng đã được mã hóa ngẫu nhiên, không thể đọc được nội dung bên trong nếu không có khóa giải mã.

#### Câu 13: Trình bày các biến thể Man-in-the-Middle và kỹ thuật không được thực hiện chủ động trong bài lab?
* *Email Hijacking:* Kẻ xấu can thiệp vào luồng thư từ giữa hai bên hoặc chiếm quyền hòm thư để sửa đổi nội dung số tài khoản chuyển tiền trong các giao dịch.
* *Wi-Fi Eavesdropping:* Kẻ xấu tạo điểm phát sóng Wi-Fi mạo danh (Evil Twin) nhằm lừa nạn nhân kết nối qua để nghe lén toàn bộ lưu lượng mạng.
* *Session Hijacking:* Đánh cắp mã định danh phiên làm việc (Session Cookie) của người dùng để mạo danh đăng nhập mà không cần mật khẩu.
* *IP/DNS/HTTPS Spoofing:* Làm giả địa chỉ mạng hoặc đầu độc dữ liệu phân giải tên miền để hướng người dùng tới máy chủ do kẻ tấn công kiểm soát.
* *Kỹ thuật không thực hiện chủ động trong lab:* Đầu độc bảng ARP (ARP Poisoning), làm giả máy chủ DNS và ép cài chứng chỉ số giả mạo. Lý do: Các kỹ thuật này có tính chất phá vỡ hạ tầng đường truyền, gây mất ổn định mạng thật và vượt quá giới hạn an toàn của bài học.

#### Câu 14: Cơ chế giảm thiểu rủi ro của HTTPS, HSTS, VPN và hai loại rủi ro không thể tự giải quyết?
* *Cơ chế bảo vệ:*
  * HTTPS: Mã hóa toàn bộ dữ liệu trao đổi giữa trình duyệt và máy chủ bằng các thuật toán mã hóa khóa công khai và mã hóa đối xứng hiện đại.
  * HSTS (HTTP Strict Transport Security): Ép buộc trình duyệt chỉ được phép kết nối qua kênh an toàn HTTPS, vô hiệu hóa hoàn toàn nguy cơ bị tấn công hạ cấp giao thức (SSL Stripping).
  * VPN: Thiết lập đường hầm truyền thông mã hóa bao bọc toàn bộ dữ liệu từ thiết bị đầu cuối tới cổng mạng của đơn vị, loại bỏ nguy cơ nghe lén trên mạng công cộng.
* *Hai loại rủi ro không thể giải quyết:*
  1. Thiết bị đầu cuối bị nhiễm mã độc (bị cài phần mềm theo dõi bàn phím hoặc chụp màn hình trực tiếp).
  2. Người dùng bị lừa đảo tâm lý (người dùng tự nguyện đăng nhập và cung cấp thông tin cho trang web giả mạo dù trang web đó vẫn có chứng chỉ HTTPS hợp lệ).

#### Câu 15: Phân biệt giả mạo (Spoofing) ở lớp IP, lớp DNS và lớp Website/Domain.
* *Giả mạo lớp IP (IP Spoofing):* Thay đổi địa chỉ IP nguồn trong tiêu đề gói tin để vượt qua các bộ lọc danh sách cho phép (ACL). *Kiểm soát:* Bật tính năng lọc chống giả mạo nguồn (Ingress/Egress Filtering) trên các thiết bị định tuyến.
* *Giả mạo lớp DNS (DNS Spoofing):* Đầu độc vùng nhớ đệm của máy chủ DNS để trả về địa chỉ IP giả khi nạn nhân phân giải tên miền hợp lệ. *Kiểm soát:* Triển khai giao thức mở rộng bảo mật tên miền DNSSEC.
* *Giả mạo lớp Website/Domain:* Đăng ký tên miền gần giống (Typosquatting) hoặc sử dụng các ký tự đồng dạng trong bảng mã Unicode (IDN Homograph Attack) để dựng trang web giả mạo. *Kiểm soát:* Đăng ký bao vây tên miền thương hiệu, trang bị bộ lọc bảo vệ duyệt web thông minh và sử dụng chứng chỉ số xác thực mở rộng (EV Certificate).

#### Câu 16: Phân biệt các hình thức tấn công tâm lý xã hội từ `social_engineering_cases.csv`.
* *Phishing:* Gửi thư mạo danh đại trà tới hàng loạt người dùng không phân biệt đối tượng nhằm thu thập thông tin quy mô lớn.
* *Spear Phishing:* Tấn công lừa đảo có chủ đích, thu thập kỹ thông tin của một nạn nhân cụ thể để tạo ra nội dung cá nhân hóa có độ thuyết phục rất cao.
* *Watering Hole:* Tấn công đầu độc trang web trung gian uy tín mà nhóm đối tượng mục tiêu thường xuyên truy cập nhằm lây nhiễm mã độc cho người dùng.
* *Pretexting:* Xây dựng một kịch bản mạo danh hoàn hảo (như đóng vai nhân viên kỹ thuật hoặc thanh tra) để đàm thoại và lừa nạn nhân tiết lộ thông tin.
* *Baiting:* Sử dụng mồi nhử vật lý hữu hình (như để rơi ổ đĩa USB nhặt được ngoài sảnh) để kích thích trí tò mò và lòng tham của nạn nhân.
* *Quid Pro Quo:* Hứa hẹn mang lại một lợi ích dịch vụ hoặc vật chất để đánh đổi lấy thông tin định danh bí mật của người dùng.

#### Câu 17: Trong `phishing_email.txt`, những chỉ dấu nào liên quan tới uy tín giả, khẩn cấp, domain, Reply-To và yêu cầu credential?
* *Uy tín giả:* Tự xưng là đại diện `"IT Support - Training"` nhằm tạo niềm tin rằng thông báo xuất phát từ bộ phận kỹ thuật nội bộ của cơ quan.
* *Khẩn cấp:* Tạo áp lực thời gian tâm lý với câu cảnh báo "sẽ bị khóa nếu không xác minh trong 15 phút" nhằm làm người nhận hoảng sợ và hành động thiếu suy xét.
* *Domain:* Sử dụng tên miền `security-training.example` hoàn toàn không thuộc hệ thống máy chủ thư chính thức của đơn vị.
* *Reply-To:* Thiết lập trường địa chỉ phản hồi hướng về `verify@account-check.example`, hoàn toàn lệch với địa chỉ hòm thư gửi ban đầu.
* *Yêu cầu credential:* Đưa ra liên kết và chỉ dẫn người dùng bấm vào đường dẫn để nộp thông tin tên đăng nhập và mã xác minh bí mật.

#### Câu 18: Xây dựng quy trình ứng phó sự cố (Incident Response) ngắn cho endpoint nghi có keylogger/backdoor.
1. **Phân loại (Triage):** Tiếp nhận thông tin, đánh giá mức độ khẩn cấp và phạm vi ảnh hưởng của dấu vết nghi vấn trên máy trạm.
2. **Bảo toàn bằng chứng (Preserve Evidence):** Thu thập bản sao bộ nhớ RAM, lưu trữ toàn bộ tệp nhật ký hệ thống và tính toán ngay mã băm SHA-256 để niêm phong chứng cứ số.
3. **Cô lập (Contain):** Ngắt kết nối mạng (rút dây mạng hoặc ngắt card mạng ảo) của máy trạm để chặn mã độc phát tán hoặc kết nối về máy chủ điều khiển.
4. **Hành động với tài khoản (Credential Action):** Thu hồi toàn bộ các phiên làm việc đang mở, cưỡng chế đổi mật khẩu từ một thiết bị an toàn khác và vô hiệu hóa các quyền hạn của tài khoản nghi lộ lọt.
5. **Triệt tiêu (Eradicate):** Xóa bỏ tận gốc các mục tự khởi động trong Registry, xóa các tác vụ hẹn giờ, chấm dứt tiến trình độc hại và tiêu hủy tệp thực thi cửa sau.
6. **Khôi phục (Recover):** Hoàn nguyên máy trạm từ bản sao lưu sạch tin cậy, kiểm tra cập nhật các bản vá an ninh và khôi phục hoạt động cho các dịch vụ hợp lệ.
7. **Giám sát (Monitor):** Duy trì chế độ giám sát tăng cường đối với máy trạm và các tài khoản liên quan trong nhiều tuần tiếp theo để đảm bảo không bị tái nhiễm.

#### Câu 19: Ý nghĩa của mã băm SHA-256 trong bài thực hành?
* **Chứng minh được:** Chứng minh tính toàn vẹn (Integrity) tuyệt đối của các tệp bằng chứng số kể từ thời điểm tính toán mã băm; nếu tệp bị thay đổi dù chỉ một ký tự thì giá trị băm sẽ hoàn toàn thay đổi.
* **Không chứng minh được:** Không chứng minh được tính đúng đắn của dữ liệu bên trong (nếu dữ liệu ban đầu thu thập bị sai thì mã băm vẫn sinh ra bình thường) và không chứng minh được danh tính nguồn gốc của người tạo ra tệp.

#### Câu 20: Đề xuất mô hình phòng thủ theo chiều sâu (Defense-in-Depth) cho máy tính kế toán hoặc máy tính quản trị.
* **Bảo vệ điểm cuối (Endpoint Protection):** Triển khai giải pháp phòng vệ điểm cuối thế hệ mới (EDR) có khả năng phát hiện hành vi bất thường theo thời gian thực và tự động cách ly mã độc.
* **Đặc quyền tối thiểu (Least Privilege):** Phân quyền người dùng thông thường cho các tác vụ công việc hàng ngày; quyền quản trị chỉ được cấp phát có thời hạn và phải qua phê duyệt khi thực sự cần thiết.
* **Kiểm soát phần mềm (Application Whitelisting):** Áp dụng chính sách AppLocker chỉ cho phép thực thi các ứng dụng nghiệp vụ đã được số hóa và phê duyệt trước.
* **Ghi nhật ký tập trung (Centralized Logging):** Cấu hình Sysmon và chuyển tiếp toàn bộ nhật ký sự kiện quan trọng về hệ thống giám sát an ninh tập trung (SIEM) để phân tích tương quan thời gian thực.
* **Phân vùng mạng (Network Segmentation & Firewall):** Bố trí máy tính kế toán/quản trị vào một vùng mạng VLAN riêng biệt, cấu hình tường lửa ngăn chặn mọi luồng kết nối không phục vụ nghiệp vụ.
* **Sao lưu dữ liệu (Immutable Backup):** Thiết lập quy trình tự động sao lưu dữ liệu kế toán theo quy tắc 3-2-1 và lưu trữ dữ liệu tại các vị trí bất biến chống lại mã độc tống tiền.
* **Bảo vệ danh tính (Credential Protection):** Bắt buộc kích hoạt xác thực đa yếu tố không dùng mật khẩu (FIDO2 / Passkey), kích hoạt tính năng Windows Defender Credential Guard để ngăn chặn việc trích xuất mật khẩu từ bộ nhớ hệ thống.

---

## YÊU CẦU NỘP BÀI VÀ QUY CHUẨN KHO LƯU TRỮ

### 1. Quy cách tệp báo cáo Word
* Đặt tên tệp báo cáo theo đúng cú pháp: `[MãLớp]-LAB3_MSSV-HoTen.docx`.
* Ở phần đầu báo cáo ghi rõ thông tin phiên bản môi trường thực hành và đường liên kết video minh chứng nếu lớp có yêu cầu.
* Mọi khung **"VỊ TRÍ HÌNH"** trong báo cáo bắt buộc phải được chèn ảnh chụp màn hình trực tiếp từ máy thực hành của sinh viên kèm kết quả đối chứng dòng lệnh.

### 2. Cấu trúc thư mục kho lưu trữ GitHub
* Tạo kho lưu trữ (Repository) công khai trên GitHub mang tên: `LAB_AT_BMHTTT`.
* Tạo thư mục con riêng biệt mang tên `LAB3/`.
* Thư mục `LAB3/` tối thiểu bao gồm:
  1. Tệp `README.md`: Ghi rõ họ tên, mã số sinh viên, tên bài lab, phiên bản môi trường, cách thức dựng môi trường, danh sách các tình huống đã thực hiện, kết quả đạt được, các lỗi gặp phải và giải pháp khắc phục.
  2. Tệp báo cáo Word chính thức (`.docx`).
  3. Thư mục `Evidence/` chứa toàn bộ các tệp nhật ký đầu ra đã được làm sạch và tệp bảng băm `evidence_sha256.csv`.
  4. Thư mục ảnh chụp màn hình chứa đầy đủ các tệp hình ảnh từ `H1_VM_WindowsVersion.png` đến `H11_Recovery_Verification.png`.
* *Cảnh báo an toàn:* Tuyệt đối không đưa các tệp thực thi (`.exe`), gói cài đặt, tệp bị trình bảo vệ cách ly hoặc thông tin mật khẩu cá nhân lên kho lưu trữ.
