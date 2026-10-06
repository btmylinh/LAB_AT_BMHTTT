$ErrorActionPreference = 'Stop'

$expected = '883fb7bc64fe548442ed007911341dd34e178449f8156ad65f7381a02b7cd9e4'
$archiveName = 'pfSense-CE-2.7.2-RELEASE-amd64.iso.gz'
$archive = Join-Path $PSScriptRoot ('INSTALL_MEDIA\\' + $archiveName)

if (-not (Test-Path $archive)) {
    $fallback = Join-Path $PSScriptRoot $archiveName
    if (Test-Path $fallback) {
        $archive = $fallback
    } else {
        Write-Host ''
        Write-Error "Không tìm thấy file $archiveName. Hãy tải file .iso.gz và đặt vào thư mục INSTALL_MEDIA."
        exit 2
    }
}

$actual = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()

Write-Host "File     : $archive"
Write-Host "Expected : $expected"
Write-Host "Actual   : $actual"
Write-Host ''

if ($actual -ne $expected) {
    Write-Error 'FAIL - SHA-256 không khớp. Không giải nén hoặc sử dụng file này.'
    exit 1
}

Write-Host 'OK - SHA-256 của file .iso.gz khớp.' -ForegroundColor Green
Write-Host 'Tiếp theo: giải nén file .iso.gz bằng 7-Zip để lấy file .iso, sau đó gắn .iso vào VirtualBox.'
exit 0
