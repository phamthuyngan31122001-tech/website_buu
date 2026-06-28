# Triển khai website_buu lên VPS Windows — quy trình hoàn chỉnh

Mục tiêu: chạy thật trên `https://blacknull.net`, chế độ **internet** (không LAN-only),
ổn định (tự khởi động lại, tự bật khi reboot), cập nhật nhanh.

## Kiến trúc
```
Internet ──HTTPS──> Caddy (cổng 443, tự xin Let's Encrypt)
                       └── reverse proxy ──> website_buu.exe (HTTP 127.0.0.1:18088)
```
- App chỉ chạy HTTP nội bộ; **Caddy lo HTTPS** (đơn giản nhất trên Windows).
- Cả hai chạy bằng **Windows Service (qua NSSM)** → ổn định.
- `APP_NETWORK_MODE=internet-test` (BẮT BUỘC cho IP công khai; lan-only sẽ chặn).

---

## BƯỚC 0 — Chuẩn bị (làm 1 lần)
1. **DNS**: trỏ về IP VPS (tại Cloudflare/registrar):
   ```
   A   blacknull.net       -> <IP_VPS>
   A   www.blacknull.net   -> <IP_VPS>
   ```
   (Nếu dùng Cloudflare DNS: để **DNS only / đám mây xám** để Caddy tự lấy cert. Bật proxy cam sau cũng được nếu SSL = Full.)
2. **Mở cổng 80 và 443**: cả Windows Firewall (setup.ps1 tự mở) **và** firewall/security group của nhà cung cấp VPS.
3. Đăng nhập VPS bằng **Remote Desktop (RDP)**.

---

## CÁCH A — Nhanh nhất: build ở máy bạn, copy exe sang VPS (khuyến nghị)
Máy dev của bạn đã build được rồi nên đỡ phải cài toolchain trên VPS.

**Trên máy DEV** (cần đã cài Rust + CMake + Perl + **NASM** để build release):
```powershell
cd <thu-muc-project>
git pull origin claude/bug-fixes-cleanup-7gybqt
cargo build --release
# File can copy: target\release\website_buu.exe
```
**Copy sang VPS:** kéo-thả `website_buu.exe` qua cửa sổ RDP (hoặc dùng ổ đĩa chia sẻ RDP).
Đặt nó vào, ví dụ, `C:\deploy\website_buu.exe` trên VPS.

**Trên VPS** (PowerShell **Administrator**), lấy repo để có script + chạy setup:
```powershell
cd C:\
git clone -b claude/bug-fixes-cleanup-7gybqt <URL_REPO> C:\website_buu_src
cd C:\website_buu_src
powershell -ExecutionPolicy Bypass -File deploy\windows\setup.ps1 `
  -Domain blacknull.net `
  -ExePath C:\deploy\website_buu.exe `
  -BootstrapUser Admin@1999 -BootstrapPass "DAT_MAT_KHAU_MANH"
```
→ Xong. Truy cập `https://blacknull.net`.

**Cập nhật sau này (Cách A):** build lại ở máy dev → copy exe đè lên VPS → trên VPS:
```powershell
C:\website_buu\tools\nssm.exe restart website_buu
```

---

## CÁCH B — Tự động hơn: build ngay trên VPS (git pull + build + restart 1 lệnh)
Cần cài toolchain trên VPS (nặng hơn lúc build, nhưng cập nhật bằng 1 script).

**Cài 1 lần trên VPS:**
1. **Rust**: tải https://win.rustup.rs → chạy, chọn mặc định (cần "Visual Studio C++ Build Tools" — rustup sẽ nhắc cài).
2. **CMake**: https://cmake.org/download (nhớ chọn "Add to PATH").
3. **Perl**: Strawberry Perl https://strawberryperl.com (aws-lc cần).
4. **NASM**: https://www.nasm.us/ → cài và thêm vào PATH (BẮT BUỘC cho bản
   release; aws-lc-sys chỉ cho bỏ nasm ở bản debug).
5. **Git**: https://git-scm.com/download/win
6. Mở **PowerShell Administrator mới** (để nhận PATH), rồi:
```powershell
cd C:\
git clone -b claude/bug-fixes-cleanup-7gybqt <URL_REPO> C:\website_buu_src
cd C:\website_buu_src
cargo build --release
powershell -ExecutionPolicy Bypass -File deploy\windows\setup.ps1 `
  -Domain blacknull.net -BootstrapUser Admin@1999 -BootstrapPass "DAT_MAT_KHAU_MANH"
```
**Cập nhật sau này (Cách B):** chỉ 1 lệnh, từ `C:\website_buu_src`:
```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\update.ps1
```
(tự pull + build + copy + restart service)

---

## Vận hành
- Trạng thái service: `Get-Service website_buu, caddy`
- Xem log app: `C:\website_buu\runtime\service-err.log`
- Khởi động lại: `C:\website_buu\tools\nssm.exe restart website_buu`
- Khởi động lại Caddy (nếu đổi domain): `...\nssm.exe restart caddy`
- Gỡ service: `...\nssm.exe remove website_buu confirm`

## Bảo mật bắt buộc
- **Đổi `APP_BOOTSTRAP_PASSWORD`** thành mật khẩu mạnh (tham số khi chạy setup.ps1),
  và đổi mật khẩu admin ngay sau lần đăng nhập đầu.
- Đã đặt `APP_REQUIRE_HTTPS=1` + Caddy gửi `X-Forwarded-Proto=https` → cookie an toàn.
- Chỉ mở RDP cho IP tin cậy nếu có thể.

## Sao lưu (quan trọng)
Sao lưu định kỳ thư mục **`C:\website_buu\runtime`** — chứa dữ liệu (Feather) + khóa mã hóa.
Mất `runtime\keys\master_key.b64` = KHÔNG giải mã lại được dữ liệu.

## Có cần Cloudflare không?
- **Không.** Caddy đã cho HTTPS đầy đủ và tự gia hạn.
- Tùy chọn: thêm domain vào Cloudflare bật proxy (ẩn IP, chống DDoS), đặt SSL = **Full (strict)**.
- **Không dùng Cloudflare Tunnel** nữa — chỉ cần khi máy không có IP công khai.
