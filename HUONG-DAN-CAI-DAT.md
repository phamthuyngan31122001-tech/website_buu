# Hướng dẫn cài đặt & triển khai website_buu (từ mã nguồn đến chạy thật trên internet)

Tài liệu này hướng dẫn đầy đủ từ lúc có mã nguồn trên máy đến khi website chạy công khai
tại tên miền của bạn (ví dụ `https://htqlqc.com`). Có 3 cách triển khai, chọn 1 cách phù hợp.

> **Tóm tắt nhanh:** website là một chương trình Rust duy nhất (`website_buu`), tự phục vụ toàn
> bộ giao diện (không cần Node/PHP/database ngoài). Dữ liệu lưu mã hóa trong thư mục `runtime/`.
> Bản thân app chỉ chạy HTTP nội bộ; một reverse proxy (Caddy hoặc nginx) đứng trước lo HTTPS.

---

## 0. Kiến trúc tổng quan

```
Internet ──HTTPS(443)──►  Reverse proxy (Caddy hoặc nginx, tự xin chứng chỉ Let's Encrypt)
                              └── proxy HTTP ──►  website_buu  (nghe 127.0.0.1:18088)
                                                     └── đọc/ghi thư mục runtime/ (dữ liệu + khóa mã hóa)
```

- **Ngôn ngữ/nền tảng:** Rust + Axum (async). Một file thực thi duy nhất.
- **Lưu trữ:** file Feather mã hóa (`runtime/data/*.feather.enc`), không cần cơ sở dữ liệu.
- **Mã hóa:** master key cục bộ (XChaCha20-Poly1305) cho dữ liệu; Kyber1024 (hậu lượng tử) bọc khóa tài liệu.
- **HTTPS:** do reverse proxy đảm nhiệm; app chỉ chạy HTTP nội bộ 127.0.0.1.

---

## 1. Yêu cầu công cụ để build

Cần cài trên máy build (máy dev hoặc trực tiếp trên VPS):

| Công cụ | Ghi chú |
|---|---|
| **Rust stable mới** (≥ 1.85, hỗ trợ *edition 2024*) | Cài qua https://rustup.rs |
| **CMake** | `aws-lc-rs` cần khi build |
| **Perl** | Windows: Strawberry Perl |
| **NASM** | **Bắt buộc cho bản `--release`** (aws-lc). Bản debug có thể bỏ qua bằng `AWS_LC_SYS_NO_ASM=1` |
| **Git** | để lấy mã nguồn |
| Windows build tools / `build-essential` | Windows: Visual Studio C++ Build Tools; Linux: `build-essential pkg-config` |

Cài nhanh trên Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y build-essential cmake nasm pkg-config perl git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

---

## 2. Lấy mã nguồn & build

```bash
git clone <URL_REPO_GIT> website_buu
cd website_buu

# Build bản chạy thật (tối ưu). Lần đầu khá lâu (vài phút).
cargo build --release
# → File thực thi: target/release/website_buu   (Windows: target\release\website_buu.exe)
```

Chạy kiểm thử/kiểm tra trước khi triển khai (khuyến nghị):
```bash
cargo check
cargo test
cargo clippy --all-targets -- -D warnings   # nếu có cài clippy
```

> RAM thấp (<1 GB) khi build release có thể cần thêm swap.

---

## 3. Chạy thử cục bộ (trước khi đưa lên internet)

**Linux/macOS:**
```bash
export APP_RUNTIME_DIR=runtime
export APP_BIND_ADDR=127.0.0.1:18088
export APP_REQUIRE_HTTPS=0
export APP_NETWORK_MODE=lan-only
./target/release/website_buu
```

**Windows PowerShell:**
```powershell
$env:APP_RUNTIME_DIR="runtime"
$env:APP_BIND_ADDR="127.0.0.1:18088"
$env:APP_REQUIRE_HTTPS="0"
$env:AWS_LC_SYS_NO_ASM="1"
.\target\release\website_buu.exe
```

Mở trình duyệt: `http://127.0.0.1:18088` và kiểm tra sức khỏe:
```bash
curl http://127.0.0.1:18088/health
# status=ok / mode=... / time=...
```

Đăng nhập lần đầu bằng tài khoản bootstrap (xem mục 4). Mặc định là `Admin@1999` / `Admin@1999`
— **đổi ngay** sau khi vào.

---

## 4. Biến môi trường (cấu hình app)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `APP_BIND_ADDR` | `127.0.0.1:8080` | Địa chỉ:cổng app lắng nghe. Sau proxy nên để `127.0.0.1:18088`. |
| `APP_NETWORK_MODE` | `lan-only` | `lan-only` chỉ nhận IP nội bộ/loopback/link-local; `internet-test` nhận mọi IP. **VPS công khai bắt buộc `internet-test`** (xem lưu ý dưới). |
| `APP_REQUIRE_HTTPS` | `0` | `1/true/yes/on` = bắt buộc HTTPS (bật cờ `Secure` cho cookie). Đặt `1` khi có proxy gửi `X-Forwarded-Proto=https`. |
| `APP_RUNTIME_DIR` | `runtime` | Thư mục lưu dữ liệu + khóa + log. |
| `APP_BOOTSTRAP_USERNAME` | `Admin@1999` | Tài khoản admin tạo lần đầu (chỉ tạo khi chưa có dữ liệu). |
| `APP_BOOTSTRAP_PASSWORD` | `Admin@1999` | Mật khẩu admin lần đầu. **Phải đổi thành mật khẩu mạnh trước khi chạy thật.** |
| `APP_TREE_KEY` | (tự sinh) | Khóa thao tác cây tổ chức. Bỏ trống → app tự sinh và ghi ra file trong `runtime/keys`. |
| `APP_SKIP_DEMO_SEED` | (tắt) | Đặt `1` để **không** nạp dữ liệu mẫu (đơn vị/danh sách demo) khi khởi tạo. Dùng khi chạy thật. |
| `AWS_LC_SYS_NO_ASM` | — | Đặt `1` để bỏ phụ thuộc NASM (thường chỉ cần cho bản debug/máy thiếu NASM). |

> ⚠️ **Lưu ý quan trọng về `lan-only` sau proxy:** app lọc IP dựa trên IP kết nối trực tiếp
> tới nó. Khi đứng sau Caddy/nginx, mọi request đều đến từ `127.0.0.1` nên `lan-only` sẽ *cho qua
> tất cả* (kể cả internet). Vì vậy VPS công khai dùng `internet-test` và chặn truy cập ở tầng
> tường lửa/proxy, không dựa vào `lan-only` của app.

**Điểm kiểm tra sức khỏe:** `GET /health` → trả `status=ok`, mode, thời gian. Dùng để kiểm tra proxy ↔ app.

---

## 5. Triển khai lên website

Chọn **một** trong ba cách:

### Cách A — Windows Server + Caddy + NSSM (đang dùng cho htqlqc.com) ✅

Phù hợp khi VPS chạy Windows. Script `deploy/windows/setup.ps1` tự tải Caddy + NSSM, tạo
2 Windows Service (app + Caddy) chạy nền, tự bật khi reboot, tự restart khi lỗi.

**Chuẩn bị 1 lần:**
1. Trỏ DNS về IP VPS:
   ```
   A   htqlqc.com       -> <IP_VPS>
   A   www.htqlqc.com   -> <IP_VPS>
   ```
   (Dùng Cloudflare DNS thì để **DNS only / đám mây xám** lúc lấy chứng chỉ; bật proxy sau nếu SSL = Full.)
2. Mở cổng **80 và 443** ở cả Windows Firewall (setup tự mở) **và** firewall của nhà cung cấp VPS.
3. Đăng nhập VPS qua Remote Desktop.

**Build ở máy dev rồi copy exe sang VPS (khuyến nghị):**
```powershell
# Máy dev:
cargo build --release            # tạo target\release\website_buu.exe
# Copy website_buu.exe sang VPS, ví dụ C:\deploy\website_buu.exe (kéo-thả qua RDP)

# Trên VPS (PowerShell Administrator), lấy repo để có script rồi chạy setup:
git clone <URL_REPO> C:\website_buu_src
cd C:\website_buu_src
powershell -ExecutionPolicy Bypass -File deploy\windows\setup.ps1 `
  -Domain htqlqc.com `
  -ExePath C:\deploy\website_buu.exe `
  -BootstrapUser Admin@1999 -BootstrapPass "DAT_MAT_KHAU_MANH"
```
→ Xong. Truy cập `https://htqlqc.com`.

**Nếu muốn build ngay trên VPS:** cài Rust + CMake + Perl + NASM + Git trên VPS, `cargo build --release`,
rồi chạy `setup.ps1` (không cần `-ExePath`).

**Vận hành (Windows):**
```powershell
Get-Service website_buu, caddy                     # trạng thái
C:\website_buu\tools\nssm.exe restart website_buu   # khởi động lại app
C:\website_buu\tools\nssm.exe restart caddy         # khởi động lại Caddy (khi đổi domain)
# Log app: C:\website_buu\runtime\service-err.log
```

**Cập nhật phiên bản mới:** build lại exe ở máy dev → copy đè lên VPS → `nssm.exe restart website_buu`.
Hoặc dùng `deploy\windows\update.ps1` (tự pull + build + copy + restart) nếu build trên VPS.

---

### Cách B — Linux VPS + systemd + nginx + Let's Encrypt

Phù hợp VPS Linux có IP công khai. Xem chi tiết trong `deploy/DEPLOY.md`.

```bash
# 1) Build
sudo mkdir -p /opt/website_buu && sudo chown $USER /opt/website_buu
git clone <URL_REPO_GIT> /opt/website_buu/src
cd /opt/website_buu/src
cargo build --release
cp target/release/website_buu /opt/website_buu/website_buu

# 2) User chạy dịch vụ + thư mục dữ liệu
sudo useradd -r -s /usr/sbin/nologin wwwbuu
sudo mkdir -p /opt/website_buu/runtime
sudo chown -R wwwbuu:wwwbuu /opt/website_buu

# 3) Service systemd
sudo cp deploy/website_buu.service /etc/systemd/system/website_buu.service
sudo nano /etc/systemd/system/website_buu.service   # ĐỔI APP_BOOTSTRAP_PASSWORD mạnh!
sudo systemctl daemon-reload
sudo systemctl enable --now website_buu
sudo systemctl status website_buu                   # phải "active (running)"

# 4) nginx + HTTPS
sudo cp deploy/nginx-website_buu.conf /etc/nginx/sites-available/website_buu
sudo nano /etc/nginx/sites-available/website_buu    # sửa server_name = domain của bạn
sudo ln -s /etc/nginx/sites-available/website_buu /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d qk5.htqlqc.com           # tự cấp + tự gia hạn chứng chỉ

# 5) Tường lửa
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```
File service đã đặt sẵn `APP_NETWORK_MODE=internet-test`, `APP_REQUIRE_HTTPS=1`, app nghe `127.0.0.1:18088`.
nginx đã gửi `X-Forwarded-Proto=https` và cho upload tới 50 MB.

**Cập nhật:**
```bash
cd /opt/website_buu/src && git pull && cargo build --release
sudo cp target/release/website_buu /opt/website_buu/website_buu
sudo systemctl restart website_buu
```

---

### Cách C — Docker Compose + Caddy + Watchtower (tự động CI/CD)

Phù hợp khi muốn tự động: push code lên `main` → GitHub Actions build image → Watchtower tự cập nhật.
Xem `deploy/docker/DEPLOY-DOCKER.md`.

```bash
cd deploy/docker
cp .env.example .env
nano .env          # đặt APP_BOOTSTRAP_PASSWORD mạnh, sửa IMAGE = repo GHCR của bạn
# Sửa Caddyfile cho đúng domain (deploy/docker/Caddyfile)
docker compose up -d
```
- Caddy mở cổng 80/443, tự xin chứng chỉ; app nghe nội bộ `18088`.
- Dữ liệu nằm ở volume `buu_data` (`/data`) — **không mất khi cập nhật image**.
- Watchtower kiểm tra mỗi 30s và tự cập nhật container app.

Tự build & đẩy image thủ công (nếu không dùng GitHub Actions):
```bash
docker build -t ghcr.io/<owner>/website_buu:latest .
docker push ghcr.io/<owner>/website_buu:latest
```

---

## 6. Kiểm tra sau khi triển khai

1. `https://<domain>/health` → `status=ok`.
2. Mở `https://<domain>` → thấy trang đăng nhập, ổ khóa HTTPS hợp lệ.
3. Đăng nhập bằng tài khoản bootstrap → **đổi mật khẩu ngay** (nút "Đổi mật khẩu").
4. Kiểm tra log không có lỗi bind cổng.

---

## 7. Sao lưu & khôi phục (BẮT BUỘC làm định kỳ)

Toàn bộ trạng thái nằm trong thư mục `runtime/`:

| Đường dẫn | Nội dung |
|---|---|
| `runtime/keys/master_key.b64` | Master key (**mất = không giải mã lại được dữ liệu**) |
| `runtime/keys/mlkem_public.b64`, `mlkem_private.b64` | Khóa hậu lượng tử bọc khóa tài liệu |
| `runtime/data/*.feather.enc` | Dữ liệu nghiệp vụ đã mã hóa |
| `runtime/logs/app.log` | Log vận hành (lỗi bind cổng, bootstrap, seed, khởi động) |

- **Sao lưu:** copy toàn bộ thư mục `runtime/` sang nơi an toàn (mã hóa bản sao lưu).
- **Khôi phục:** dừng service → thay thư mục `runtime/` bằng bản sao lưu → khởi động lại.
- Windows còn có `runtime\service-err.log` / `service-out.log` do NSSM ghi.

---

## 8. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| `Error 10048` / cổng bị chiếm | Tiến trình cũ chưa tắt. Windows: `Stop-Process -Name website_buu -Force`; hoặc `netstat -ano | findstr :18088` rồi kill PID. |
| Lỗi build release thiếu NASM | Cài NASM và thêm vào PATH; hoặc build debug với `AWS_LC_SYS_NO_ASM=1`. |
| Trình duyệt báo không bảo mật / cookie mất | Đảm bảo proxy gửi `X-Forwarded-Proto=https` và app đặt `APP_REQUIRE_HTTPS=1`. |
| Chứng chỉ HTTPS không cấp | DNS chưa trỏ đúng IP; cổng 80 chưa mở cho ACME; Cloudflare đang bật proxy (để DNS only khi lấy cert). |
| Truy cập bị chặn "network" | Đang ở `lan-only` mà truy cập từ IP ngoài. VPS công khai đặt `APP_NETWORK_MODE=internet-test`. |
| Lỗi master key | Nếu chấp nhận **mất dữ liệu**: xóa `runtime/keys/master_key.b64` để tạo key mới (dữ liệu cũ sẽ không giải mã được). |

---

## 9. Ghi chú bảo mật khi vận hành thật

- Đổi `APP_BOOTSTRAP_PASSWORD` thành mật khẩu mạnh **trước** lần chạy đầu, và đổi lại trong web sau khi đăng nhập.
- Đặt `APP_SKIP_DEMO_SEED=1` khi chạy thật để không nạp dữ liệu mẫu.
- Hạn chế RDP/SSH chỉ cho IP tin cậy.
- Cân nhắc bật Cloudflare proxy (ẩn IP, chống DDoS), SSL/TLS = **Full (strict)**.
- Sao lưu `runtime/` định kỳ và mã hóa bản sao lưu.

> Tham khảo thêm: `deploy/DEPLOY.md` (Linux), `deploy/windows/DEPLOY-WINDOWS.md` (Windows),
> `deploy/docker/DEPLOY-DOCKER.md` (Docker), `README.md` (tổng quan), `RUN.txt` (chạy nhanh cục bộ/tunnel).
