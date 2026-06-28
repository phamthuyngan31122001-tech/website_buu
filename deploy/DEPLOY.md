# Triển khai website_buu lên VPS (Linux) — chạy ổn định, không cần Cloudflare Tunnel

VPS có IP công khai nên phục vụ trực tiếp. HTTPS dùng nginx + Let's Encrypt (miễn phí).
Chạy ổn định bằng systemd (tự khởi động lại, tự bật khi reboot).

Giả định: Ubuntu/Debian, domain trỏ A record về IP VPS (vd `qk5.blacknull.net -> IP_VPS`).

---

## 1. Trỏ tên miền về VPS
Ở nơi quản lý DNS (Cloudflare hoặc registrar), tạo bản ghi:
```
A    qk5.blacknull.net    ->    <IP_CONG_KHAI_CUA_VPS>
```
(Nếu dùng Cloudflare DNS, để **DNS only / xám** lúc lấy chứng chỉ Let's Encrypt; sau đó bật proxy/cam tùy ý.)

## 2. Cài công cụ build trên VPS
```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config perl git curl nginx
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## 3. Lấy mã nguồn + build
```bash
sudo mkdir -p /opt/website_buu && sudo chown $USER /opt/website_buu
git clone -b claude/bug-fixes-cleanup-7gybqt <URL_REPO_GIT> /opt/website_buu/src
cd /opt/website_buu/src
AWS_LC_SYS_NO_ASM=1 cargo build --release
cp target/release/website_buu /opt/website_buu/website_buu
```
(Build lần đầu khá lâu ~vài phút. RAM thấp <1GB có thể cần thêm swap.)

## 4. Tạo user chạy dịch vụ + thư mục dữ liệu
```bash
sudo useradd -r -s /usr/sbin/nologin wwwbuu
sudo mkdir -p /opt/website_buu/runtime
sudo chown -R wwwbuu:wwwbuu /opt/website_buu
```

## 5. Cài service systemd
```bash
sudo cp /opt/website_buu/src/deploy/website_buu.service /etc/systemd/system/website_buu.service
sudo nano /etc/systemd/system/website_buu.service     # ĐỔI APP_BOOTSTRAP_PASSWORD mạnh!
sudo systemctl daemon-reload
sudo systemctl enable --now website_buu
sudo systemctl status website_buu        # phải thấy active (running)
journalctl -u website_buu -f             # xem log khởi động
```
App giờ chạy ở `127.0.0.1:18088` (chỉ nội bộ VPS) — nginx sẽ đưa ra ngoài qua HTTPS.

## 6. nginx + HTTPS (Let's Encrypt)
```bash
sudo cp /opt/website_buu/src/deploy/nginx-website_buu.conf /etc/nginx/sites-available/website_buu
# Sửa server_name trong file cho đúng tên miền của bạn:
sudo nano /etc/nginx/sites-available/website_buu
sudo ln -s /etc/nginx/sites-available/website_buu /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d qk5.blacknull.net      # tự cấp chứng chỉ + tự gia hạn
```

## 7. Mở tường lửa
```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'      # mở 80 + 443
sudo ufw enable
```

## 8. Xong
Truy cập: **https://qk5.blacknull.net**
Đăng nhập bằng tài khoản bootstrap đã đặt trong service (đổi mật khẩu ngay sau lần đầu).

---

## Cập nhật phiên bản mới
```bash
cd /opt/website_buu/src
git pull
AWS_LC_SYS_NO_ASM=1 cargo build --release
sudo cp target/release/website_buu /opt/website_buu/website_buu
sudo systemctl restart website_buu
```

## Có cần Cloudflare không?
- **Không bắt buộc.** nginx + Let's Encrypt ở trên đã cho HTTPS đầy đủ.
- Nếu muốn **ẩn IP VPS + chống DDoS + CDN**: thêm domain vào Cloudflare, bật proxy (cam),
  đặt SSL/TLS = **Full (strict)**. Lúc đó vẫn giữ nguyên nginx + Let's Encrypt ở VPS.
- **Không dùng Cloudflare Tunnel nữa** — tunnel chỉ cần khi máy KHÔNG có IP công khai.

## Ghi chú quan trọng
- `APP_NETWORK_MODE=internet-test` là BẮT BUỘC trên VPS công khai (lan-only chặn IP ngoài).
- Sao lưu định kỳ thư mục `/opt/website_buu/runtime` (chứa dữ liệu Feather + khóa mã hóa).
  Mất `runtime/keys/master_key.b64` = mất khả năng giải mã dữ liệu.
