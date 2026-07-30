# CI/CD push-to-deploy với Docker (Linux VPS) — giống cách web lớn làm

Mục tiêu: **sửa code ở máy bất kỳ → `git push` lên `main` → website tự cập nhật**
sau vài phút, không thao tác thủ công.

## Luồng tự động
```
Bạn: sửa code → git push origin main
        ↓
GitHub Actions (.github/workflows/deploy.yml): build Docker image → đẩy lên GHCR
        ↓
VPS - Watchtower: mỗi 60s kiểm tra, thấy image mới → tự cập nhật container app
        ↓
https://htqlqc.com đã chạy bản mới (Caddy giữ HTTPS, dữ liệu giữ nguyên trong volume)
```

---

## A. Cài đặt 1 lần

### A1. Bật CI trên GitHub (build image)
- Workflow đã có sẵn: `.github/workflows/deploy.yml` (chạy khi push `main`).
- Vào repo trên GitHub → **Settings → Actions → General → Workflow permissions** → chọn
  **Read and write permissions** (để đẩy image lên GHCR).
- Đẩy code lên `main` lần đầu (xem mục C) → Actions sẽ build và tạo package image.
- Vào **Packages** của repo → mở package `website_buu` → **Package settings** →
  **Change visibility → Public** (để VPS kéo image không cần đăng nhập).
  *(Nếu muốn để Private: xem mục E.)*

### A2. Trên VPS Linux (Ubuntu/Debian)
1. **DNS**: `A htqlqc.com → IP_VPS` và `A www.htqlqc.com → IP_VPS`
   (nếu ở Cloudflare, để **DNS only/xám** để Caddy tự lấy chứng chỉ).
2. **Mở cổng 80, 443** ở firewall nhà cung cấp VPS + máy:
   ```bash
   sudo ufw allow 80,443/tcp && sudo ufw allow OpenSSH && sudo ufw enable
   ```
3. **Cài Docker**:
   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER   # đăng xuất/đăng nhập lại cho có hiệu lực
   ```
4. **Lấy file triển khai + cấu hình**:
   ```bash
   git clone <URL_REPO> ~/website_buu && cd ~/website_buu/deploy/docker
   cp .env.example .env
   nano .env            # đặt IMAGE đúng OWNER, mật khẩu admin mạnh
   nano Caddyfile       # đổi email + (nếu cần) tên miền
   ```
5. **Chạy**:
   ```bash
   docker compose up -d
   docker compose logs -f       # xem khởi động; Ctrl+C để thoát log
   ```
6. Mở **https://htqlqc.com** → đăng nhập tài khoản bootstrap → đổi mật khẩu admin.

---

## B. Từ giờ — cập nhật website (đây là phần "tự động")
Trên **máy bất kỳ** có code, chỉ cần:
```bash
git add -A && git commit -m "đổi giao diện ..."
git push origin main
```
→ GitHub Actions build image mới → Watchtower trên VPS (≤60s sau khi image lên)
tự kéo về và thay container → **website tự đổi theo**. Không cần đụng vào VPS.

> Đang phát triển trên nhánh khác? Gộp vào `main` để triển khai:
> ```bash
> git checkout main && git merge <nhánh-của-bạn> && git push origin main
> ```
> (Hoặc sửa `branches: [main]` trong workflow thành nhánh bạn muốn dùng làm production.)

---

## C. Lần đẩy đầu tiên (tạo image)
```bash
# tại máy dev
git checkout main 2>/dev/null || git checkout -b main
git merge claude/bug-fixes-cleanup-7gybqt   # gộp toàn bộ thay đổi
git push origin main
```
Theo dõi build ở tab **Actions** của repo. Build xong → image có ở **Packages**.

---

## D. Vận hành
- Trạng thái: `docker compose ps`
- Log app: `docker compose logs -f app`
- Cập nhật thủ công ngay (không chờ Watchtower): `docker compose pull && docker compose up -d`
- Khởi động lại: `docker compose restart app`
- Dừng tất cả: `docker compose down`

## E. (Tùy chọn) Giữ image Private trên GHCR
Nếu không muốn để image Public, đăng nhập GHCR trên VPS để Watchtower kéo được:
```bash
echo <GITHUB_TOKEN_co_quyen_read:packages> | docker login ghcr.io -u <github_user> --password-stdin
```
(token tạo ở GitHub → Settings → Developer settings → Personal access tokens, scope `read:packages`.)

## F. Sao lưu (quan trọng)
Dữ liệu + khóa mã hóa nằm trong volume `buu_data`. Sao lưu định kỳ:
```bash
docker run --rm -v website_buu_buu_data:/data -v $PWD:/backup alpine \
  tar czf /backup/buu_data_backup.tar.gz -C /data .
```
Mất khóa `keys/master_key.b64` = KHÔNG giải mã lại được dữ liệu.

## Có cần Cloudflare không?
- **Không.** Caddy trong compose tự lo HTTPS (Let's Encrypt) + tự gia hạn.
- Tùy chọn bật proxy Cloudflare (ẩn IP, chống DDoS), SSL = **Full (strict)**.
- **Không dùng Cloudflare Tunnel** — chỉ cần khi máy không có IP công khai.
