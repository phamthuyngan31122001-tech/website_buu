# Quy trình cập nhật website (đơn giản, cho người không rành code)

Website chạy theo kiểu **tự động**: bạn đẩy code lên GitHub → GitHub tự đóng gói → VPS tự tải về và cập nhật.
Bạn gần như không phải đụng vào máy chủ.

```
Bạn sửa code  →  git push (lên main)  →  GitHub tự build  →  VPS tự cập nhật  →  https://htqlqc.com đổi theo
```

Có **2 loại thay đổi**, cách làm hơi khác nhau:

| Loại thay đổi | Cần làm gì |
|---|---|
| **Giao diện, chức năng, chữ nghĩa, dữ liệu…** (đa số) | Chỉ **push lên GitHub** → tự động hoàn toàn, KHÔNG đụng VPS |
| **Tên miền / Caddyfile / file `.env`** (hạ tầng) | Push lên GitHub → rồi chạy **1 lệnh** trên VPS |

---

## A. Cập nhật giao diện / chức năng (dùng hằng ngày) — TỰ ĐỘNG

Làm ở **máy có code** (máy dev). Chỉ 3 dòng:

```bash
git add -A
git commit -m "mo ta ngan gon thay doi"
git push origin main
```

> **Không quen dòng lệnh?** Dùng **GitHub Desktop**: bấm *Commit to main* → *Push origin*.
> Hoặc sửa file thẳng trên **github.com** rồi bấm nút **Commit** (xanh) — cũng tính là push.

Sau khi push:
1. Chờ **2–4 phút** (GitHub đóng gói + VPS tự tải về).
2. Mở `https://htqlqc.com` bằng **tab ẩn danh** (Ctrl+Shift+N) để tránh bộ nhớ đệm → thấy bản mới.

**Xem đã build xong chưa:** vào repo trên GitHub → tab **Actions**. Dấu **✓ xanh** = xong; vòng tròn vàng = đang chạy.

Xong. Với loại thay đổi này **bạn không cần đăng nhập VPS**.

---

## B. Đổi tên miền / Caddyfile / `.env` — chạy 1 lệnh trên VPS

Các file này **không nằm trong gói app** (chúng được gắn từ ổ đĩa VPS), nên VPS không tự nhận. Sau khi
push lên GitHub, cần cập nhật ở VPS. Để chỉ phải gõ **1 lệnh**, tạo sẵn một script (**làm 1 lần duy nhất**):

**Tạo script (chỉ làm 1 lần):** đăng nhập VPS, dán nguyên khối này:
```bash
cat > /root/capnhat.sh <<'EOF'
#!/bin/bash
set -e
echo "== Dang cap nhat website =="
cd /root/website_buu
git pull origin main
cd deploy/docker
docker compose pull
docker compose up -d --force-recreate
docker image prune -f
echo "== XONG. Mo kiem tra: https://htqlqc.com =="
EOF
chmod +x /root/capnhat.sh
```

**Từ nay, mỗi khi đổi tên miền/cấu hình:** push lên GitHub (như mục A), rồi trên VPS chỉ gõ:
```bash
/root/capnhat.sh
```

> Lệnh này tự: kéo code mới về → tải gói app mới → dựng lại toàn bộ (kể cả Caddy đọc lại Caddyfile) → dọn rác.
> **Dữ liệu và chứng chỉ HTTPS được giữ nguyên**, không mất gì.

---

## C. Bảng "chỉ cần nhớ"

| Muốn làm | Làm gì |
|---|---|
| Sửa giao diện / chức năng | Push lên GitHub → chờ 2–4 phút (tự động) |
| Đổi tên miền / Caddyfile / `.env` | Push lên GitHub → trên VPS gõ `/root/capnhat.sh` |
| Xem web đã đổi chưa | Mở `https://htqlqc.com` ở **tab ẩn danh** |
| Xem GitHub build xong chưa | Repo → tab **Actions** (✓ xanh) |
| Ép cập nhật ngay (không chờ) | Trên VPS gõ `/root/capnhat.sh` |

---

## D. Khi có trục trặc (xử lý nhanh)

- **Web chưa đổi sau vài phút:** mở tab ẩn danh hoặc bấm **Ctrl+F5**. Kiểm tra tab **Actions** đã ✓ xanh chưa.
- **Đổi cấu hình mà chưa thấy tác dụng:** chạy `/root/capnhat.sh` trên VPS (bắt buộc với thay đổi Caddyfile/.env).
- **Kiểm tra máy chủ còn sống:**
  ```bash
  curl -I https://htqlqc.com/health
  ```
  Thấy `HTTP/… 200` là bình thường.
- **Xem log khi lỗi:**
  ```bash
  cd /root/website_buu/deploy/docker
  docker compose logs --tail=50 app     # log ứng dụng
  docker compose logs --tail=50 caddy   # log HTTPS / tên miền
  ```

---

## E. Sao lưu dữ liệu (nên làm định kỳ, ví dụ hằng tuần)

Toàn bộ dữ liệu + khóa mã hóa nằm trong volume Docker. Sao lưu bằng 1 lệnh trên VPS:
```bash
docker run --rm -v docker_buu_data:/data -v /root:/backup alpine \
  tar czf /backup/buu_backup_$(date +%F).tar.gz -C /data .
```
File sao lưu sẽ nằm ở `/root/buu_backup_NGAY.tar.gz` — tải về nơi an toàn.

> ⚠️ **Mất khóa `keys/master_key.b64` là KHÔNG giải mã lại được dữ liệu.** Luôn giữ bản sao lưu cẩn thận.

---

## Ghi nhớ 1 câu
- **Thay đổi bình thường** → chỉ **push GitHub**, chờ vài phút.
- **Đổi tên miền/cấu hình** → push GitHub **+** gõ `/root/capnhat.sh` trên VPS.
