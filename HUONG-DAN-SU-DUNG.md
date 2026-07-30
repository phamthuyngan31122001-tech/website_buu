# Hướng dẫn sử dụng — Hệ thống quản lý danh sách quần chúng

Tài liệu dành cho người dùng cuối (cán bộ quản lý đơn vị, người phụ trách danh sách quân số).
Hướng dẫn từng thao tác trên giao diện web.

---

## 1. Đăng nhập

1. Mở trình duyệt, vào địa chỉ hệ thống (ví dụ `https://htqlqc.com`).
2. Nhập **Tên đăng nhập** và **Mật khẩu** được cấp → bấm **Đăng nhập**.
3. Vào lần đầu bằng tài khoản quản trị, **hãy đổi mật khẩu ngay** (xem mục 2).

**Về khóa đăng nhập:** nếu nhập sai mật khẩu nhiều lần, hệ thống sẽ tạm khóa và bắt chờ, thời gian
chờ tăng dần (sai 5 lần: chờ 1 phút; 6 lần: 3 phút; 7 lần: 5 phút; 8 lần: 10 phút; 9 lần: 30 phút;
10 lần: 1 giờ; từ 11 lần: 24 giờ). Màn hình sẽ hiện đồng hồ đếm ngược. Hãy chờ hết thời gian rồi thử lại.

> Mẹo: tên đăng nhập phân biệt chữ hoa/thường. Nhập đúng như được cấp.

---

## 2. Đổi mật khẩu / đổi tên đăng nhập của chính mình

Trên màn hình chính, ở khu điều khiển góc trên:

- **Đổi mật khẩu:** bấm nút **Đổi mật khẩu** → nhập *Mật khẩu cũ*, *Mật khẩu mới* (và xác nhận) → **Lưu**.
- **Đổi tên đăng nhập:** bấm nút **Tài khoản** (hoặc ô tên đăng nhập) → nhập tên mới → **Xác nhận**.

Nên đặt mật khẩu mạnh (dài, có chữ + số + ký tự đặc biệt).

**Đăng xuất:** bấm nút **Đăng xuất**.

---

## 3. Vai trò và quyền hạn

| Vai trò | Quyền |
|---|---|
| **Quản trị gốc (root_admin)** | Toàn quyền: xem/sửa mọi đơn vị, tạo người dùng, đổi cài đặt mạng, quản lý toàn bộ cây. |
| **Quản lý đơn vị (org_manager)** | **Sửa** đơn vị của mình và các đơn vị **cấp dưới**; **xem** (chỉ đọc) đơn vị **cấp trên** (cần mở khóa để tải tài liệu cấp trên). |
| **Kiểm toán (auditor)** | Xem/duyệt (chỉ đọc), không chỉnh sửa dữ liệu. |

Nguyên tắc chung: **cấp trên nhìn thấy dữ liệu tổng hợp của cấp dưới**; mỗi đơn vị chỉ thấy phần
được phân quyền theo cây tổ chức.

---

## 4. Màn hình chính — Cây tổ chức

Sau khi đăng nhập, màn hình chính hiển thị:

- **Sơ đồ cây tổ chức** (các đơn vị e1, d1, c1…): bấm vào một đơn vị để mở **trang chi tiết** của đơn vị đó.
- **Danh sách đơn vị** bên cạnh, kèm ô **Tìm đơn vị** để lọc nhanh theo tên.
- Các nút chức năng: **Cài đặt (⚙)**, **Tài khoản**, **Tài liệu**, **Báo cáo**.

### Quản lý đơn vị trên cây

Với mỗi đơn vị, bấm **Tùy chọn (⋮)** để mở menu thao tác:

- **Đổi tên (✎):** đổi tên đơn vị.
- **Di chuyển lên (↑):** đổi thứ tự đơn vị trong danh sách.
- **Xóa khỏi danh sách (🗑):** xóa đơn vị. ⚠️ **Xóa sẽ xóa cả nhánh con** (đơn vị con, thành viên,
  tài liệu, tài khoản kèm theo) và **không khôi phục được**. Không thể xóa đơn vị gốc.

Trong khung sơ đồ cây còn có:

- **Thêm nút con:** tạo một đơn vị con mới dưới đơn vị đang chọn. Hệ thống **tự tạo sẵn một tài khoản
  đăng nhập** cho đơn vị mới và hiển thị tài khoản/mật khẩu tạm để bàn giao.
- **Đổi tên / Lưu tên:** đổi tên nút đang chọn.
- **Xóa nút:** xóa đơn vị đang chọn (kèm cảnh báo như trên).
- **Xem tài khoản / mật khẩu:** hiển thị tài khoản đăng nhập gắn với đơn vị (chỉ người có quyền quản lý
  đơn vị đó mới xem được). ⚠️ Đây là thông tin nhạy cảm — tránh để người khác nhìn thấy màn hình.

> Các thao tác thêm/đổi tên/xóa/di chuyển đơn vị được **lưu thật** vào dữ liệu, không chỉ là hiển thị tạm.

---

## 5. Trang chi tiết đơn vị — Danh sách quân số

Bấm vào một đơn vị để mở trang chi tiết. Tại đây hiển thị **bảng danh sách** dạng Excel, các cột chuẩn:

| STT | Họ và tên | Sinh ngày | Trình độ | Cấp bậc | Mức độ hoàn thành nhiệm vụ |
|---|---|---|---|---|---|

Các nút trên trang:

- **Quay lại / Về trang chủ:** trở về màn hình chính.
- **Tab tài liệu** (ví dụ `e1.xlsx`) với nút **▾**: chọn tài liệu đang xem; **×** đóng tab; **+** mở/thêm tài liệu.
- **⌕ Tìm kiếm tài liệu:** tìm nhanh trong danh sách.
- **⇩ Tải Excel (.xlsx):** tải bảng đang hiển thị về đúng định dạng Excel.

### Xem theo cấp

- Nếu bạn là **cấp trên**, bảng của đơn vị cấp trên là **bảng tổng hợp** ("Sổ tổng hợp nhân sự")
  gộp dữ liệu từ các đơn vị cấp dưới — cập nhật của cấp dưới sẽ phản ánh lên đây.
- Đơn vị lá (thấp nhất) có bảng danh sách gốc của chính đơn vị.

### Chỉnh sửa bảng (với người có quyền sửa)

Người quản lý đơn vị (hoặc cấp trên của đơn vị) có thể chỉnh sửa nội dung bảng của đơn vị mình phụ trách,
sau đó **lưu** để ghi vào dữ liệu. Thay đổi ở đơn vị cấp dưới sẽ được **tổng hợp lên** bảng của cấp trên.

> Người chỉ có quyền **xem** (cấp dưới nhìn cấp trên, hoặc vai trò kiểm toán) sẽ không sửa được, chỉ đọc.

---

## 6. Tài liệu (tải lên / tải xuống)

Mở khung **Tài liệu** ở màn hình chính hoặc trong trang đơn vị.

### Tải danh sách lên (upload)

- Dùng **Tải lên danh sách** → chọn file Excel (`.xlsx`) theo đúng mẫu cột ở mục 5.
  (File mẫu: `docs-mau/danh-sach-mau.xlsx`.)
- Tài liệu tải lên được **mã hóa** khi lưu.

### Tải xuống

- **Tải Excel (.xlsx):** tải bảng đang xem về (không cần khóa) — dùng cho nhu cầu xem/in thông thường.
- **Tải bản mã hóa gốc:** với tài liệu đã mã hóa hậu lượng tử, khi tải bản gốc cần **khóa giải mã hợp lệ**.
  Nhập sai khóa sẽ **không tải được** (hệ thống báo lỗi khóa không hợp lệ).
- **Mở khóa tài liệu cấp trên:** nếu bạn là cấp dưới muốn tải tài liệu của đơn vị cấp trên, cần thao tác
  **mở khóa** trước (theo phân quyền).

> Lưu ý: tên file tải về hiện có thể bị thay dấu tiếng Việt thành dấu gạch dưới (ví dụ
> `Danh sách.xlsx` → `Danh_s_ch.xlsx`). Đây là hạn chế đã biết, không ảnh hưởng nội dung file.

---

## 7. Báo cáo

Bấm nút **Báo cáo** ở màn hình chính:

- Chọn đơn vị cần xem trong danh sách (có ô **Tìm đơn vị** để lọc).
- Hệ thống dựng báo cáo bám theo đúng các cột của bảng danh sách đơn vị đó.
- Có thể dùng cùng các thao tác **Đổi tên / Di chuyển lên / Xóa** như ở danh sách đơn vị.

---

## 8. Cài đặt (chỉ quản trị gốc)

Bấm **Cài đặt (⚙)**:

- **Chế độ mạng:** chuyển giữa `internet-test` (nhận mọi IP) và `lan-only` (chỉ IP nội bộ),
  và khai báo danh sách IP cho phép. *(Chỉ tài khoản quản trị gốc thao tác được.)*
- **Chỉnh sửa giao diện:** tùy chỉnh hiển thị.

> Thay đổi chế độ mạng ảnh hưởng đến việc ai truy cập được hệ thống — chỉ đổi khi hiểu rõ.

---

## 9. Tạo người dùng mới (quản trị)

Quản trị gốc có thể tạo tài khoản theo vai trò (`root_admin`, `org_manager`, `auditor`) và **gán đơn vị
phụ trách**. Với đơn vị tạo mới từ cây, hệ thống tự sinh sẵn một tài khoản quản lý cho đơn vị đó.

Sau khi bàn giao tài khoản, nên yêu cầu người dùng **đổi mật khẩu ngay** ở lần đăng nhập đầu.

---

## 10. Mẹo & lưu ý an toàn

- **Đổi mật khẩu mặc định ngay** sau lần đăng nhập đầu; đặt mật khẩu mạnh.
- Tài khoản/mật khẩu đơn vị là thông tin nhạy cảm — tránh mở khi có người nhìn màn hình, đăng xuất khi rời máy.
- **Xóa đơn vị là xóa cả nhánh con và không khôi phục được** — cân nhắc kỹ, nên sao lưu trước.
- Khi bị khóa đăng nhập, **chờ hết đếm ngược** thay vì thử liên tục (thử tiếp sẽ kéo dài thời gian khóa).
- Dữ liệu được mã hóa và lưu nội bộ; việc sao lưu do quản trị hệ thống thực hiện định kỳ.

---

### Tóm tắt thao tác nhanh

| Muốn làm gì | Bấm vào |
|---|---|
| Xem danh sách một đơn vị | Bấm tên đơn vị trên cây |
| Sửa danh sách | Mở trang đơn vị → chỉnh bảng → Lưu (nếu có quyền) |
| Tải danh sách ra Excel | Nút **⇩ Tải Excel (.xlsx)** |
| Tải danh sách lên | **Tải lên danh sách** → chọn file .xlsx |
| Thêm đơn vị con | **Thêm nút con** |
| Đổi tên / Di chuyển / Xóa đơn vị | **Tùy chọn (⋮)** → chọn thao tác |
| Xem tài khoản đơn vị | **Xem tài khoản / mật khẩu** |
| Đổi mật khẩu của mình | **Đổi mật khẩu** |
| Xem báo cáo | **Báo cáo** |
| Đổi chế độ mạng (admin) | **Cài đặt (⚙)** |
