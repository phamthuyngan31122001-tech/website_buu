# Website nội bộ tổ chức bằng Rust

Ứng dụng này là một web nội bộ viết bằng Rust, tối ưu cho mạng LAN hoặc chạy cục bộ, không dùng dịch vụ internet ngoài trong mã nguồn. Dữ liệu được lưu bằng Feather và mã hóa tại chỗ, tài liệu tải lên được mã hóa bằng Kyber1024 kết hợp XChaCha20Poly1305.

## Bao phủ yêu cầu

- Cây tổ chức nhiều cấp: đã có, cấp trên thấy ngay cập nhật từ cấp dưới theo cây quyền.
- Thêm nhánh, phân loại cây bằng key quyền: đã có qua `APP_TREE_KEY` và cờ `tree_key_enabled`.
- Quản lý thành viên, hoạt động theo năm: đã có.
- Mã hóa dữ liệu: đã có cho dữ liệu nghiệp vụ, mật khẩu, tài liệu tải lên.
- Chế độ mạng: đã bổ sung `internet-test` và `lan-only`.
- Giao diện dễ dùng trên LAN: đã có giao diện server-rendered, không phụ thuộc frontend ngoài.
- Kiểm thử và rà lỗi: đã có `cargo test`, `cargo check`; khuyến nghị thêm `cargo clippy` và `cargo audit` khi môi trường cho phép.
- Hướng dẫn cài đặt, sử dụng, sửa chữa: đã có trong tài liệu này.
- Feather + std trong Rust: đã dùng Feather qua `arrow-ipc` với lưu file cục bộ.
- Mã hóa hậu lượng tử: đã dùng Kyber1024 để bảo vệ khóa tài liệu.

Các điểm cần hiểu đúng:

- Chặn internet tuyệt đối vào và ra không thể chỉ dựa vào code ứng dụng. Bản hiện tại đã không gọi dịch vụ internet và ở `lan-only` sẽ chặn request từ IP public, nhưng khi đưa vào dùng thật vẫn phải chặn thêm bằng firewall/router.
- Kyber1024 là KEM hậu lượng tử để bọc khóa tài liệu. Dữ liệu nghiệp vụ Feather đang được mã hóa đối xứng bằng XChaCha20Poly1305 với master key cục bộ, đây là lựa chọn thực dụng và hiệu quả hơn cho dữ liệu lưu trữ lớn.

## Chức năng chính

- Cây tổ chức nhiều cấp, cấp trên xem ngay cập nhật của cấp dưới.
- Quản lý thành viên theo đơn vị và theo năm.
- Quản lý hoạt động đã diễn ra, đang diễn ra, sẽ diễn ra.
- Tạo người dùng theo vai trò `root_admin`, `org_manager`, `auditor`.
- Tài liệu tải lên được mã hóa hậu lượng tử, tải xuống cần private key hợp lệ.

## Cài đặt

1. Cài Rust stable.
2. Vào thư mục dự án và chạy `cargo run`.
3. Truy cập `http://127.0.0.1:8080`.

Biến môi trường tùy chọn:

- `APP_NETWORK_MODE`: `internet-test` hoặc `lan-only`. Mặc định là `lan-only`.
- `APP_BIND_ADDR`: mặc định `127.0.0.1:8080`. Muốn mở trong LAN, đặt ví dụ `0.0.0.0:8080`.
- `APP_TREE_KEY`: key thao tác cây tổ chức.
- `APP_BOOTSTRAP_USERNAME`: tài khoản admin khởi tạo.
- `APP_BOOTSTRAP_PASSWORD`: mật khẩu admin khởi tạo.

Ví dụ chạy kiểm tra giữa máy chủ và máy khách:

```powershell
$env:APP_NETWORK_MODE="internet-test"
$env:APP_BIND_ADDR="0.0.0.0:8080"
cargo run
```

Ví dụ chạy khi đưa vào sử dụng nội bộ:

```powershell
$env:APP_NETWORK_MODE="lan-only"
$env:APP_BIND_ADDR="0.0.0.0:8080"
$env:APP_TREE_KEY="doi-key-rieng"
$env:APP_BOOTSTRAP_PASSWORD="doi-mat-khau-admin"
cargo run
```

Điểm kiểm tra kết nối máy chủ - máy khách:

- `GET /health`: trả về trạng thái app, mode hiện tại và timestamp.

## Bảo mật và vận hành

- Dữ liệu nghiệp vụ nằm ở `runtime/data/*.feather.enc`.
- Master key nằm ở `runtime/keys/master_key.b64`.
- Khóa tài liệu hậu lượng tử nằm ở `runtime/keys/mlkem_public.b64` và `runtime/keys/mlkem_private.b64`.
- Log vận hành nằm ở `runtime/logs/app.log`; dùng file này để xem lỗi bind cổng, tiến trình bootstrap, seed dữ liệu và mốc khởi động.
- Ở mode `lan-only`, ứng dụng chỉ chấp nhận request từ IP loopback, private hoặc link-local.
- Ứng dụng không gọi internet ra ngoài trong logic runtime.
- Để chặn internet tuyệt đối, cần cấu hình thêm firewall trên máy chủ và chỉ cho phép cổng LAN nội bộ cần thiết.
- Response đã thêm các header giảm rủi ro cơ bản: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control`.

## Sử dụng

1. Đăng nhập bằng tài khoản bootstrap lần đầu.
2. Tạo đơn vị gốc hoặc nhánh con bằng `APP_TREE_KEY`.
3. Tạo user theo vai trò và gán đơn vị phụ trách.
4. Cập nhật thành viên và hoạt động theo năm.
5. Tải tài liệu lên; khi tải xuống phải có private key hậu lượng tử hợp lệ.

## Kiểm thử

- `cargo test`
- `cargo check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit` nếu môi trường cho phép cài thêm công cụ

Hiện có test cho:

- route `GET /health`
- lọc IP ở mode `lan-only`
- đăng nhập hợp lệ và tạo session cookie

## Kiểm tra lỗ hổng và fix bug

- Kiểm tra quyền: thử tài khoản `org_manager` chỉ nhìn thấy cây của đơn vị được gán.
- Kiểm tra chế độ mạng: ở `lan-only`, thử truy cập từ IP public sẽ bị từ chối ở tầng ứng dụng.
- Kiểm tra key tài liệu: nhập sai private key phải không tải được file.
- Khi sửa lỗi, chạy lại `cargo check`, `cargo test` và kiểm tra `GET /health` trước khi triển khai lại.

## Chuyển firewall Windows

Script [c:\Users\DELL\Desktop\website_buu\scripts\set-firewall-mode.ps1](/c:/Users/DELL/Desktop/website_buu/scripts/set-firewall-mode.ps1) quản lý rule firewall cho file chạy thực tế.

Ví dụ bật mode kiểm tra mở:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-firewall-mode.ps1 -Mode internet-test -ProgramPath .\target\release\website_buu.exe -Port 8080
```

Ví dụ bật mode LAN-only khi triển khai:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-firewall-mode.ps1 -Mode lan-only -ProgramPath .\target\release\website_buu.exe -Port 8080
```

Gỡ toàn bộ rule do script tạo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\set-firewall-mode.ps1 -Mode lan-only -ProgramPath .\target\release\website_buu.exe -RemoveOnly
```

## Bảo hành sửa chữa

- Quy trình khuyến nghị: sao lưu thư mục `runtime/`, đổi khóa nếu nghi lộ, kiểm tra `runtime/logs/app.log`, chạy lại bộ test trước khi nâng cấp.
- Nếu cần sửa lỗi, ưu tiên tái hiện trên dữ liệu sao lưu, sửa trong nhánh riêng, chạy lại `cargo test` và kiểm tra quyền truy cập cây tổ chức trước khi triển khai.