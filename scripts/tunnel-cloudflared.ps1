# Mo website ra internet bang Cloudflare Tunnel.
# Dung khi ngrok bi ISP chan (loi "connection forcibly closed" / ERR_NGROK_3200).
# Cloudflare di qua ha tang khac (443/QUIC) nen thuong on dinh hon o Viet Nam.
#
# Tai cloudflared (1 lan): https://github.com/cloudflare/cloudflared/releases
#   (tai cloudflared-windows-amd64.exe, doi ten thanh cloudflared.exe, dat vao PATH
#    hoac canh thu muc project)
#
# ── CHE DO 1: QUICK TUNNEL (nhanh, KHONG can tai khoan / ten mien) ────────────
#   URL ngau nhien dang https://xxxx.trycloudflare.com (RAT on dinh, nhung URL
#   doi moi lan chay -> KHONG co dinh). Tot de test nhanh.
#     powershell -ExecutionPolicy Bypass -File scripts\tunnel-cloudflared.ps1
#
# ── CHE DO 2: NAMED TUNNEL (URL CO DINH VINH VIEN, can ten mien tren Cloudflare) ─
#   Chuan bi 1 lan:
#     cloudflared tunnel login
#     cloudflared tunnel create qk5
#     cloudflared tunnel route dns qk5 qk5.tenmien-cua-ban.com
#   Roi chay:
#     powershell -ExecutionPolicy Bypass -File scripts\tunnel-cloudflared.ps1 -TunnelName qk5
#   URL co dinh: https://qk5.tenmien-cua-ban.com
#
# Dung: Ctrl+C

param(
    [int]   $Port          = 18088,
    [int]   $RetryDelay    = 5,
    [string]$CloudflaredExe = "cloudflared",
    # De trong = quick tunnel (trycloudflare.com). Dat ten = named tunnel co dinh.
    [string]$TunnelName    = "",
    # Neu may ra internet QUA PROXY: dat proxy (http://user:pass@host:port).
    # Cloudflare ho tro proxy MIEN PHI nhung phai ep --protocol http2 (mac dinh
    # dung QUIC/UDP khong qua duoc HTTP proxy). Script tu them http2 khi co proxy.
    [string]$Proxy         = $env:APP_TUNNEL_PROXY,
    # Ep giao thuc: "http2" (TCP 443) khi mang CHAN QUIC/UDP 7844. De trong =
    # mac dinh cua cloudflared (quic). Neu QUIC bi chan -> dung -Protocol http2.
    [string]$Protocol      = $env:APP_TUNNEL_PROTOCOL
)

$ErrorActionPreference = "Stop"

# Cloudflare doc HTTPS_PROXY/HTTP_PROXY (kem --protocol http2) de noi qua proxy.
# Qua proxy thi bat buoc http2. Neu QUIC bi chan, dat -Protocol http2 (khong proxy).
if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
    $env:HTTPS_PROXY = $Proxy
    $env:HTTP_PROXY  = $Proxy
    $env:https_proxy = $Proxy
    $env:http_proxy  = $Proxy
    if ([string]::IsNullOrWhiteSpace($Protocol)) { $Protocol = "http2" }
    Write-Host "Dung proxy: $Proxy" -ForegroundColor DarkGray
}
if (-not [string]::IsNullOrWhiteSpace($Protocol)) {
    Write-Host "Giao thuc: $Protocol" -ForegroundColor DarkGray
}

# Tim cloudflared
$cf = (Get-Command $CloudflaredExe -ErrorAction SilentlyContinue)
if (-not $cf) {
    if (Test-Path (Join-Path $PSScriptRoot "..\cloudflared.exe")) {
        $CloudflaredExe = Join-Path $PSScriptRoot "..\cloudflared.exe"
    } else {
        Write-Host "Khong tim thay cloudflared. Tai tai:" -ForegroundColor Red
        Write-Host "  https://github.com/cloudflare/cloudflared/releases" -ForegroundColor Yellow
        exit 1
    }
}

$Attempt = 0
Write-Host "=== Cloudflare Tunnel ===" -ForegroundColor Cyan
if ([string]::IsNullOrWhiteSpace($TunnelName)) {
    Write-Host "Che do: QUICK TUNNEL (URL trycloudflare.com se hien ben duoi)" -ForegroundColor Cyan
} else {
    Write-Host "Che do: NAMED TUNNEL '$TunnelName' (URL co dinh theo ten mien da route)" -ForegroundColor Green
}
Write-Host "Local 127.0.0.1:$Port  (Ctrl+C de dung)" -ForegroundColor DarkGray

while ($true) {
    $Attempt++
    Write-Host ""
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Ket noi #$Attempt ..." -ForegroundColor Yellow

    # Co dinh giao thuc + tang do ben khi mang/proxy hay cat ket noi dai.
    $common = @("--no-autoupdate", "--retries", "10", "--grace-period", "30s")
    if (-not [string]::IsNullOrWhiteSpace($Protocol)) {
        $common = @("--protocol", $Protocol) + $common
    }

    if ([string]::IsNullOrWhiteSpace($TunnelName)) {
        # Quick tunnel: co cac flag tren `tunnel ... --url`
        & $CloudflaredExe tunnel @common --url "http://127.0.0.1:$Port"
    } else {
        # Named tunnel: cac flag phai dat SAU `run`
        & $CloudflaredExe tunnel run @common --url "http://127.0.0.1:$Port" $TunnelName
    }

    $Exit = $LASTEXITCODE
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Tunnel ngat (exit=$Exit). Ket noi lai sau ${RetryDelay}s..." -ForegroundColor Red
    Start-Sleep -Seconds $RetryDelay
}
