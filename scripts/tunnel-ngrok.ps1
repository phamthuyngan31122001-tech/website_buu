# Mo website ra internet bang ngrok voi URL CO DINH (static domain) + tu ket noi lai.
#
# Vi sao ngrok static domain: tai khoan ngrok mien phi duoc cap 1 domain tinh
# (vd: quan-khu-5.ngrok-free.app) KHONG doi sau moi lan chay -> link "vinh vien".
# Khac voi localhost.run mien phi (URL ngau nhien, doi moi lan reconnect).
#
# ── CHUAN BI MOT LAN DUY NHAT ────────────────────────────────────────────────
# 1. Tao tai khoan mien phi: https://dashboard.ngrok.com/signup
# 2. Tai ngrok: https://ngrok.com/download  (giai nen ngrok.exe vao PATH,
#    hoac de canh project roi sua $NgrokExe ben duoi)
# 3. Lay authtoken: https://dashboard.ngrok.com/get-started/your-authtoken
#       ngrok config add-authtoken <TOKEN_CUA_BAN>
# 4. Tao 1 static domain mien phi:
#       https://dashboard.ngrok.com/cloud-edge/domains  -> "Create Domain"
#    Copy domain duoc cap (vd: quan-khu-5.ngrok-free.app)
#
# ── CACH CHAY ────────────────────────────────────────────────────────────────
#   powershell -ExecutionPolicy Bypass -File scripts\tunnel-ngrok.ps1 -Domain quan-khu-5.ngrok-free.app
# Hoac dat bien moi truong roi chay khong can tham so:
#   $env:APP_NGROK_DOMAIN = "quan-khu-5.ngrok-free.app"
#   powershell -ExecutionPolicy Bypass -File scripts\tunnel-ngrok.ps1
# Dung: Ctrl+C
#
# LUU Y: server phai dang chay tai 127.0.0.1:18088 trong terminal khac
# (xem RUN.txt). URL cong khai cua ban se la: https://<Domain>

param(
    [string]$Domain     = $env:APP_NGROK_DOMAIN,
    [int]   $Port       = 18088,
    [int]   $RetryDelay = 5,
    [string]$NgrokExe   = "ngrok",
    # Region giup tranh duong mang bi ISP chan (loi ERR_NGROK_3200 / connection
    # forcibly closed). Thu: jp (Nhat), ap (Singapore), in (An Do), us, eu, au.
    [string]$Region     = $env:APP_NGROK_REGION,
    # Neu may ban ra internet QUA PROXY, dat proxy o day de ngrok noi qua proxy
    # (vd: http://user:pass@host:port). KHONG luu mat khau vao repo -> truyen luc chay.
    [string]$Proxy      = $env:APP_TUNNEL_PROXY
)

# ngrok doc HTTPS_PROXY/HTTP_PROXY de noi toi may chu cua no. Neu mang chan ket
# noi truc tiep (chi cho di qua proxy), bat buoc phai set proxy nay.
if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
    $env:HTTPS_PROXY = $Proxy
    $env:HTTP_PROXY  = $Proxy
    Write-Host "Dung proxy: $Proxy" -ForegroundColor DarkGray
}

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Domain)) {
    Write-Host "THIEU static domain." -ForegroundColor Red
    Write-Host "Tao domain tinh mien phi tai https://dashboard.ngrok.com/cloud-edge/domains" -ForegroundColor Yellow
    Write-Host "Roi chay: scripts\tunnel-ngrok.ps1 -Domain <domain-cua-ban>" -ForegroundColor Yellow
    exit 1
}

# Kiem tra ngrok co san khong
$ngrokPath = (Get-Command $NgrokExe -ErrorAction SilentlyContinue)
if (-not $ngrokPath) {
    if (Test-Path (Join-Path $PSScriptRoot "..\ngrok.exe")) {
        $NgrokExe = Join-Path $PSScriptRoot "..\ngrok.exe"
    } else {
        Write-Host "Khong tim thay ngrok. Tai tai https://ngrok.com/download" -ForegroundColor Red
        Write-Host "roi them ngrok.exe vao PATH (hoac de canh thu muc project)." -ForegroundColor Yellow
        exit 1
    }
}

$Attempt = 0
Write-Host "=== ngrok Tunnel (URL co dinh) ===" -ForegroundColor Cyan
Write-Host "Local 127.0.0.1:$Port  -->  https://$Domain" -ForegroundColor Cyan
Write-Host "URL cong khai CO DINH: https://$Domain" -ForegroundColor Green
Write-Host "(Ctrl+C de dung)" -ForegroundColor DarkGray

while ($true) {
    $Attempt++
    Write-Host ""
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Ket noi #$Attempt -> https://$Domain" -ForegroundColor Yellow

    # --domain : ep dung static domain co dinh (khong doi giua cac lan chay)
    # --region : chon vung edge (neu dat) de tranh duong mang bi ISP chan/RST.
    $ngrokArgs = @("http", "--domain=$Domain")
    if (-not [string]::IsNullOrWhiteSpace($Region)) {
        $ngrokArgs += "--region=$Region"
        Write-Host "    (region = $Region)" -ForegroundColor DarkGray
    }
    $ngrokArgs += @("$Port", "--log=stdout")
    & $NgrokExe @ngrokArgs

    $Exit = $LASTEXITCODE
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Tunnel ngat (exit=$Exit). Ket noi lai sau ${RetryDelay}s..." -ForegroundColor Red
    Start-Sleep -Seconds $RetryDelay
}
