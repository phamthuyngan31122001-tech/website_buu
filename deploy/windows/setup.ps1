# ============================================================================
#  setup.ps1 - Cai website_buu + Caddy thanh Windows Service (chay nen, on dinh)
#  Chay 1 LAN (quyen Administrator). Sau do dung update.ps1 de cap nhat.
#
#  Yeu cau truoc:
#    - Da build duoc website_buu.exe (cargo build --release) -> target\release\
#      (hoac dat s''an .exe vao thu muc, xem -ExePath)
#    - DNS htqlqc.com + www -> IP VPS
#    - Mo quyen Administrator: chuot phai PowerShell -> Run as Administrator
#
#  Chay:
#    powershell -ExecutionPolicy Bypass -File deploy\windows\setup.ps1 `
#       -Domain htqlqc.com -BootstrapUser Admin@1999 -BootstrapPass "MAT_KHAU_MANH"
# ============================================================================
param(
    [string]$Domain        = "htqlqc.com",
    [int]   $Port          = 18088,
    [string]$InstallDir    = "C:\website_buu",
    [string]$ExePath       = "",                 # de trong = tu tim target\release\website_buu.exe
    [string]$BootstrapUser = "Admin@1999",
    [string]$BootstrapPass = "Admin@1999",
    [string]$Email         = "admin@htqlqc.com"
)
$ErrorActionPreference = "Stop"

function Need-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "Hay chay PowerShell voi quyen Administrator." -ForegroundColor Red; exit 1
    }
}
Need-Admin

$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent   # ..\..\ tu deploy\windows
$ToolsDir = Join-Path $InstallDir "tools"
New-Item -ItemType Directory -Force -Path $InstallDir, $ToolsDir, (Join-Path $InstallDir "runtime") | Out-Null

# --- 1. Xac dinh exe da build ---
if ([string]::IsNullOrWhiteSpace($ExePath)) {
    $ExePath = Join-Path $RepoRoot "target\release\website_buu.exe"
}
if (-not (Test-Path $ExePath)) {
    Write-Host "Khong thay $ExePath" -ForegroundColor Red
    Write-Host "Hay build truoc: cargo build --release  (trong thu muc project)" -ForegroundColor Yellow
    exit 1
}
Copy-Item $ExePath (Join-Path $InstallDir "website_buu.exe") -Force
Write-Host "Da copy exe vao $InstallDir" -ForegroundColor Green

# --- 2. Tai NSSM (quan ly service) neu chua co ---
$Nssm = Join-Path $ToolsDir "nssm.exe"
if (-not (Test-Path $Nssm)) {
    Write-Host "Tai NSSM ..." -ForegroundColor Cyan
    $zip = Join-Path $ToolsDir "nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $ToolsDir -Force
    Copy-Item (Join-Path $ToolsDir "nssm-2.24\win64\nssm.exe") $Nssm -Force
}

# --- 3. Tai Caddy neu chua co ---
$Caddy = Join-Path $ToolsDir "caddy.exe"
if (-not (Test-Path $Caddy)) {
    Write-Host "Tai Caddy ..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://caddyserver.com/api/download?os=windows&arch=amd64" -OutFile $Caddy
}

# --- 4. Tao Caddyfile ---
$CaddyfilePath = Join-Path $InstallDir "Caddyfile"
@"
{
	email $Email
}
$Domain, www.$Domain {
	encode gzip
	reverse_proxy 127.0.0.1:$Port {
		header_up X-Forwarded-Proto https
	}
	request_body {
		max_size 50MB
	}
}
"@ | Set-Content -Encoding ascii $CaddyfilePath
Write-Host "Da tao $CaddyfilePath" -ForegroundColor Green

# --- 5. Cai service app (website_buu) ---
& $Nssm stop website_buu 2>$null
& $Nssm remove website_buu confirm 2>$null
& $Nssm install website_buu (Join-Path $InstallDir "website_buu.exe")
& $Nssm set website_buu AppDirectory $InstallDir
& $Nssm set website_buu AppEnvironmentExtra `
    "APP_BIND_ADDR=127.0.0.1:$Port" `
    "APP_NETWORK_MODE=internet-test" `
    "APP_REQUIRE_HTTPS=1" `
    "APP_RUNTIME_DIR=$InstallDir\runtime" `
    "AWS_LC_SYS_NO_ASM=1" `
    "APP_BOOTSTRAP_USERNAME=$BootstrapUser" `
    "APP_BOOTSTRAP_PASSWORD=$BootstrapPass"
& $Nssm set website_buu Start SERVICE_AUTO_START
& $Nssm set website_buu AppStdout (Join-Path $InstallDir "runtime\service-out.log")
& $Nssm set website_buu AppStderr (Join-Path $InstallDir "runtime\service-err.log")

# --- 6. Cai service Caddy ---
& $Nssm stop caddy 2>$null
& $Nssm remove caddy confirm 2>$null
& $Nssm install caddy $Caddy "run --config `"$CaddyfilePath`" --adapter caddyfile"
& $Nssm set caddy AppDirectory $InstallDir
& $Nssm set caddy Start SERVICE_AUTO_START

# --- 7. Mo firewall 80/443 ---
New-NetFirewallRule -DisplayName "HTTP 80"  -Direction Inbound -Protocol TCP -LocalPort 80  -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "HTTPS 443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue | Out-Null

# --- 8. Khoi dong ---
& $Nssm start website_buu
Start-Sleep -Seconds 4
& $Nssm start caddy

Write-Host ""
Write-Host "=== XONG ===" -ForegroundColor Green
Write-Host "App + Caddy da chay nen (tu bat khi reboot, tu restart khi loi)."
Write-Host "Truy cap: https://$Domain"
Write-Host "Log app:  $InstallDir\runtime\service-err.log"
Write-Host "Quan ly:  $Nssm restart website_buu | $Nssm restart caddy"
