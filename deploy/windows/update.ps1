# ============================================================================
#  update.ps1 - Cap nhat phien ban moi trong 1 lenh:
#               git pull -> build -> copy exe -> restart service
#  Chay (quyen Administrator), tu thu muc project:
#    powershell -ExecutionPolicy Bypass -File deploy\windows\update.ps1
# ============================================================================
param(
    [string]$InstallDir = "C:\website_buu",
    [string]$Branch     = "claude/bug-fixes-cleanup-7gybqt"
)
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Nssm     = Join-Path $InstallDir "tools\nssm.exe"

Set-Location $RepoRoot
Write-Host "1) Lay code moi (branch $Branch) ..." -ForegroundColor Cyan
git fetch origin
git checkout $Branch
git pull origin $Branch

Write-Host "2) Build release ..." -ForegroundColor Cyan
$env:AWS_LC_SYS_NO_ASM = "1"
cargo build --release
if ($LASTEXITCODE -ne 0) { Write-Host "Build that bai." -ForegroundColor Red; exit 1 }

Write-Host "3) Cap nhat exe + restart service ..." -ForegroundColor Cyan
& $Nssm stop website_buu
Copy-Item (Join-Path $RepoRoot "target\release\website_buu.exe") (Join-Path $InstallDir "website_buu.exe") -Force
& $Nssm start website_buu

Write-Host "Xong. Da chay ban moi." -ForegroundColor Green
