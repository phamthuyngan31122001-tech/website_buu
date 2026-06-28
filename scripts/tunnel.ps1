# Script tu dong ket noi lai SSH tunnel (localhost.run) khi bi ngat.
# Cach chay: powershell -ExecutionPolicy Bypass -File scripts\tunnel.ps1
# Dung: Ctrl+C
#
# ⚠️  CANH BAO: localhost.run ban mien phi cap URL *.lhr.life NGAU NHIEN moi
#     lan ket noi lai -> link DOI lien tuc, KHONG the co dinh "vinh vien".
#     De co LINK CO DINH on dinh, dung: scripts\tunnel-ngrok.ps1 (ngrok static domain).

$LocalPort   = 18088
$RemotePort  = 80
$RetryDelay  = 5
$Attempt     = 0
$ProxyScript = Join-Path $PSScriptRoot "..\proxy_connect.py"

Write-Host "=== SSH Tunnel Auto-Reconnect ===" -ForegroundColor Cyan
Write-Host "Local 127.0.0.1:$LocalPort --> localhost.run:$RemotePort" -ForegroundColor Cyan
Write-Host "(URL public se xuat hien trong banner sau khi ket noi)" -ForegroundColor DarkGray

while ($true) {
    $Attempt++
    Write-Host ""
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Lan ket noi #$Attempt ..." -ForegroundColor Yellow

    # -N : khong mo shell, chi giu tunnel
    # ServerAliveInterval=15 : gui keepalive moi 15s
    # ServerAliveCountMax=3  : ngat sau 3 lan mat keepalive (~45s)
    # ExitOnForwardFailure   : thoat ngay neu port-forward that bai
    $SshArgs = @(
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "TCPKeepAlive=yes",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=20",
        "-R", "${RemotePort}:127.0.0.1:${LocalPort}",
        "phamthuyngan31122001@localhost.run"
    )
    if ($env:TUNNEL_PROXY_HOST) {
        $SshArgs = @("-o", "ProxyCommand=python `"$ProxyScript`" %h %p") + $SshArgs
    }

    ssh @SshArgs

    $Exit = $LASTEXITCODE
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Tunnel ngat (exit=$Exit). Ket noi lai sau ${RetryDelay}s..." -ForegroundColor Red
    Start-Sleep -Seconds $RetryDelay
}
