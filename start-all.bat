@echo off
REM ============================================================
REM  Bam 1 cai chay ca Server + Cloudflare Tunnel (link co dinh)
REM  Dat file nay o thu muc goc project (canh cloudflared.exe).
REM  Sua TUNNEL / LINK ben duoi neu ban dung ten khac.
REM ============================================================
setlocal
set TUNNEL=qk5
set LINK=https://qk5.blacknull.net

cd /d "%~dp0"

echo Khoi dong server tai 127.0.0.1:18088 ...
start "QK5 Server" cmd /k "set APP_BIND_ADDR=127.0.0.1:18088&& set APP_REQUIRE_HTTPS=0&& set AWS_LC_SYS_NO_ASM=1&& target\debug\website_buu.exe"

echo Cho server san sang (6s) ...
timeout /t 6 >nul

echo Khoi dong Cloudflare Tunnel (http2) ...
start "QK5 Tunnel" cmd /k "cloudflared.exe tunnel run --protocol http2 --url http://127.0.0.1:18088 %TUNNEL%"

echo.
echo === Da khoi dong xong ===
echo Link cong khai: %LINK%
echo (Giu 2 cua so vua mo. Dong chung de tat server + tunnel.)
echo.
pause
