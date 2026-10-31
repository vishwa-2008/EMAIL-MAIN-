@echo off
setlocal
cd /d "%~dp0"
title Java Mini Project - Team 10 Launcher

echo ========================================================
echo    JAVA MINI PROJECT - EMAIL OTP AUTHENTICATION
echo    TEAM 10 - #CHINNI KRISHNA
echo ========================================================
echo.

set "JAVA_BIN=C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot\bin\java.exe"
if not exist "%JAVA_BIN%" (
    set "JAVA_BIN=java.exe"
)

echo [1/2] Starting Java Backend Server on port 8080...
start "Java OTP Server" "%JAVA_BIN%" -jar "%~dp0target\java-email-authentication-1.0.0.jar"
timeout /t 2 /nobreak >nul

echo [2/2] Starting Live Cloudflare Public Tunnel...
echo.
echo ========================================================
echo Look for your live https://*.trycloudflare.com link below:
echo ========================================================
echo.
if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" (
    "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8080
) else (
    cloudflared tunnel --url http://localhost:8080
)

pause
