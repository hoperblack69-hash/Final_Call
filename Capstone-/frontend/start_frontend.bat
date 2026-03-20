@echo off
REM Frontend Development Server Launcher (Windows)
REM Usage: start_frontend.bat [port] [no-open]

if "%1"=="" (
    set PORT=3000
) else (
    set PORT=%1
)

if "%2"=="no-open" (
    set AUTO_OPEN=no-open
) else (
    set AUTO_OPEN=
)

echo ================================================
echo 🚀 Starting Frontend Development Server
echo ================================================
echo Port: %PORT%
echo Auto-open: %AUTO_OPEN%
echo ================================================

python start_frontend.py %PORT% %AUTO_OPEN%

pause