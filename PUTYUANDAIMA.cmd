@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dpn0.ps1" %*
echo.
pause
