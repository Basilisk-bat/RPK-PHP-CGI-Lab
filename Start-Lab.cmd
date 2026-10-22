@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0lab\windows\Start-Lab.ps1" %*
set "RPK_LAB_EXIT=%ERRORLEVEL%"
echo.
if not "%RPK_LAB_EXIT%"=="0" echo The lab stopped. Read the message above; no result was accepted.
pause
exit /b %RPK_LAB_EXIT%
