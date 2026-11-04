@echo off
rem Launches the Windows 10 Security Pack GUI. The script asks for administrator rights itself (UAC).
rem Double-click this file - no need to change the PowerShell execution policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10SecurityPack.ps1"
if errorlevel 1 (
  echo.
  echo The tool did not start correctly. Error level: %errorlevel%
  pause
)
