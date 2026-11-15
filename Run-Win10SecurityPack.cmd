@echo off
rem Launches the Windows 10 Security Pack GUI. The script asks for administrator rights itself (UAC).
rem Double-click this file - no need to change the PowerShell execution policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10SecurityPack.ps1"
rem 1223 = the UAC prompt was declined; the tool has already said so and waited for a key press.
if %errorlevel% EQU 1223 exit /b 1223
if errorlevel 1 (
  echo.
  echo The tool did not start correctly. Error level: %errorlevel%
  pause
)
