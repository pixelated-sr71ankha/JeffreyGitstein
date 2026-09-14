@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0scripts\launch-finlens.ps1"
if errorlevel 1 (
  echo.
  echo FinLens could not start. See finlens-launcher.log in this folder.
  pause
)
