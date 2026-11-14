@echo off
rem CYBERARENA: one-command setup. Double-click, or run from a console: start.bat [-ResetData]
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1" %*
set "CODE=%ERRORLEVEL%"
echo.
pause
exit /b %CODE%
