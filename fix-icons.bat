@echo off
REM Fix stale UDM icons on the desktop and on the installer file.
REM Windows keeps old icons in its icon cache even after the program is updated.
REM Double-click this file, wait for the taskbar to come back, then look at the desktop icons.
taskkill /f /im explorer.exe >nul 2>&1
timeout /t 1 /nobreak >nul
del /a /q "%localappdata%\IconCache.db" >nul 2>&1
del /a /q "%localappdata%\Microsoft\Windows\Explorer\iconcache*" >nul 2>&1
start explorer.exe
echo.
echo Done - the icons should be fresh now.
pause
