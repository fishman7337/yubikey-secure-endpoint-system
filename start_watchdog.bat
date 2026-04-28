@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

if exist "%SCRIPT_DIR%.dist\yubiwatch-latest.exe" (
    "%SCRIPT_DIR%.dist\yubiwatch-latest.exe" --env-file "%SCRIPT_DIR%.env"
    exit /b %ERRORLEVEL%
)

if exist "%SCRIPT_DIR%.dist\yubiwatch.exe" (
    "%SCRIPT_DIR%.dist\yubiwatch.exe" --env-file "%SCRIPT_DIR%.env"
    exit /b %ERRORLEVEL%
)

if exist "%SCRIPT_DIR%target\release\yubiwatch.exe" (
    "%SCRIPT_DIR%target\release\yubiwatch.exe" --env-file "%SCRIPT_DIR%.env"
    exit /b %ERRORLEVEL%
)

if exist "%SCRIPT_DIR%.venv\Scripts\pythonw.exe" (
    "%SCRIPT_DIR%.venv\Scripts\pythonw.exe" "%SCRIPT_DIR%yubikey_watchdog.py"
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 "%SCRIPT_DIR%yubikey_watchdog.py"
    exit /b %ERRORLEVEL%
)

python "%SCRIPT_DIR%yubikey_watchdog.py"
