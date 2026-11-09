@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "HERE=%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found in PATH.
    echo Install Python 3, then run: python -m pip install keystone-engine
    echo.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo No files dropped: processing EXE files in "%HERE%" ...
    python "%~dp0patch_mytestx.py" "%HERE:~0,-1%"
) else (
    python "%~dp0patch_mytestx.py" %*
)
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" (
    echo Finished with errors, exit code %RC%.
) else (
    echo Finished successfully.
)
echo Press any key to close...
pause >nul
exit /b %RC%
