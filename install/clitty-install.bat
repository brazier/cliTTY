@echo off
setlocal EnableDelayedExpansion

set "INSTALL_DIR=%LOCALAPPDATA%\clitty"
set "VENV_DIR=%INSTALL_DIR%\.venv"
set "SCRIPT_DIR=%~dp0"
set "SOURCE_DIR=%SCRIPT_DIR%.."
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM Remove trailing backslash from SOURCE_DIR
if "%SOURCE_DIR:~-1%"=="\" set "SOURCE_DIR=%SOURCE_DIR:~0,-1%"

if not exist "%SOURCE_DIR%\main.py" (
    echo Error: clitty source not found at %SOURCE_DIR%
    exit /b 1
)

REM Check for Python
where python >nul 2>&1
if errorlevel 1 (
    where py >nul 2>&1
    if errorlevel 1 (
        echo Error: Python not found. Install Python 3 from https://python.org
        exit /b 1
    )
    set "PYTHON=py -3"
) else (
    set "PYTHON=python"
)

REM Check for venv module
%PYTHON% -c "import venv" 2>nul
if errorlevel 1 (
    echo Error: Python venv module not found. Reinstall Python with venv support.
    exit /b 1
)

if exist "%INSTALL_DIR%" (
    echo WARNING: %INSTALL_DIR% exists and will be replaced.
    set /p "confirm=Continue? [y/N] "
    if /i not "!confirm!"=="y" if /i not "!confirm!"=="yes" exit /b 1
)

echo ==> Copying to %INSTALL_DIR%
if exist "%INSTALL_DIR%" rmdir /s /q "%INSTALL_DIR%"
mkdir "%INSTALL_DIR%"

copy "%SOURCE_DIR%\main.py" "%INSTALL_DIR%\" /Y >nul
copy "%SOURCE_DIR%\requirements.txt" "%INSTALL_DIR%\" /Y >nul
xcopy "%SOURCE_DIR%\src" "%INSTALL_DIR%\src\" /E /I /Y >nul

REM Copy clitty-run.bat to install dir
copy "%~dp0clitty-run.bat" "%INSTALL_DIR%\" /Y >nul

echo ==> Creating venv
%PYTHON% -m venv "%VENV_DIR%"
call "%VENV_DIR%\Scripts\activate.bat"

echo ==> Installing dependencies
pip install -q --upgrade pip
pip install -q -r "%INSTALL_DIR%\requirements.txt"

echo.
echo Done. Run "%INSTALL_DIR%\clitty-run.bat" to start.
echo Add "%INSTALL_DIR%" to PATH or create a shortcut for easy access.
exit /b 0
