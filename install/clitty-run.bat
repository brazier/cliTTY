@echo off
setlocal

set "INSTALL_DIR=%LOCALAPPDATA%\clitty"
set "VENV_DIR=%INSTALL_DIR%\.venv"

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Error: clitty is not installed. Run clitty-install.bat first.
    exit /b 1
)

call "%VENV_DIR%\Scripts\activate.bat"
python "%INSTALL_DIR%\main.py" %*
exit /b %ERRORLEVEL%
