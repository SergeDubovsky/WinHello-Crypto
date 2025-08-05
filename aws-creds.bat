@echo off
REM AWS Hello Credentials Manager - Windows Batch Wrapper
REM Enhanced version with better error handling and validation

setlocal enabledelayedexpansion

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
set "PYTHON_SCRIPT=%SCRIPT_DIR%aws_hello_creds.py"

REM Check if Python script exists
if not exist "%PYTHON_SCRIPT%" (
    echo.
    echo ❌ Error: aws_hello_creds.py not found in %SCRIPT_DIR%
    echo Please ensure the Python script is in the same directory as this batch file.
    echo.
    pause
    exit /b 1
)

REM Check if Python is available and get version
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ❌ Error: Python is not installed or not in PATH
    echo Please install Python 3.7+ and ensure it's in your PATH
    echo Download from: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM Check Python version (basic check for 3.x)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
if not "!PYTHON_VERSION:~0,1!"=="3" (
    echo.
    echo ❌ Error: Python 3.7+ is required, found version !PYTHON_VERSION!
    echo Please upgrade Python: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM Check for required Python packages
python -c "import winrt, cryptography" >nul 2>&1
if errorlevel 1 (
    echo.
    echo ❌ Error: Required Python packages not found
    echo Please install required dependencies:
    echo   pip install cryptography winrt
    echo.
    pause
    exit /b 1
)

REM If no arguments provided, show enhanced help
if "%~1"=="" (
    echo.
    echo 🔐 AWS Hello Credentials Manager
    echo ================================
    echo Version: Enhanced v2.0
    echo Python: !PYTHON_VERSION!
    echo.
    echo Usage: %~nx0 [command] [options]
    echo.
    echo Commands:
    echo   add-profile [name] --access-key [key] --secret-key [secret] [options]
    echo   list-profiles
    echo   get-credentials --profile [name]
    echo   remove-profile [name]
    echo.
    echo Options for add-profile:
    echo   --region [region]        Set default AWS region
    echo   --session-token [token]  For temporary credentials
    echo.
    echo Examples:
    echo   %~nx0 add-profile my-aws --access-key AKIA... --secret-key xyz... --region us-east-1
    echo   %~nx0 add-profile temp --access-key AKIA... --secret-key xyz... --session-token IQo...
    echo   %~nx0 list-profiles
    echo   %~nx0 get-credentials --profile my-aws
    echo   %~nx0 remove-profile old-profile
    echo.
    echo Note: Each operation requires Windows Hello biometric authentication
    echo.
    pause
    exit /b 0
)

REM Pass all arguments to the Python script
python "%PYTHON_SCRIPT%" %*

REM Pause on error to see the message
if errorlevel 1 (
    echo.
    echo Command failed with error code %errorlevel%
    pause
)
