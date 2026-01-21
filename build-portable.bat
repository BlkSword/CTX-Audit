@echo off
setlocal enabledelayedexpansion

REM ========================================
REM   CTX-Audit Portable Build Script
REM ========================================

echo.
echo ========================================
echo   CTX-Audit Portable Build Script
echo ========================================
echo.

REM Get version from package.json
set VERSION=2.0.0
echo Version: %VERSION%
echo.

REM Build frontend
echo [1/3] Building frontend...
call npm run build
if errorlevel 1 (
    echo ERROR: Frontend build failed
    pause
    exit /b 1
)

REM Build Tauri app
echo.
echo [2/3] Building Tauri app...
call npm run tauri:build
if errorlevel 1 (
    echo ERROR: Tauri build failed
    pause
    exit /b 1
)

REM Create portable package
echo.
echo [3/3] Creating portable package...

REM Clean old version
if exist "portable" rmdir /s /q "portable"

REM Create directory structure
mkdir portable
mkdir portable\data

REM Copy main executable
copy "src-tauri\target\release\ctx-audit-desktop.exe" "portable\CTX-Audit.exe" >nul
if not exist "portable\CTX-Audit.exe" (
    echo ERROR: Cannot find compiled exe file
    pause
    exit /b 1
)

REM Create readme
echo CTX-Audit v%VERSION% > portable\README.txt
echo. >> portable\README.txt
echo Usage: >> portable\README.txt
echo 1. Double click CTX-Audit.exe to launch >> portable\README.txt
echo 2. All data is saved in the data folder >> portable\README.txt
echo 3. Delete the whole folder to uninstall >> portable\README.txt
echo. >> portable\README.txt
echo Version: %VERSION% >> portable\README.txt
echo Build Date: %date% %time% >> portable\README.txt

REM Build complete
echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo Portable location: portable\
echo Main exe: portable\CTX-Audit.exe
echo.
for %%A in ("portable\CTX-Audit.exe") do echo File size: %%~zA bytes
echo.
echo You can run portable\CTX-Audit.exe to test
echo.
pause
