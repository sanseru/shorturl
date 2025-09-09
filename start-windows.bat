@echo off
REM ShortURL Windows Startup Script
REM This script will start the ShortURL application using PM2

echo ========================================
echo Starting ShortURL Application with PM2
echo ========================================

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check if PM2 is installed globally
pm2 --version >nul 2>&1
if errorlevel 1 (
    echo PM2 not found globally. Installing PM2...
    npm install -g pm2
    if errorlevel 1 (
        echo ERROR: Failed to install PM2
        pause
        exit /b 1
    )
)

REM Check if .env file exists
if not exist ".env" (
    echo ERROR: .env file not found!
    echo Please run setup first: npm run setup-with-password
    pause
    exit /b 1
)

REM Create logs directory if it doesn't exist
if not exist "logs" (
    echo Creating logs directory...
    mkdir logs
)

REM Check if ShortURL is already running
pm2 list | findstr "shorturl" >nul 2>&1
if not errorlevel 1 (
    echo ShortURL is already running!
    echo Current status:
    pm2 list | findstr shorturl
    echo.
    set /p restart_choice="Do you want to restart it? (y/n): "
    if /i "%restart_choice%"=="y" (
        echo Restarting ShortURL application...
        pm2 restart shorturl
    ) else (
        echo Keeping existing instance running.
        pm2 logs shorturl --lines 10
        pause
        exit /b 0
    )
) else (
    REM Start the application
    echo Starting ShortURL application...
    pm2 start ecosystem.config.json --env production
    
    if errorlevel 1 (
        echo ERROR: Failed to start application
        pause
        exit /b 1
    )
)

echo.
echo ========================================
echo ShortURL started successfully!
echo ========================================
echo.
echo Available commands:
echo - View logs: pm2 logs shorturl
echo - Monitor: pm2 monit
echo - Stop: pm2 stop shorturl
echo - Restart: pm2 restart shorturl
echo.
echo Access your application at: http://localhost:[PORT_FROM_ENV]
echo Check .env file for the actual port number (default: 3000)
echo.

REM Open PM2 monitoring
set /p choice="Open PM2 monitoring? (y/n): "
if /i "%choice%"=="y" (
    pm2 monit
)

pause
