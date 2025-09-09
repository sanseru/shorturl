@echo off
REM Stop and cleanup all ShortURL PM2 instances

echo 🛑 Stopping all ShortURL PM2 instances...
echo ========================================

REM List current PM2 processes
echo Current PM2 processes:
pm2 list

echo.

REM Stop all shorturl instances
pm2 delete shorturl 2>nul || echo No shorturl process found to delete

echo.
echo ✅ Cleanup complete!
echo.
echo Current PM2 status:
pm2 list

echo.
echo To start fresh, run: start-windows.bat or npm run startup:windows
pause
