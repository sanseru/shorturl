#!/bin/bash
# Script untuk deploy fix Trust Proxy yang aman

echo "=== DEPLOYING SECURE TRUST PROXY FIX ==="

# 1. Stop aplikasi
echo "Stopping PM2 application..."
pm2 stop shorturl

# 2. Pull latest changes
echo "Pulling latest changes from Git..."
git pull origin main

# 3. Install dependencies jika ada perubahan
echo "Installing/updating dependencies..."
npm install

# 4. Backup current nginx config
echo "Backing up current Nginx config..."
sudo cp /etc/nginx/sites-available/shorturl /etc/nginx/sites-available/shorturl.backup.$(date +%Y%m%d_%H%M%S)

# 5. Update nginx config
echo "Updating Nginx configuration..."
sudo cp nginx-secure-proxy.conf /etc/nginx/sites-available/shorturl

# 6. Test nginx config
echo "Testing Nginx configuration..."
sudo nginx -t

if [ $? -eq 0 ]; then
    echo "Nginx config test passed. Reloading Nginx..."
    sudo systemctl reload nginx
else
    echo "Nginx config test failed. Restoring backup..."
    sudo cp /etc/nginx/sites-available/shorturl.backup.* /etc/nginx/sites-available/shorturl
    exit 1
fi

# 7. Start aplikasi dengan environment production
echo "Starting PM2 application in production mode..."
NODE_ENV=production pm2 start ecosystem.config.json

# 8. Show status
echo "Checking application status..."
pm2 status
pm2 logs shorturl --lines 20

echo ""
echo "=== DEPLOYMENT COMPLETE ==="
echo "Trust proxy is now set to secure mode (trust only 1 proxy)"
echo "Rate limiting will use real client IPs from X-Forwarded-For header"
echo "Monitor logs with: pm2 logs shorturl"
echo ""
