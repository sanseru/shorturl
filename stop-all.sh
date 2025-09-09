#!/bin/bash

# Stop and cleanup all ShortURL PM2 instances

echo "🛑 Stopping all ShortURL PM2 instances..."
echo "========================================"

# List current PM2 processes
echo "Current PM2 processes:"
pm2 list

echo ""

# Stop all shorturl instances
pm2 delete shorturl 2>/dev/null || echo "No shorturl process found to delete"

# Also try to delete any process running server.js
pm2 list | grep server.js | awk '{print $4}' | xargs -I {} pm2 delete {} 2>/dev/null || true

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "Current PM2 status:"
pm2 list

echo ""
echo "To start fresh, run: ./start-linux.sh or npm run startup:linux"
