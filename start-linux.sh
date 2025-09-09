#!/bin/bash

# ShortURL Linux Startup Script
# This script will start the ShortURL application using PM2

echo "========================================"
echo "Starting ShortURL Application with PM2"
echo "========================================"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js is not installed"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

# Check if PM2 is installed globally
if ! command -v pm2 &> /dev/null; then
    echo "PM2 not found globally. Installing PM2..."
    sudo npm install -g pm2
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install PM2"
        exit 1
    fi
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found!"
    echo "Please run setup first: npm run setup-with-password"
    exit 1
fi

# Create logs directory if it doesn't exist
if [ ! -d "logs" ]; then
    echo "Creating logs directory..."
    mkdir -p logs
fi

# Start the application
echo "Starting ShortURL application..."
pm2 start ecosystem.config.json --env production

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to start application"
    exit 1
fi

echo ""
echo "========================================"
echo "ShortURL started successfully!"
echo "========================================"
echo ""
echo "Available commands:"
echo "- View logs: pm2 logs shorturl"
echo "- Monitor: pm2 monit" 
echo "- Stop: pm2 stop shorturl"
echo "- Restart: pm2 restart shorturl"
echo ""
echo "Access your application at: http://localhost:[PORT_FROM_ENV]" 
echo "Check .env file for the actual port number (default: 3000)"
echo ""

# Ask if user wants to view logs
read -p "View logs now? (y/n): " choice
case "$choice" in 
    y|Y ) pm2 logs shorturl;;
    * ) echo "Use 'pm2 logs shorturl' to view logs later";;
esac
