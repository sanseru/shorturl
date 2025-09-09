#!/usr/bin/env node

// Utility script to show current configuration
require('dotenv').config();

const fs = require('fs');
const path = require('path');

console.log('🔍 ShortURL Current Configuration');
console.log('================================');

// Check if .env exists
const envPath = path.join(__dirname, '.env');
if (!fs.existsSync(envPath)) {
  console.log('❌ .env file not found!');
  console.log('   Run: npm run setup-with-password');
  process.exit(1);
}

// Display configuration
const port = process.env.PORT || 3000;
const nodeEnv = process.env.NODE_ENV || 'development';
const adminUsername = process.env.ADMIN_USERNAME || 'admin';
const hasPasswordHash = !!process.env.ADMIN_PASSWORD_HASH;
const hasSessionSecret = !!process.env.SESSION_SECRET;

console.log(`📡 Port: ${port}`);
console.log(`🏷️  Environment: ${nodeEnv}`);
console.log(`👤 Admin Username: ${adminUsername}`);
console.log(`🔐 Password Hash: ${hasPasswordHash ? '✅ Set' : '❌ Not set'}`);
console.log(`🔑 Session Secret: ${hasSessionSecret ? '✅ Set' : '❌ Not set'}`);
console.log('');

// Check if app is running
const { exec } = require('child_process');

exec('pm2 jlist', (error, stdout, stderr) => {
  if (!error) {
    try {
      const processes = JSON.parse(stdout);
      const shortUrlProcess = processes.find(p => p.name === 'shorturl');
      
      if (shortUrlProcess) {
        console.log('🚀 Application Status: RUNNING');
        console.log(`   PID: ${shortUrlProcess.pid}`);
        console.log(`   Status: ${shortUrlProcess.pm2_env.status}`);
        console.log(`   Uptime: ${Math.floor(shortUrlProcess.pm2_env.pm_uptime / 1000)}s`);
        console.log(`   Memory: ${Math.floor(shortUrlProcess.memory / 1024 / 1024)}MB`);
      } else {
        console.log('⏹️  Application Status: STOPPED');
      }
    } catch (e) {
      console.log('❓ Application Status: UNKNOWN (PM2 not available)');
    }
  } else {
    console.log('❓ Application Status: UNKNOWN (PM2 not available)');
  }
  
  console.log('');
  console.log(`🌐 Access URL: http://localhost:${port}`);
  console.log(`🔧 Admin URL: http://localhost:${port}/admin`);
  console.log(`💊 Health Check: http://localhost:${port}/health`);
  console.log('');
  
  // Warnings
  if (!hasPasswordHash) {
    console.log('⚠️  WARNING: Admin password not set! Run: npm run generate-password');
  }
  if (!hasSessionSecret || process.env.SESSION_SECRET === 'your-super-secret-session-key-change-this') {
    console.log('⚠️  WARNING: Weak session secret! Change SESSION_SECRET in .env');
  }
  if (nodeEnv === 'production' && port == 3000) {
    console.log('💡 INFO: Running on default port 3000 in production');
  }
});

console.log('📋 Available Commands:');
console.log('  npm start           - Start in development mode');
console.log('  npm run pm2:prod    - Start with PM2 (production)'); 
console.log('  npm run pm2:logs    - View PM2 logs');
console.log('  npm run pm2:monit   - PM2 monitoring');
console.log('  npm run pm2:stop    - Stop PM2 process');
console.log('');
