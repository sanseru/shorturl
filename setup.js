#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 Setting up ShortURL application...\n');

// Check if .env exists
const envPath = path.join(__dirname, '.env');
const envExamplePath = path.join(__dirname, 'env.example');

if (!fs.existsSync(envPath)) {
  if (fs.existsSync(envExamplePath)) {
    console.log('📄 Creating .env file from template...');
    fs.copyFileSync(envExamplePath, envPath);
    console.log('✅ .env file created. Please edit it with your configuration.\n');
  } else {
    console.log('⚠️  No .env template found. Creating basic .env file...');
    const basicEnv = `# ShortURL Configuration
PORT=3000
NODE_ENV=development
SESSION_SECRET=change-this-to-a-random-string-in-production
ADMIN_USERNAME=admin
# Run: node generate-password.js to create ADMIN_PASSWORD_HASH
`;
    fs.writeFileSync(envPath, basicEnv);
    console.log('✅ Basic .env file created.\n');
  }
} else {
  console.log('✅ .env file already exists.\n');
}

// Check if data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  console.log('📁 Creating data directory...');
  fs.mkdirSync(dataDir);
  console.log('✅ Data directory created.\n');
}

// Check if logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  console.log('📁 Creating logs directory...');
  fs.mkdirSync(logsDir);
  console.log('✅ Logs directory created.\n');
}

// Generate admin password if requested
const args = process.argv.slice(2);
if (args.includes('--generate-password') || args.includes('-p')) {
  console.log('🔐 Generating admin password...');
  try {
    execSync('node generate-password.js', { stdio: 'inherit' });
  } catch (err) {
    console.error('❌ Failed to generate password:', err.message);
  }
}

console.log('📋 Next steps:');
console.log('1. Edit .env file with your configuration (including PORT if needed)');
console.log('2. Run: node generate-password.js (to generate admin password hash)');
console.log('3. Choose how to start the application:');
console.log('   • Development: npm start');
console.log('   • Production with PM2: npm run pm2:prod');
console.log('   • Windows: start-windows.bat');
console.log('   • Linux: ./start-linux.sh');
console.log('4. Check configuration: npm run config');
console.log('5. Visit: http://localhost:[YOUR_PORT_FROM_ENV] (default: 3000)');
console.log('\n🚀 PM2 Production Commands:');
console.log('- Start: npm run pm2:prod');
console.log('- Stop: npm run pm2:stop');
console.log('- Restart: npm run pm2:restart');
console.log('- Logs: npm run pm2:logs');
console.log('- Monitor: npm run pm2:monit');
console.log('\n🔒 Security recommendations:');
console.log('- Use strong SESSION_SECRET in production');
console.log('- Use HTTPS in production');
console.log('- Regularly backup your data/shorturl.db file');
console.log('- Monitor logs for security events');
console.log('- Setup PM2 startup script for auto-restart');
console.log('\n✨ Setup complete!');
