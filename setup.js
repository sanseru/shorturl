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
console.log('1. Edit .env file with your configuration');
console.log('2. Run: node generate-password.js (to generate admin password hash)');
console.log('3. Run: npm start (to start the application)');
console.log('4. Visit: http://localhost:3000');
console.log('\n🔒 Security recommendations:');
console.log('- Use strong SESSION_SECRET in production');
console.log('- Use HTTPS in production');
console.log('- Regularly backup your data/shorturl.db file');
console.log('- Monitor logs for security events');
console.log('\n✨ Setup complete!');
