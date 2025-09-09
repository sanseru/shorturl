const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Generate a secure random password
function generateSecurePassword(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

async function main() {
  const args = process.argv.slice(2);
  let password = args[0];
  
  if (!password) {
    password = generateSecurePassword();
    console.log('Generated password:', password);
  }
  
  const hash = await bcrypt.hash(password, 12);
  
  console.log('\n=== Admin Credentials Setup ===');
  console.log('Password:', password);
  console.log('Hash:', hash);
  console.log('\nAdd these to your .env file:');
  console.log(`ADMIN_USERNAME=admin`);
  console.log(`ADMIN_PASSWORD_HASH=${hash}`);
  console.log('\nOr set as environment variables for production.');
}

main().catch(console.error);
