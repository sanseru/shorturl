# 🔒 Security Guide for ShortURL Application

## Security Features Implemented

### 1. **Authentication & Authorization**
- ✅ Bcrypt password hashing (12 rounds)
- ✅ Session-based authentication with timeout (2 hours)
- ✅ CSRF protection on all forms
- ✅ Rate limiting on login attempts (5 per 15 minutes)

### 2. **Input Validation & Sanitization**
- ✅ URL validation and blacklisting
- ✅ SQL injection protection using prepared statements
- ✅ XSS prevention through EJS auto-escaping
- ✅ Request size limits

### 3. **Rate Limiting**
- ✅ General requests: 30/minute
- ✅ URL shortening: 5/minute
- ✅ Login attempts: 5/15 minutes

### 4. **Security Headers**
- ✅ Helmet.js with CSP configuration
- ✅ Secure session cookies
- ✅ SameSite cookie protection

### 5. **Monitoring & Logging**
- ✅ Security event logging
- ✅ Failed authentication tracking
- ✅ Suspicious URL blocking logs

## Setup Instructions

### Initial Setup
```bash
# 1. Install dependencies
npm install

# 2. Run setup script
npm run setup-with-password

# 3. Edit .env file with generated credentials
# 4. Start the application
npm start
```

### Environment Configuration

**Required Variables:**
```env
SESSION_SECRET=your-super-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=generated-bcrypt-hash
```

**Optional Variables:**
```env
PORT=3000
NODE_ENV=production
```

### Password Management

```bash
# Generate new admin password
npm run generate-password

# Generate hash for existing password
node generate-password.js your-existing-password
```

## Security Best Practices

### 1. **Production Deployment**
- [ ] Use HTTPS (SSL/TLS certificate)
- [ ] Set `NODE_ENV=production`
- [ ] Use strong `SESSION_SECRET` (32+ characters)
- [ ] Enable secure cookies (`secure: true`)
- [ ] Use reverse proxy (nginx/Apache)

### 2. **Database Security**
- [ ] Regular database backups
- [ ] File permissions: `chmod 600 data/shorturl.db`
- [ ] Database encryption at rest (if needed)

### 3. **Monitoring**
- [ ] Log monitoring for failed logins
- [ ] Rate limit violation alerts
- [ ] Unusual URL shortening patterns
- [ ] Health check monitoring (`/health`)

### 4. **Regular Maintenance**
- [ ] Update dependencies monthly
- [ ] Review security logs weekly
- [ ] Clean up expired links
- [ ] Monitor disk space usage

## Security Features by Priority

### 🔴 **Critical (Immediate)**
1. Change default passwords
2. Set strong session secret
3. Enable HTTPS in production
4. Update all dependencies

### 🟡 **Important (Within 1 week)**
1. Implement log monitoring
2. Set up automated backups
3. Configure firewall rules
4. Review user access patterns

### 🟢 **Recommended (Within 1 month)**
1. Implement IP geolocation blocking
2. Add honeypot traps
3. Set up intrusion detection
4. Implement 2FA for admin

## Common Security Issues to Avoid

❌ **Don't do:**
- Use default passwords in production
- Allow HTTP in production
- Skip dependency updates
- Ignore security logs
- Use weak session secrets

✅ **Do:**
- Regularly update dependencies
- Monitor security logs
- Use strong authentication
- Implement proper rate limiting
- Keep backups current

## Incident Response

### If Suspicious Activity Detected:
1. Check security logs for patterns
2. Review recent URL creations
3. Check for failed login attempts
4. Consider temporary rate limit reduction
5. Update passwords if compromised

### Emergency Actions:
```bash
# Stop the service
pm2 stop shorturl

# Backup current database
cp data/shorturl.db data/shorturl.db.backup.$(date +%Y%m%d_%H%M%S)

# Review logs
tail -f logs/security.log

# Restart with new configuration
npm start
```

## Contact & Updates

Keep this application updated by regularly:
- Checking for npm security updates: `npm audit`
- Updating dependencies: `npm update`
- Reviewing security best practices
- Following Node.js security advisories
