# 🔗 ShortURL - Secure URL Shortener

![Node.js](https://img.shields.io/badge/Node.js-v18+-green)
![Express](https://img.shields.io/badge/Express-4.18+-blue)
![SQLite](https://img.shields.io/badge/SQLite-3+-lightgrey)
![Security](https://img.shields.io/badge/Security-Enhanced-red)

Aplikasi pemendekan URL yang aman dan mudah digunakan dengan fitur keamanan enterprise-grade, built dengan Node.js, Express, dan SQLite.

## ✨ **Fitur Utama**

### 🔒 **Keamanan**
- ✅ Bcrypt password hashing (12 rounds)
- ✅ CSRF protection pada semua form
- ✅ Rate limiting (berbeda untuk setiap endpoint)
- ✅ SQL injection protection (prepared statements)
- ✅ Session timeout otomatis (2 jam)
- ✅ URL blacklisting (domain berbahaya & internal network)
- ✅ Security headers dengan Helmet.js
- ✅ XSS prevention dengan EJS auto-escaping

### 📊 **Management & Monitoring**
- ✅ Admin dashboard dengan statistik lengkap
- ✅ Bulk operations (hapus expired/unused links)
- ✅ Health check endpoint (`/health`)
- ✅ API stats endpoint (`/api/stats`)
- ✅ Security event logging
- ✅ Real-time visitor tracking

### 🚀 **Performance**
- ✅ SQLite dengan indexing optimal
- ✅ Session-based authentication
- ✅ Automated cleanup (expired links)
- ✅ PM2 clustering support
- ✅ Background cron jobs

## 📋 **Requirements**

- Node.js v18 atau lebih baru
- npm v8 atau lebih baru
- PM2 (untuk production deployment)

## 🚀 **Quick Start**

### 1. **Clone & Install**
```bash
# Clone repository
git clone https://github.com/sanseru/shorturl.git
cd shorturl

# Install dependencies
npm install

# Install PM2 globally (untuk production)
npm install -g pm2
```

### 2. **Setup Aplikasi**
```bash
# Setup otomatis dengan password generation
npm run setup-with-password

# Atau setup manual
npm run setup
npm run generate-password
```

### 3. **Konfigurasi Environment**
Edit file `.env` yang telah dibuat:
```env
# Server Configuration
PORT=3000                    # Aplikasi akan berjalan di port ini
NODE_ENV=development

# Session Security (REQUIRED)
SESSION_SECRET=your-super-secret-session-key-here

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=generated-bcrypt-hash-from-setup
```

**📡 Port Configuration:**
- Aplikasi otomatis membaca port dari `PORT` di file `.env`
- Jika tidak ada `PORT` di `.env`, default menggunakan port `3000`
- PM2 akan menggunakan port yang sama dari `.env`

### 4. **Jalankan Aplikasi**

#### Development Mode
```bash
npm start
# atau
npm run dev
```

#### Production dengan PM2
```bash
# Buat folder logs
npm run logs:create

# Start dengan PM2
npm run pm2:prod

# Monitoring
npm run pm2:monit
npm run pm2:logs
```

### **Check Configuration**
```bash
# Lihat konfigurasi dan status aplikasi
npm run config

# Output contoh:
# 🔍 ShortURL Current Configuration
# ================================
# 📡 Port: 8080
# 🏷️  Environment: production
# 👤 Admin Username: admin
# 🔐 Password Hash: ✅ Set
# 🔑 Session Secret: ✅ Set
# 🚀 Application Status: RUNNING
# 🌐 Access URL: http://localhost:8080
```

## 🔧 **PM2 Management**

### **Commands Tersedia:**
```bash
# Start aplikasi
npm run pm2:start          # Default mode
npm run pm2:dev            # Development mode  
npm run pm2:prod           # Production mode

# Management
npm run pm2:stop           # Stop aplikasi
npm run pm2:restart        # Restart aplikasi
npm run pm2:delete         # Hapus dari PM2

# Monitoring
npm run pm2:logs           # Lihat logs
npm run pm2:monit          # Real-time monitoring
```

### **PM2 Configuration (ecosystem.config.json):**
```json
{
  "apps": [{
    "name": "shorturl",
    "script": "server.js",
    "instances": "max",        // Gunakan semua CPU cores
    "exec_mode": "cluster",    // Cluster mode untuk performance
    "max_memory_restart": "1G", // Auto restart jika memory > 1GB
    "cron_restart": "0 2 * * *", // Auto restart setiap hari jam 2 pagi
    "autorestart": true,
    "watch": false
  }]
}
```

## 🌐 **Deployment ke Production**

### 1. **Persiapan Server**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js v18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2
sudo npm install -g pm2

# Clone dan setup aplikasi
git clone https://github.com/sanseru/shorturl.git
cd shorturl
npm install
npm run setup-with-password
```

### 2. **Konfigurasi Environment Production**
```bash
# Edit .env untuk production
nano .env
```

Set nilai berikut:
```env
NODE_ENV=production
PORT=3000
SESSION_SECRET=your-super-strong-random-session-secret
ADMIN_USERNAME=your-admin-username
ADMIN_PASSWORD_HASH=your-generated-hash
```

### 3. **Start dengan PM2**
```bash
# Buat folder logs
npm run logs:create

# Start production
npm run pm2:prod

# Setup PM2 startup script
pm2 startup
pm2 save
```

### 4. **Setup Reverse Proxy (Nginx)**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### 5. **Setup SSL dengan Let's Encrypt**
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## 📊 **Monitoring & Maintenance**

### **Health Check**
```bash
# Check aplikasi status
curl http://localhost:3000/health

# Response example:
{
  "status": "healthy",
  "timestamp": "2025-09-09T10:00:00.000Z",
  "uptime": 3600,
  "database": "connected",
  "version": "1.0.0"
}
```

### **Statistics API**
```bash
# Get stats (requires admin authentication)
curl -H "Cookie: sessionId=your-session" http://localhost:3000/api/stats
```

### **Log Management**
```bash
# PM2 logs
npm run pm2:logs

# Application logs
tail -f logs/combined.log
tail -f logs/err.log

# Log rotation (recommended)
pm2 install pm2-logrotate
```

### **Database Backup**
```bash
# Manual backup
cp data/shorturl.db data/shorturl.db.backup.$(date +%Y%m%d_%H%M%S)

# Automated backup script
echo "0 1 * * * cp /path/to/shorturl/data/shorturl.db /path/to/backups/shorturl.db.$(date +\%Y\%m\%d)" | crontab -
```

## 🔐 **Security Checklist**

### **Before Production:**
- [ ] Change default admin credentials
- [ ] Set strong `SESSION_SECRET`
- [ ] Enable HTTPS/SSL
- [ ] Configure firewall (UFW/iptables)
- [ ] Set proper file permissions (`chmod 600 .env`)
- [ ] Review and update blacklisted domains

### **Regular Maintenance:**
- [ ] Update dependencies monthly (`npm audit` & `npm update`)
- [ ] Review security logs weekly
- [ ] Clean expired links (`/admin/bulk-delete`)
- [ ] Monitor disk space usage
- [ ] Backup database regularly

### **Monitoring Setup:**
- [ ] Setup log monitoring (ELK Stack/Grafana)
- [ ] Configure alerts for failed logins
- [ ] Monitor rate limit violations
- [ ] Track unusual URL creation patterns

## 📝 **API Endpoints**

### **Public**
- `GET /` - Homepage
- `POST /shorten` - Create short URL
- `GET /:code` - Redirect to original URL
- `GET /health` - Health check

### **Admin** (requires authentication)
- `GET /admin` - Admin dashboard
- `GET /admin/list` - List all links
- `POST /admin/delete/:code` - Delete specific link
- `POST /admin/bulk-delete` - Bulk operations
- `GET /debug/stats` - Detailed statistics
- `GET /api/stats` - API statistics

## 🛠️ **Development**

### **Project Structure**
```
shorturl/
├── server.js              # Main application
├── package.json           # Dependencies & scripts
├── ecosystem.config.json  # PM2 configuration
├── generate-password.js   # Password generator utility
├── setup.js              # Setup automation script
├── .env.example          # Environment template
├── data/                 # SQLite database
├── views/                # EJS templates
├── public/               # Static assets
└── logs/                 # Application logs
```

### **Environment Variables**
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | Server port |
| `NODE_ENV` | No | `development` | Environment mode |
| `SESSION_SECRET` | Yes | - | Session encryption key |
| `ADMIN_USERNAME` | No | `admin` | Admin username |
| `ADMIN_PASSWORD_HASH` | Yes | - | Bcrypt hashed password |

---

**Made with ❤️ for secure and efficient URL shortening**
