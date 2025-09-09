require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const crypto = require('crypto');
const cron = require('node-cron');

// Enhanced logging function
function securityLog(event, details = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    event,
    ...details
  };
  console.log('SECURITY:', JSON.stringify(logEntry));
  
  // In production, you might want to write to a separate security log file
  // or send to a monitoring service
}

// Helper function to get real client IP
function getRealIP(req) {
  // Dengan trust proxy enabled, req.ip akan menggunakan X-Forwarded-For header
  // yang dikirim oleh Nginx dengan real client IP
  return req.ip || 'unknown';
}

const app = express();

// Trust proxy configuration untuk production dengan Nginx
if (process.env.NODE_ENV === 'production') {
  // Trust semua proxy untuk production (Nginx, load balancers, etc)
  app.set('trust proxy', true);
  console.log('Trust proxy enabled for production environment');
} else {
  // Untuk development, hanya trust localhost
  app.set('trust proxy', 'loopback');
  console.log('Trust proxy set to loopback for development');
}

// Use sql.js for a portable WASM-backed sqlite; persist by writing the DB file.
const DB_PATH = path.join(__dirname, 'data', 'shorturl.db');
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
let SQL;
let db;
async function initDb() {
  console.log('=== INITIALIZING DATABASE ===');
  console.log('DB Path:', DB_PATH);
  
  SQL = await initSqlJs();
  console.log('SQL.js initialized successfully');
  
  if (fs.existsSync(DB_PATH)) {
    console.log('Existing database file found, loading...');
    const filebuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(filebuffer);
    console.log('Database loaded from file');
  } else {
    console.log('Creating new database...');
    db = new SQL.Database();
    console.log('New database created');
  }
  
  // Ensure schema with proper indexes for performance
  console.log('Creating/verifying table schema...');
  db.run(`
    CREATE TABLE IF NOT EXISTS links (
      id INTEGER PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      url TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expire_at INTEGER,
      visits INTEGER DEFAULT 0,
      creator_ip TEXT,
      creator_user_agent TEXT,
      creator_country TEXT,
      last_visit_at INTEGER,
      last_visit_ip TEXT,
      last_visit_user_agent TEXT
    );
  `);
  
  // Create indexes for better performance
  console.log('Creating indexes...');
  try {
    db.run('CREATE INDEX IF NOT EXISTS idx_code ON links(code);');
    db.run('CREATE INDEX IF NOT EXISTS idx_expire_at ON links(expire_at);');
    db.run('CREATE INDEX IF NOT EXISTS idx_created_at ON links(created_at);');
    db.run('CREATE INDEX IF NOT EXISTS idx_creator_ip ON links(creator_ip);');
    db.run('CREATE INDEX IF NOT EXISTS idx_last_visit_at ON links(last_visit_at);');
    console.log('Indexes created successfully');
  } catch (indexErr) {
    console.warn('Index creation warning:', indexErr.message);
  }
  
  // Check current data
  try {
    const countResult = db.exec('SELECT COUNT(*) as count FROM links');
    if (countResult && countResult.length > 0) {
      const count = countResult[0].values[0][0];
      console.log('Current links in database:', count);
    }
  } catch (countErr) {
    console.warn('Could not count existing links:', countErr.message);
  }
  
  persist();
  console.log('Database initialization complete');
}

function persist() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Basic security headers with CSP configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", 
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com"
      ],
      scriptSrc: [
        "'self'", 
        "'unsafe-inline'", 
        "https://cdn.jsdelivr.net"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      fontSrc: [
        "'self'", 
        "https://cdn.jsdelivr.net",
        "https://fonts.gstatic.com"
      ],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
  }
}));

// Views and static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/css/bootstrap.min.css', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/css/bootstrap.min.css')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-fallback-secret-key-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Change default session name
  proxy: process.env.NODE_ENV === 'production', // Trust proxy untuk HTTPS detection
  cookie: { 
    secure: process.env.NODE_ENV === 'production' ? 'auto' : false, // Auto detect HTTPS dengan proxy
    httpOnly: true,
    maxAge: 2 * 60 * 60 * 1000, // Reduced to 2 hours for admin sessions
    sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'strict' // Lebih flexible untuk production
  }
}));

// Rate limiting with different limits for different routes
const generalLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 30,
  message: 'Too many requests, please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip successful requests to reduce false positives
  skipSuccessfulRequests: false
});

const shortenLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5, // Only 5 URL shortening per minute
  message: 'Too many URL shortening requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator untuk lebih akurat dengan proxy
  keyGenerator: function (req) {
    return req.ip; // Menggunakan real IP dari trust proxy
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 login attempts per 15 minutes
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  // Track failed login attempts more strictly
  skipSuccessfulRequests: true,
  keyGenerator: function (req) {
    return req.ip; // Menggunakan real IP dari trust proxy
  }
});

app.use(generalLimiter);

// CSRF protection for forms
const csrfProtection = csurf({ cookie: true });

// Authentication middleware with session timeout
function requireAuth(req, res, next) {
  console.log('RequireAuth check:', {
    sessionExists: !!req.session,
    authenticated: req.session?.authenticated,
    user: req.session?.user,
    sessionId: req.session?.id,
    cookies: req.headers.cookie ? 'present' : 'missing'
  });
  
  if (req.session && req.session.authenticated) {
    // Check session timeout (2 hours)
    const sessionAge = Date.now() - (req.session.loginTime || 0);
    const maxAge = 2 * 60 * 60 * 1000; // 2 hours
    
    if (sessionAge > maxAge) {
      console.log('Session expired for user:', req.session?.user);
      req.session.destroy((err) => {
        if (err) console.error('Session destroy error:', err);
      });
      return res.redirect('/admin/login?redirect=' + encodeURIComponent(req.originalUrl) + '&message=session_expired');
    }
    
    // Refresh session on activity
    req.session.loginTime = Date.now();
    console.log('Authentication successful, proceeding...');
    return next();
  } else {
    console.log('Authentication failed, redirecting to login...');
    return res.redirect('/admin/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
}

// NOTE: DB schema is created inside initDb() after sql.js is initialized.

function genCode(n = 6) {
  return crypto.randomBytes(n).toString('base64url').slice(0, n);
}

// Helper to parse duration rule like "hours:5" or "days:2"
function parseExpiry(rule) {
  if (!rule) return null;
  // allow formats: hours:5, days:2, months:1
  const [unit, val] = rule.split(':');
  const num = Math.max(0, parseInt(val || '0', 10));
  if (!num) return null;
  const now = Date.now();
  switch (unit) {
    case 'hours': return now + num * 3600 * 1000;
    case 'days': return now + num * 24 * 3600 * 1000;
    case 'months': return now + num * 30 * 24 * 3600 * 1000;
    case 'minutes': return now + num * 60 * 1000;
    default: return null;
  }
}

// Authentication routes
app.get('/admin/login', csrfProtection, (req, res) => {
  if (req.session && req.session.authenticated) {
    const redirect = req.query.redirect || '/admin';
    return res.redirect(redirect);
  }
  res.render('login', { 
    csrfToken: req.csrfToken(), 
    error: null,
    redirect: req.query.redirect || '/admin'
  });
});

app.post('/admin/login', csrfProtection, loginLimiter, async (req, res) => {
  const { username, password, redirect } = req.body;
  
  console.log('=== LOGIN ATTEMPT ===');
  console.log('Username:', username);
  console.log('Redirect URL:', redirect);
  
  try {
    // Get credentials from environment
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
    
    // If no hash is set, use default for development (should be changed in production)
    let isValidPassword = false;
    if (adminPasswordHash) {
      // Use bcrypt to verify hashed password
      isValidPassword = await bcrypt.compare(password, adminPasswordHash);
    } else {
      // Fallback for development - should be removed in production
      const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
      isValidPassword = (password === defaultPassword);
      console.warn('WARNING: Using plain text password. Set ADMIN_PASSWORD_HASH for production!');
    }
    
    if (username === adminUsername && isValidPassword) {
      req.session.authenticated = true;
      req.session.user = username;
      req.session.loginTime = Date.now();
      
      console.log('Login successful for user:', username);
      console.log('Session after login:', {
        authenticated: req.session.authenticated,
        user: req.session.user,
        loginTime: req.session.loginTime,
        sessionId: req.session.id
      });
      
      const redirectUrl = redirect || '/admin';
      console.log('Redirecting to:', redirectUrl);
      
      // Force save session before redirect
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'Login failed. Please try again.',
            redirect: redirect || '/admin'
          });
        }
        console.log('Session saved successfully, redirecting...');
        res.redirect(redirectUrl);
      });
    } else {
      console.log('Login failed for user:', username);
      res.render('login', { 
        csrfToken: req.csrfToken(), 
        error: 'Invalid username or password',
        redirect: redirect || '/admin'
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { 
      csrfToken: req.csrfToken(), 
      error: 'Login failed. Please try again.',
      redirect: redirect || '/admin'
    });
  }
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/admin/login');
  });
});

app.get('/', csrfProtection, (req, res) => {
  res.render('index', { csrfToken: req.csrfToken(), error: null, short: null });
});

// Terms of Service page
app.get('/terms', (req, res) => {
  res.render('terms');
});

// Privacy Policy page
app.get('/privacy', (req, res) => {
  res.render('privacy');
});

app.post('/shorten', csrfProtection, shortenLimiter, (req, res) => {
  const { url, expiryRule } = req.body;
  
  console.log('Creating short URL for:', url?.substring(0, 100) + (url?.length > 100 ? '...' : ''));
  
  if (!url || !url.trim()) {
    return res.status(400).render('index', { 
      csrfToken: req.csrfToken(), 
      error: 'URL is required', 
      short: null 
    });
  }

  let trimmedUrl = url.trim();

  // Check URL length (most browsers support up to ~2000 chars, but we'll be more generous)
  if (trimmedUrl.length > 5000) {
    console.log('ERROR: URL too long:', trimmedUrl.length, 'characters');
    return res.status(400).render('index', { 
      csrfToken: req.csrfToken(), 
      error: 'URL is too long. Maximum length is 5000 characters.', 
      short: null 
    });
  }

  // If URL doesn't have protocol, prepend https://
  if (!/^https?:\/\//i.test(trimmedUrl)) {
    trimmedUrl = 'https://' + trimmedUrl;
  }

  try {
    // Basic validation using the trimmed URL
    const parsed = new URL(trimmedUrl);
    
    // Prevent local/internal network targets and blacklisted domains
    const host = parsed.hostname.toLowerCase();
    
    // Enhanced blacklist
    const blacklistedDomains = [
      'localhost', '127.', '::1', '0.', '10.', '192.168.',
      'bit.ly', 'tinyurl.com', 'short.link', 't.co', // Prevent URL shortener chains
      'malware.com', 'phishing.com' // Add known malicious domains
    ];
    
    const isBlacklisted = blacklistedDomains.some(domain => 
      host.includes(domain) || host.endsWith('.local') || host.endsWith('.internal')
    );
    
    // Check for private IP ranges
    const isPrivateIP = /^(localhost|127\.|::1|0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(host);
    
    if (isBlacklisted || isPrivateIP) {
      securityLog('BLOCKED_URL', {
        url: trimmedUrl,
        hostname: host,
        ip: getRealIP(req),
        userAgent: userAgent
      });
      
      return res.status(400).render('index', { 
        csrfToken: req.csrfToken(), 
        error: 'This URL is not allowed to be shortened', 
        short: null 
      });
    }

    // Generate unique short code
    let code;
    let attempts = 0;
    do {
      code = genCode(6);
      attempts++;
      
      if (attempts > 20) {
        console.error('Failed to generate unique code after 20 attempts');
        return res.status(500).render('index', { 
          csrfToken: req.csrfToken(), 
          error: 'Unable to generate unique short code. Please try again.', 
          short: null 
        });
      }
      
      // Check if code exists using sql.js compatible query
      const stmt = db.prepare('SELECT 1 FROM links WHERE code = ?');
      const checkResult = stmt.getAsObject([code]);
      stmt.free();
      if (!checkResult || Object.keys(checkResult).length === 0) break;
    } while (attempts < 20);

    const expireAt = parseExpiry(expiryRule);
    const createdAt = Date.now();
    
    // Get client information (menggunakan helper function untuk real IP)
    const clientIP = getRealIP(req);
    const userAgent = req.get('User-Agent') || 'unknown';
    
    // Use prepared statements for safe insertion
    const stmt = db.prepare('INSERT INTO links (code, url, created_at, expire_at, creator_ip, creator_user_agent) VALUES (?, ?, ?, ?, ?, ?)');
    stmt.run([code, trimmedUrl, createdAt, expireAt, clientIP, userAgent]);
    stmt.free();
    persist();

    const short = req.protocol + '://' + req.get('host') + '/' + code;
    console.log('Created short URL:', code, 'for', parsed.hostname);
    
    res.render('index', { 
      csrfToken: req.csrfToken(), 
      error: null, 
      short 
    });
    
  } catch (err) {
    console.error('URL shortening error:', err.message);
    res.status(400).render('index', { 
      csrfToken: req.csrfToken(), 
      error: 'Invalid URL. Please enter a valid URL (e.g., https://example.com)', 
      short: null 
    });
  }
});

app.get('/favicon.ico', (req, res) => res.status(204).end());

// Health check endpoint
app.get('/health', (req, res) => {
  try {
    // Check database connectivity
    const testResult = db.exec('SELECT 1 as test');
    const isDbOk = testResult && testResult.length > 0;
    
    const status = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: isDbOk ? 'connected' : 'error',
      version: require('./package.json').version
    };
    
    res.json(status);
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Debug endpoint untuk session (temporary - remove in production)
app.get('/debug/session', (req, res) => {
  if (process.env.NODE_ENV !== 'production') {
    res.json({
      session: {
        id: req.session?.id,
        authenticated: req.session?.authenticated,
        user: req.session?.user,
        loginTime: req.session?.loginTime
      },
      cookies: req.headers.cookie,
      headers: {
        'x-forwarded-proto': req.get('x-forwarded-proto'),
        'x-forwarded-for': req.get('x-forwarded-for'),
        'x-real-ip': req.get('x-real-ip'),
        'host': req.get('host')
      },
      ip: req.ip,
      secure: req.secure,
      protocol: req.protocol
    });
  } else {
    res.status(404).send('Not found');
  }
});

// API endpoint for stats (for external monitoring)
app.get('/api/stats', requireAuth, (req, res) => {
  try {
    const countResult = db.exec('SELECT COUNT(*) as total FROM links');
    const visitsResult = db.exec('SELECT SUM(visits) as total_visits FROM links');
    const recentResult = db.exec('SELECT COUNT(*) as recent FROM links WHERE created_at > ' + (Date.now() - 24*60*60*1000));
    
    const stats = {
      totalLinks: countResult[0]?.values[0]?.[0] || 0,
      totalVisits: visitsResult[0]?.values[0]?.[0] || 0,
      linksLast24h: recentResult[0]?.values[0]?.[0] || 0,
      timestamp: new Date().toISOString()
    };
    
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

// Serve robots.txt to prevent search engine crawling
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *
Disallow: /

# This is a private URL shortener service
# No crawling allowed`);
});

// Block common crawler patterns
app.use((req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  const blockedAgents = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 
    'baiduspider', 'yandexbot', 'facebookexternalhit',
    'twitterbot', 'linkedinbot', 'whatsapp', 'telegrambot'
  ];
  
  if (blockedAgents.some(agent => userAgent.toLowerCase().includes(agent))) {
    console.log('Blocked crawler:', userAgent);
    return res.status(403).send('Crawling not allowed');
  }
  next();
});

// Admin routes should come before the catch-all /:code route (protected by auth)
app.get('/admin', requireAuth, (req, res) => {
  res.redirect('/admin/list');
});

// Stats page with beautiful UI (protected by auth)
app.get('/debug/stats', requireAuth, (req, res) => {
  try {
    const countResult = db.exec('SELECT COUNT(*) as total FROM links');
    const recentResult = db.exec('SELECT COUNT(*) as recent FROM links WHERE created_at > ' + (Date.now() - 24*60*60*1000));
    const visitsResult = db.exec('SELECT SUM(visits) as total_visits FROM links');
    const topLinksResult = db.exec('SELECT code, url, visits FROM links ORDER BY visits DESC LIMIT 5');
    const recentLinksResult = db.exec('SELECT code, url, created_at FROM links ORDER BY created_at DESC LIMIT 5');
    
    // Get detailed visitor information
    const visitorStatsResult = db.exec(`
      SELECT 
        COUNT(DISTINCT creator_ip) as unique_ips,
        COUNT(DISTINCT last_visit_ip) as unique_visitor_ips,
        COUNT(*) as total_links_with_ip
      FROM links 
      WHERE creator_ip IS NOT NULL OR last_visit_ip IS NOT NULL
    `);
    
    // Get recent visitor activity
    const recentVisitorsResult = db.exec(`
      SELECT 
        code, 
        url, 
        creator_ip, 
        creator_user_agent, 
        creator_country,
        last_visit_ip,
        last_visit_user_agent,
        last_visit_at,
        visits,
        created_at
      FROM links 
      WHERE last_visit_at IS NOT NULL 
      ORDER BY last_visit_at DESC 
      LIMIT 10
    `);
    
    // Get top countries
    const topCountriesResult = db.exec(`
      SELECT creator_country, COUNT(*) as count 
      FROM links 
      WHERE creator_country IS NOT NULL 
      GROUP BY creator_country 
      ORDER BY count DESC 
      LIMIT 5
    `);
    
    // Get browser statistics
    const browserStatsResult = db.exec(`
      SELECT 
        CASE 
          WHEN creator_user_agent LIKE '%Chrome%' THEN 'Chrome'
          WHEN creator_user_agent LIKE '%Firefox%' THEN 'Firefox'
          WHEN creator_user_agent LIKE '%Safari%' THEN 'Safari'
          WHEN creator_user_agent LIKE '%Edge%' THEN 'Edge'
          WHEN creator_user_agent LIKE '%Opera%' THEN 'Opera'
          ELSE 'Other'
        END as browser,
        COUNT(*) as count
      FROM links 
      WHERE creator_user_agent IS NOT NULL 
      GROUP BY browser 
      ORDER BY count DESC
    `);
    
    const total = countResult[0]?.values[0]?.[0] || 0;
    const recent = recentResult[0]?.values[0]?.[0] || 0;
    const totalVisits = visitsResult[0]?.values[0]?.[0] || 0;
    
    // Visitor statistics
    const uniqueIPs = visitorStatsResult[0]?.values[0]?.[0] || 0;
    const uniqueVisitorIPs = visitorStatsResult[0]?.values[0]?.[1] || 0;
    
    // Format top links
    const topLinks = topLinksResult[0] ? 
      topLinksResult[0].values.map(row => ({
        code: row[0],
        url: row[1].length > 50 ? row[1].substring(0, 50) + '...' : row[1],
        visits: row[2]
      })) : [];
    
    // Format recent links
    const recentLinks = recentLinksResult[0] ? 
      recentLinksResult[0].values.map(row => ({
        code: row[0],
        url: row[1].length > 50 ? row[1].substring(0, 50) + '...' : row[1],
        created_at: new Date(row[2]).toLocaleString()
      })) : [];
    
    // Format recent visitors
    const recentVisitors = recentVisitorsResult[0] ? 
      recentVisitorsResult[0].values.map(row => ({
        code: row[0],
        url: row[1].length > 60 ? row[1].substring(0, 60) + '...' : row[1],
        creator_ip: row[2] || 'N/A',
        creator_user_agent: row[3] || 'N/A',
        creator_country: row[4] || 'Unknown',
        last_visit_ip: row[5] || 'N/A',
        last_visit_user_agent: row[6] || 'N/A',
        last_visit_at: row[7] ? new Date(row[7]).toLocaleString() : 'Never',
        visits: row[8] || 0,
        created_at: new Date(row[9]).toLocaleString()
      })) : [];
    
    // Format top countries
    const topCountries = topCountriesResult[0] ? 
      topCountriesResult[0].values.map(row => ({
        country: row[0] || 'Unknown',
        count: row[1]
      })) : [];
    
    // Format browser statistics
    const browserStats = browserStatsResult[0] ? 
      browserStatsResult[0].values.map(row => ({
        browser: row[0],
        count: row[1]
      })) : [];
    
    res.render('stats', {
      csrfToken: req.csrfToken ? req.csrfToken() : 'no-csrf',
      error: null,
      stats: {
        totalLinks: total,
        linksLast24h: recent,
        totalVisits: totalVisits,
        uniqueIPs: uniqueIPs,
        uniqueVisitorIPs: uniqueVisitorIPs,
        topLinks: topLinks,
        recentLinks: recentLinks,
        recentVisitors: recentVisitors,
        topCountries: topCountries,
        browserStats: browserStats
      }
    });
  } catch (err) {
    res.render('stats', {
      csrfToken: req.csrfToken ? req.csrfToken() : 'no-csrf',
      error: err.message,
      stats: null
    });
  }
});

// Admin — simple listing and cleanup (protected by auth)
app.get('/admin/list', requireAuth, (req, res) => {
  console.log('=== ADMIN LIST REQUEST ===');
  
  try {
    // Use sql.js compatible query
    const result = db.exec('SELECT * FROM links ORDER BY created_at DESC LIMIT 100');
    console.log('Admin query result:', result);
    
    const rows = [];
    if (result && result.length > 0 && result[0].values) {
      const cols = result[0].columns;
      result[0].values.forEach(v => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = v[i]);
        rows.push(obj);
      });
    }
    
    console.log('Formatted rows:', rows.length, 'items');
    
    // Format the rows for better display
    const formattedRows = rows.map(row => ({
      ...row,
      created_at_formatted: new Date(row.created_at).toLocaleString(),
      expire_at_formatted: row.expire_at ? new Date(row.expire_at).toLocaleString() : 'Never',
      url_display: row.url.length > 60 ? row.url.substring(0, 60) + '...' : row.url
    }));
    
    res.render('admin', { rows: formattedRows });
  } catch (err) {
    console.error('Admin list error:', err);
    console.error('Error stack:', err.stack);
    res.render('admin', { rows: [] });
  }
});

// Delete link route (protected by auth)
app.post('/admin/delete/:code', requireAuth, (req, res) => {
  const code = req.params.code;
  
  try {
    // Validate code format
    if (!/^[A-Za-z0-9_-]+$/.test(code) || code.length > 20) {
      return res.json({ success: false, error: 'Invalid code format' });
    }
    
    // Check if link exists using prepared statement
    const stmt = db.prepare('SELECT id FROM links WHERE code = ?');
    const checkResult = stmt.getAsObject([code]);
    stmt.free();
    
    if (!checkResult || Object.keys(checkResult).length === 0) {
      return res.json({ success: false, error: 'Link not found' });
    }
    
    // Delete the link using prepared statement
    const deleteStmt = db.prepare('DELETE FROM links WHERE code = ?');
    deleteStmt.run([code]);
    deleteStmt.free();
    persist(); // Save changes to file
    
    securityLog('LINK_DELETED', {
      code: code,
      admin: req.session.user,
      timestamp: new Date().toISOString()
    });
    
    res.json({ success: true, message: 'Link deleted successfully' });
    
  } catch (err) {
    console.error('Delete error:', err);
    res.json({ success: false, error: 'Failed to delete link' });
  }
});

// Bulk operations for admin
app.post('/admin/bulk-delete', requireAuth, (req, res) => {
  const { action, criteria } = req.body;
  
  try {
    let deletedCount = 0;
    
    if (action === 'expired') {
      // Delete all expired links
      const stmt = db.prepare('DELETE FROM links WHERE expire_at IS NOT NULL AND expire_at <= ?');
      const result = stmt.run([Date.now()]);
      stmt.free();
      deletedCount = result.changes || 0;
      
    } else if (action === 'old') {
      // Delete links older than specified days
      const days = parseInt(criteria.days) || 30;
      const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
      const stmt = db.prepare('DELETE FROM links WHERE created_at < ?');
      const result = stmt.run([cutoff]);
      stmt.free();
      deletedCount = result.changes || 0;
      
    } else if (action === 'unused') {
      // Delete links with zero visits older than 7 days
      const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000);
      const stmt = db.prepare('DELETE FROM links WHERE visits = 0 AND created_at < ?');
      const result = stmt.run([cutoff]);
      stmt.free();
      deletedCount = result.changes || 0;
    }
    
    persist();
    
    securityLog('BULK_DELETE', {
      action: action,
      criteria: criteria,
      deletedCount: deletedCount,
      admin: req.session.user
    });
    
    res.json({ success: true, message: `Deleted ${deletedCount} links successfully` });
    
  } catch (err) {
    console.error('Bulk delete error:', err);
    res.json({ success: false, error: 'Failed to perform bulk operation' });
  }
});

app.get('/:code', async (req, res) => {
  const code = req.params.code;
  
  // Skip processing for known static files or admin routes
  if (code.includes('.') || code === 'admin' || code === 'debug') {
    return res.status(404).render('404');
  }
  
  // Validate code format (should be alphanumeric base64url)
  if (!/^[A-Za-z0-9_-]+$/.test(code) || code.length > 20) {
    return res.status(404).render('404');
  }
  
  try {
    // Use sql.js compatible query with proper escaping
    const escapedCode = code.replace(/'/g, "''");
    const selectQuery = `SELECT * FROM links WHERE code = '${escapedCode}'`;
    
    const result = db.exec(selectQuery);
    
    if (!result || result.length === 0 || !result[0].values || result[0].values.length === 0) {
      return res.status(404).render('404');
    }
    
    // Convert result to object
    const cols = result[0].columns;
    const vals = result[0].values[0];
    const row = {};
    cols.forEach((c, i) => row[c] = vals[i]);
    
    // Check if expired
    if (row.expire_at && Date.now() > row.expire_at) {
      console.log('Removing expired link:', code);
      // Delete expired link
      const deleteQuery = `DELETE FROM links WHERE code = '${escapedCode}'`;
      db.exec(deleteQuery);
      persist();
      return res.status(410).render('expired');
    }

    // Increment visit counter and update visit info (menggunakan helper function untuk real IP)
    const visitIP = getRealIP(req);
    const visitUserAgent = req.get('User-Agent') || 'unknown';
    const visitTime = Date.now();
    
    // Update visit information using prepared statement
    const updateStmt = db.prepare('UPDATE links SET visits = visits + 1, last_visit_at = ?, last_visit_ip = ?, last_visit_user_agent = ? WHERE code = ?');
    updateStmt.run([visitTime, visitIP, visitUserAgent, code]);
    updateStmt.free();
    persist();
    
    console.log('Redirecting:', code, '->', new URL(row.url).hostname);
    // Redirect to the original URL
    res.redirect(301, row.url);
    
  } catch (err) {
    console.error('URL retrieval error for code', code + ':', err.message);
    res.status(500).render('404');
  }
});

// Background cleanup: delete expired every hour
cron.schedule('0 * * * *', () => {
  try {
    const now = Date.now();
    console.log('Running cleanup job at:', new Date().toLocaleString());
    
    // Use sql.js compatible query
    const deleteQuery = `DELETE FROM links WHERE expire_at IS NOT NULL AND expire_at <= ${now}`;
    console.log('Cleanup query:', deleteQuery);
    
    db.exec(deleteQuery);
    persist();
    console.log('Cleanup completed successfully');
  } catch (err) {
    console.error('Cleanup error:', err);
    console.error('Error stack:', err.stack);
  }
});

const port = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(port, () => console.log('ShortURL app listening on', port));
}).catch(err => {
  console.error('Failed to init DB', err);
  process.exit(1);
});
