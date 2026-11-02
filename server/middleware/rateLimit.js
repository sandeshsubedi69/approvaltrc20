const LoginAttempt = require('../models/LoginAttempt');

const MAX_ATTEMPTS = 5;
const LOCK_HOURS = 24;

var PROXY_HEADERS = [
  'x-forwarded-for',
  'via',
  'x-proxy-id',
  'x-real-ip',
  'forwarded',
  'proxy-connection',
  'x-coming-from',
  'x-forwarded-host',
  'x-originating-ip'
];

function getClientIp(req) {
  return req.socket.remoteAddress || req.ip || '0.0.0.0';
}

function isProxyRequest(req) {
  for (var i = 0; i < PROXY_HEADERS.length; i++) {
    var val = req.headers[PROXY_HEADERS[i]];
    if (val) return true;
  }
  if (req.headers['x-forwarded-for']) {
    var ips = req.headers['x-forwarded-for'].split(',');
    if (ips.length > 1) return true;
  }
  return false;
}

async function checkVpn(ip) {
  try {
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return false;
    var cleanIp = ip.replace('::ffff:', '');
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 3000);
    var res = await fetch('http://ip-api.com/json/' + cleanIp + '?fields=proxy,hosting', { signal: controller.signal });
    clearTimeout(timeout);
    var data = await res.json();
    return data.proxy === true || data.hosting === true;
  } catch (e) {
    return false;
  }
}

async function loginRateLimit(req, res, next) {
  var ip = getClientIp(req);

  if (isProxyRequest(req)) {
    return res.status(403).json({ error: 'Direct connections only. Proxy/VPN detected.' });
  }

  var vpn = await checkVpn(ip);
  if (vpn) {
    return res.status(403).json({ error: 'VPN/proxy connections are not allowed.' });
  }

  var record = await LoginAttempt.findOne({ ip: ip });

  if (record && record.lockedUntil && record.lockedUntil > new Date()) {
    var hours = Math.ceil((record.lockedUntil - new Date()) / 3600000);
    return res.status(429).json({
      error: 'Account locked due to too many failed attempts. Try again in ' + hours + ' hour' + (hours > 1 ? 's' : '') + '.',
      lockedUntil: record.lockedUntil
    });
  }

  req._rateIp = ip;
  next();
}

async function recordFailure(ip, username, userAgent) {
  var record = await LoginAttempt.findOne({ ip: ip });
  if (!record) {
    record = new LoginAttempt({ ip: ip, failures: 0, attempts: [] });
  }

  record.failures += 1;
  record.attempts.push({ username: username, userAgent: userAgent, blocked: false });

  if (record.failures >= MAX_ATTEMPTS) {
    record.lockedUntil = new Date(Date.now() + LOCK_HOURS * 3600000);
    if (record.attempts.length > 0) {
      record.attempts[record.attempts.length - 1].blocked = true;
    }
  }

  await record.save();
  return record.failures;
}

async function clearFailures(ip) {
  await LoginAttempt.deleteOne({ ip: ip });
}

module.exports = { loginRateLimit, recordFailure, clearFailures };
