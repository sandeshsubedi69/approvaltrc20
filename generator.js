/**
 * Standalone Link Generator for Platform B
 *
 * This file contains the full algorithm. No API calls needed.
 * Just set LINK_SECRET to the same value as the server's .env
 * and call generateLink(amount).
 *
 * Usage (Node.js):
 *   node generator.js 100
 *
 * Usage (in any JS app):
 *   const { generateLink } = require('./generator');
 *   var url = generateLink(100);
 */

// ──── SHARED SECRET (must match server's LINK_SECRET) ────
var LINK_SECRET = 'REPLACE_WITH_YOUR_LINK_SECRET';

// ──── ALGORITHM (copy this block to any platform) ────
var MONTHS = ['january','february','march','april','may','june','july','august','september','october','november','december'];

function deriveKey(secret, hh, mm, ss, day, month) {
  var str = secret + ':' + hh + ':' + mm + ':' + ss + ':' + day + ':' + month;
  var hash = 0;
  for (var i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % 16777216;
}

function sign(secret, hh, mm, ss, day, month) {
  var str = secret + '|' + hh + '|' + mm + '|' + ss + '|' + day + '|' + month;
  var h = 2166136261;
  for (var i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (Math.abs(h) >>> 0).toString(36).slice(0, 4).padStart(4, '0');
}

function generateLink(amount, baseUrl) {
  baseUrl = baseUrl || '';
  var d = new Date();
  var hh = d.getUTCHours();
  var mm = d.getUTCMinutes();
  var ss = d.getUTCSeconds();
  var monthIdx = d.getUTCMonth();
  var month = MONTHS[monthIdx];
  var day = d.getUTCDate();
  var year = d.getUTCFullYear();

  var timePart = String(hh).padStart(2, '0') + String(ss).padStart(2, '0') + String(mm).padStart(2, '0');
  var monthEnd = month.slice(-3).split('').reverse().join('');
  var yearTens = Math.floor(year / 10) % 10;
  var monthFirst = month[0];
  var sig = sign(LINK_SECRET, hh, mm, ss, day, monthIdx);

  var cents = Math.round(amount * 100);
  var key = deriveKey(LINK_SECRET, hh, mm, ss, day, monthIdx);
  var amtCode = (cents ^ key).toString(36);

  var slug = timePart + monthEnd + day + yearTens + monthFirst + sig + amtCode;
  return baseUrl + '/' + slug;
}
// ──── END ALGORITHM ────

// CLI usage
if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].indexOf('generator') !== -1) {
  var amount = parseFloat(process.argv[2]);
  var base = process.argv[3] || 'https://yourdomain.com';
  if (!amount || amount <= 0) {
    console.log('Usage: node generator.js <amount> [baseUrl]');
    console.log('Example: node generator.js 100 https://yourdomain.com');
    process.exit(1);
  }
  console.log(generateLink(amount, base));
}

if (typeof module !== 'undefined') module.exports = { generateLink: generateLink };
