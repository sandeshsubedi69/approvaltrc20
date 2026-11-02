var MONTHS = ['january','february','march','april','may','june','july','august','september','october','november','december'];

// Derive a numeric hash from the shared secret + time components
function deriveKey(secret, hh, mm, ss, day, month) {
  var str = secret + ':' + hh + ':' + mm + ':' + ss + ':' + day + ':' + month;
  var hash = 0;
  for (var i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % 16777216;
}

// Generate a 4-char signature from the secret + time to prove authenticity
function sign(secret, hh, mm, ss, day, month) {
  var str = secret + '|' + hh + '|' + mm + '|' + ss + '|' + day + '|' + month;
  var h = 2166136261;
  for (var i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (Math.abs(h) >>> 0).toString(36).slice(0, 4).padStart(4, '0');
}

function scrambleAmount(amount, secret, hh, mm, ss, day, month) {
  var cents = Math.round(amount * 100);
  var key = deriveKey(secret, hh, mm, ss, day, month);
  var scrambled = cents ^ key;
  return scrambled.toString(36);
}

function unscrambleAmount(code, secret, hh, mm, ss, day, month) {
  var scrambled = parseInt(code, 36);
  if (isNaN(scrambled)) return NaN;
  var key = deriveKey(secret, hh, mm, ss, day, month);
  var cents = scrambled ^ key;
  return cents / 100;
}

// Format: HHSSMM + last3ofMonth reversed + day + yearTens + monthFirst + signature(4) + scrambledAmount
function encode(amount, secret, date) {
  var d = date || new Date();
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
  var sig = sign(secret, hh, mm, ss, day, monthIdx);
  var amtCode = scrambleAmount(amount, secret, hh, mm, ss, day, monthIdx);

  return timePart + monthEnd + day + yearTens + monthFirst + sig + amtCode;
}

function decode(slug, secret, maxAgeMinutes) {
  maxAgeMinutes = maxAgeMinutes || 20;
  if (!slug || slug.length < 16) return null;

  var timePart = slug.slice(0, 6);
  if (!/^\d{6}$/.test(timePart)) return null;
  var hh = parseInt(timePart.slice(0, 2), 10);
  var ss = parseInt(timePart.slice(2, 4), 10);
  var mm = parseInt(timePart.slice(4, 6), 10);
  if (hh > 23 || mm > 59 || ss > 59) return null;

  var monthEnd = slug.slice(6, 9);
  if (!/^[a-z]{3}$/.test(monthEnd)) return null;
  var monthEndReversed = monthEnd.split('').reverse().join('');

  var candidateMonths = [];
  for (var i = 0; i < MONTHS.length; i++) {
    if (MONTHS[i].slice(-3) === monthEndReversed) {
      candidateMonths.push(i);
    }
  }
  if (!candidateMonths.length) return null;

  var rest = slug.slice(9);
  var now = new Date();

  for (var cm = 0; cm < candidateMonths.length; cm++) {
    var monthIndex = candidateMonths[cm];
    var monthFirst = MONTHS[monthIndex][0];

    for (var j = 2; j < rest.length; j++) {
      if (rest[j] !== monthFirst) continue;

      var dayYearPart = rest.slice(0, j);
      var afterMonth = rest.slice(j + 1);
      if (afterMonth.length < 5) continue;

      var yearTens = parseInt(dayYearPart.slice(-1), 10);
      if (isNaN(yearTens)) continue;
      var dayStr = dayYearPart.slice(0, -1);
      if (!/^\d{1,2}$/.test(dayStr)) continue;
      var day = parseInt(dayStr, 10);
      if (day < 1 || day > 31) continue;

      var sig = afterMonth.slice(0, 4);
      var amtCode = afterMonth.slice(4);
      if (!amtCode) continue;

      for (var y = now.getUTCFullYear() - 1; y <= now.getUTCFullYear() + 1; y++) {
        if (Math.floor(y / 10) % 10 !== yearTens) continue;
        var test = new Date(Date.UTC(y, monthIndex, day, hh, mm, ss));
        if (test.getUTCMonth() !== monthIndex || test.getUTCDate() !== day) continue;
        var ageMinutes = (now - test) / 60000;
        if (ageMinutes >= -1 && ageMinutes <= maxAgeMinutes) {
          // Verify signature
          var expectedSig = sign(secret, hh, mm, ss, day, monthIndex);
          if (sig !== expectedSig) return null;

          var amount = unscrambleAmount(amtCode, secret, hh, mm, ss, day, monthIndex);
          if (isNaN(amount) || amount <= 0) continue;
          return {
            amount: amount,
            timestamp: test,
            ageMinutes: Math.round(ageMinutes * 10) / 10
          };
        }
      }
    }
  }

  return null;
}

module.exports = { encode: encode, decode: decode };
