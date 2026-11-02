var express = require('express');
var jwt = require('jsonwebtoken');
var crypto = require('crypto');
var bip39 = require('bip39');
var { TOTP, Secret } = require('otpauth');
var QRCode = require('qrcode');
var Admin = require('../models/Admin');
var auth = require('../middleware/auth');
var bcrypt = require('bcryptjs');
var fs = require('fs');
var path = require('path');
var { loginRateLimit, recordFailure, clearFailures } = require('../middleware/rateLimit');
var vault = require('../crypto');

var router = express.Router();

var sessionKeys = {};

function setSessionKey(adminId, masterKey) {
  sessionKeys[String(adminId)] = masterKey;
}

function getSessionKey(adminId) {
  return sessionKeys[String(adminId)] || null;
}

function clearSessionKey(adminId) {
  delete sessionKeys[String(adminId)];
}

function generateBackupCodes() {
  var codes = [];
  for (var i = 0; i < 8; i++) {
    codes.push({ code: crypto.randomBytes(4).toString('hex').toUpperCase(), used: false });
  }
  return codes;
}

function makeTOTP(hexSecret) {
  return new TOTP({
    issuer: 'ApprovalManager',
    label: 'Admin',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromHex(hexSecret)
  });
}

router.post('/setup', loginRateLimit, async function (req, res) {
  try {
    var existing = await Admin.findOne();
    if (existing) return res.status(400).json({ error: 'Admin already exists' });
    if (req.body.setupKey !== process.env.ADMIN_SETUP_KEY) {
      await recordFailure(req._rateIp, req.body.username || '', req.headers['user-agent'] || '');
      return res.status(403).json({ error: 'Invalid setup key' });
    }
    if (!req.body.username || !req.body.password || req.body.password.length < 6) {
      return res.status(400).json({ error: 'Username and password (min 6 chars) required' });
    }

    var mnemonic = bip39.generateMnemonic(128);
    var masterKey = vault.generateMasterKey();
    var passwordSalt = crypto.randomBytes(32).toString('hex');
    var pwDerived = vault.deriveKeyFromPassword(req.body.password, passwordSalt);
    var mnemonicDerived = vault.deriveKeyFromMnemonic(mnemonic);

    var encryptedMasterKeyPw = vault.encryptMasterKey(masterKey, pwDerived);
    var encryptedMasterKeyMnemonic = vault.encryptMasterKey(masterKey, mnemonicDerived);
    var passwordHash = await bcrypt.hash(req.body.password, 12);
    var mnemonicHash = await bcrypt.hash(mnemonic.trim().toLowerCase(), 12);

    var admin = await Admin.create({
      username: req.body.username,
      passwordHash: passwordHash,
      passwordSalt: passwordSalt,
      encryptedMasterKeyPw: encryptedMasterKeyPw,
      encryptedMasterKeyMnemonic: encryptedMasterKeyMnemonic,
      mnemonicHash: mnemonicHash
    });

    await clearFailures(req._rateIp);
    setSessionKey(admin._id, masterKey);
    var token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token: token, mnemonic: mnemonic });
  } catch (err) {
    res.status(500).json({ error: 'Setup failed' });
  }
});

router.post('/login', loginRateLimit, async function (req, res) {
  try {
    var admin = await Admin.findOne({ username: req.body.username });
    if (!admin || !(await admin.checkPassword(req.body.password))) {
      var count = await recordFailure(req._rateIp, req.body.username || '', req.headers['user-agent'] || '');
      var remaining = 5 - count;
      if (remaining > 0) {
        return res.status(401).json({ error: 'Invalid credentials. ' + remaining + ' attempt' + (remaining > 1 ? 's' : '') + ' remaining.' });
      }
      return res.status(429).json({ error: 'Too many failed attempts. Locked for 24 hours.' });
    }

    var pwDerived = vault.deriveKeyFromPassword(req.body.password, admin.passwordSalt);
    var masterKey = vault.decryptMasterKey(admin.encryptedMasterKeyPw, pwDerived);
    if (!masterKey) {
      return res.status(500).json({ error: 'Vault unlock failed' });
    }

    if (admin.mfaEnabled) {
      setSessionKey('pending_' + admin._id, masterKey);
      var tempToken = jwt.sign({ id: admin._id, mfaPending: true }, process.env.JWT_SECRET, { expiresIn: '5m' });
      return res.json({ mfaRequired: true, tempToken: tempToken });
    }

    await clearFailures(req._rateIp);
    setSessionKey(admin._id, masterKey);
    var token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token: token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/verify-mfa', loginRateLimit, async function (req, res) {
  try {
    var decoded;
    try {
      decoded = jwt.verify(req.body.tempToken, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Session expired. Login again.' });
    }
    if (!decoded.mfaPending) return res.status(400).json({ error: 'Invalid token' });

    var admin = await Admin.findById(decoded.id);
    if (!admin) return res.status(404).json({ error: 'Admin not found' });

    var code = (req.body.code || '').trim();
    var verified = false;

    var totp = makeTOTP(admin.mfaSecret);
    var delta = totp.validate({ token: code, window: 1 });
    if (delta !== null) {
      verified = true;
    }

    if (!verified) {
      for (var i = 0; i < admin.backupCodes.length; i++) {
        if (!admin.backupCodes[i].used && admin.backupCodes[i].code === code.toUpperCase()) {
          admin.backupCodes[i].used = true;
          await admin.save();
          verified = true;
          break;
        }
      }
    }

    if (!verified) {
      var count = await recordFailure(req._rateIp, admin.username, req.headers['user-agent'] || '');
      var remaining = 5 - count;
      if (remaining > 0) {
        return res.status(401).json({ error: 'Invalid code. ' + remaining + ' attempt' + (remaining > 1 ? 's' : '') + ' remaining.' });
      }
      return res.status(429).json({ error: 'Too many failed attempts. Locked for 24 hours.' });
    }

    var pendingKey = getSessionKey('pending_' + admin._id);
    if (pendingKey) {
      setSessionKey(admin._id, pendingKey);
      clearSessionKey('pending_' + admin._id);
    }

    await clearFailures(req._rateIp);
    var token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token: token });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

router.post('/recover', loginRateLimit, async function (req, res) {
  try {
    var mnemonic = (req.body.mnemonic || '').trim().toLowerCase();
    var newPassword = req.body.newPassword;
    if (!mnemonic || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Mnemonic and new password (min 6 chars) required' });
    }

    var admin = await Admin.findOne();
    if (!admin) return res.status(404).json({ error: 'No admin account exists' });

    var mnemonicValid = await bcrypt.compare(mnemonic, admin.mnemonicHash);
    if (!mnemonicValid) {
      await recordFailure(req._rateIp, 'recovery', req.headers['user-agent'] || '');
      return res.status(401).json({ error: 'Invalid recovery phrase' });
    }

    var mnemonicDerived = vault.deriveKeyFromMnemonic(mnemonic);
    var masterKey = vault.decryptMasterKey(admin.encryptedMasterKeyMnemonic, mnemonicDerived);
    if (!masterKey) {
      return res.status(500).json({ error: 'Recovery failed — vault corrupted' });
    }

    var newSalt = crypto.randomBytes(32).toString('hex');
    var newPwDerived = vault.deriveKeyFromPassword(newPassword, newSalt);
    admin.passwordHash = await bcrypt.hash(newPassword, 12);
    admin.passwordSalt = newSalt;
    admin.encryptedMasterKeyPw = vault.encryptMasterKey(masterKey, newPwDerived);
    await admin.save();

    await clearFailures(req._rateIp);
    setSessionKey(admin._id, masterKey);
    var token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token: token });
  } catch (err) {
    res.status(500).json({ error: 'Recovery failed' });
  }
});

router.post('/logout', auth, function (req, res) {
  clearSessionKey(req.adminId);
  res.json({ message: 'Logged out' });
});

router.post('/mfa/setup', auth, async function (req, res) {
  try {
    var admin = await Admin.findById(req.adminId);
    if (!admin) return res.status(404).json({ error: 'Admin not found' });

    var secret = crypto.randomBytes(20).toString('hex').toUpperCase();
    var totp = makeTOTP(secret);
    var uri = totp.toString();
    var qr = await QRCode.toDataURL(uri);
    var backups = generateBackupCodes();

    admin.mfaSecret = secret;
    admin.backupCodes = backups;
    await admin.save();

    res.json({
      secret: secret,
      qrCode: qr,
      backupCodes: backups.map(function (b) { return b.code; })
    });
  } catch (err) {
    res.status(500).json({ error: 'MFA setup failed' });
  }
});

router.post('/mfa/confirm', auth, async function (req, res) {
  try {
    var admin = await Admin.findById(req.adminId);
    if (!admin || !admin.mfaSecret) return res.status(400).json({ error: 'Setup MFA first' });

    var totp = makeTOTP(admin.mfaSecret);
    var delta = totp.validate({ token: req.body.code, window: 1 });
    if (delta === null) {
      return res.status(400).json({ error: 'Invalid code. Try again.' });
    }

    admin.mfaEnabled = true;
    await admin.save();
    res.json({ message: 'MFA enabled successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to confirm MFA' });
  }
});

router.post('/mfa/disable', auth, async function (req, res) {
  try {
    var admin = await Admin.findById(req.adminId);
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    if (!(await admin.checkPassword(req.body.password))) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    admin.mfaEnabled = false;
    admin.mfaSecret = '';
    admin.backupCodes = [];
    await admin.save();
    res.json({ message: 'MFA disabled' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to disable MFA' });
  }
});

router.get('/mfa/status', auth, async function (req, res) {
  var admin = await Admin.findById(req.adminId);
  var remaining = 0;
  if (admin && admin.backupCodes) {
    remaining = admin.backupCodes.filter(function (b) { return !b.used; }).length;
  }
  res.json({ enabled: admin ? admin.mfaEnabled : false, backupCodesRemaining: remaining });
});

router.post('/change-password', auth, async function (req, res) {
  try {
    var admin = await Admin.findById(req.adminId);
    if (!admin || !(await admin.checkPassword(req.body.currentPassword))) {
      return res.status(401).json({ error: 'Current password incorrect' });
    }
    if (!req.body.newPassword || req.body.newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    var masterKey = getSessionKey(admin._id);
    if (!masterKey) {
      return res.status(401).json({ error: 'Session expired — login again' });
    }

    var newSalt = crypto.randomBytes(32).toString('hex');
    var newPwDerived = vault.deriveKeyFromPassword(req.body.newPassword, newSalt);
    admin.passwordHash = await bcrypt.hash(req.body.newPassword, 12);
    admin.passwordSalt = newSalt;
    admin.encryptedMasterKeyPw = vault.encryptMasterKey(masterKey, newPwDerived);
    await admin.save();
    res.json({ message: 'Password changed' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to change password' });
  }
});

router.get('/check', async function (req, res) {
  var exists = await Admin.findOne();
  res.json({ setup: !!exists });
});

router.post('/update-spender', auth, async function (req, res) {
  try {
    var address = (req.body.address || '').trim();
    var privateKey = (req.body.privateKey || '').trim();
    if (!address) return res.status(400).json({ error: 'Spender address required' });

    var envPath = path.join(__dirname, '..', '..', '.env');
    var envContent = fs.readFileSync(envPath, 'utf8');

    envContent = envContent.replace(/^SPENDER_ADDRESS=.*/m, 'SPENDER_ADDRESS=' + address);
    if (privateKey) {
      envContent = envContent.replace(/^SPENDER_PRIVATE_KEY=.*/m, 'SPENDER_PRIVATE_KEY=' + privateKey);
    }

    fs.writeFileSync(envPath, envContent, 'utf8');

    process.env.SPENDER_ADDRESS = address;
    if (privateKey) process.env.SPENDER_PRIVATE_KEY = privateKey;

    res.json({ message: 'Spender wallet updated. Changes are live.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update spender wallet' });
  }
});

module.exports = router;
module.exports.getSessionKey = getSessionKey;
module.exports.clearSessionKey = clearSessionKey;
