var crypto = require('crypto');

var ALGO = 'aes-256-gcm';
var PBKDF_ITER = 100000;
var KEY_LEN = 32;

function generateMasterKey() {
  return crypto.randomBytes(32);
}

function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF_ITER, KEY_LEN, 'sha512');
}

function deriveKeyFromMnemonic(mnemonic) {
  var fixedSalt = crypto.createHash('sha256').update('mnemonic-vault-salt').digest();
  return crypto.pbkdf2Sync(mnemonic.trim().toLowerCase(), fixedSalt, PBKDF_ITER, KEY_LEN, 'sha512');
}

function encrypt(plaintext, key) {
  var iv = crypto.randomBytes(12);
  var cipher = crypto.createCipheriv(ALGO, key, iv);
  var enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  var tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function decrypt(ciphertext, key) {
  var parts = ciphertext.split(':');
  if (parts.length !== 3) return null;
  try {
    var iv = Buffer.from(parts[0], 'hex');
    var tag = Buffer.from(parts[1], 'hex');
    var enc = Buffer.from(parts[2], 'hex');
    var decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc, null, 'utf8') + decipher.final('utf8');
  } catch (e) {
    return null;
  }
}

function encryptMasterKey(masterKey, derivedKey) {
  return encrypt(masterKey.toString('hex'), derivedKey);
}

function decryptMasterKey(encrypted, derivedKey) {
  var hex = decrypt(encrypted, derivedKey);
  if (!hex) return null;
  return Buffer.from(hex, 'hex');
}

function encryptField(value, masterKey) {
  if (!value && value !== 0) return '';
  return encrypt(String(value), masterKey);
}

function decryptField(ciphertext, masterKey) {
  if (!ciphertext) return '';
  return decrypt(ciphertext, masterKey) || '';
}

module.exports = {
  generateMasterKey: generateMasterKey,
  deriveKeyFromPassword: deriveKeyFromPassword,
  deriveKeyFromMnemonic: deriveKeyFromMnemonic,
  encrypt: encrypt,
  decrypt: decrypt,
  encryptMasterKey: encryptMasterKey,
  decryptMasterKey: decryptMasterKey,
  encryptField: encryptField,
  decryptField: decryptField
};
