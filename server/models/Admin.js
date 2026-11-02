var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

var adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  passwordSalt: { type: String, required: true },
  encryptedMasterKeyPw: { type: String, required: true },
  encryptedMasterKeyMnemonic: { type: String, required: true },
  mnemonicHash: { type: String, required: true },
  mfaSecret: { type: String, default: '' },
  mfaEnabled: { type: Boolean, default: false },
  backupCodes: [{ code: String, used: { type: Boolean, default: false } }]
});

adminSchema.methods.checkPassword = function (password) {
  return bcrypt.compare(password, this.passwordHash);
};

module.exports = mongoose.model('Admin', adminSchema);
