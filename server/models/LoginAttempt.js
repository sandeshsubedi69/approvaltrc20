const mongoose = require('mongoose');

const loginAttemptSchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true },
  failures: { type: Number, default: 0 },
  lockedUntil: { type: Date, default: null },
  attempts: [{
    timestamp: { type: Date, default: Date.now },
    username: String,
    userAgent: String,
    blocked: { type: Boolean, default: false }
  }]
});

loginAttemptSchema.index({ lockedUntil: 1 }, { expireAfterSeconds: 86400 });

module.exports = mongoose.model('LoginAttempt', loginAttemptSchema);
