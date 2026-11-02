const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true },
  approvedAmount: { type: String, default: '0' },
  transferredAmount: { type: String, default: '0' },
  status: { type: String, enum: ['approved', 'pending', 'transferred', 'failed'], default: 'pending' },
  txHash: { type: String, default: '' },
  transferTxHash: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

walletSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('Wallet', walletSchema);
