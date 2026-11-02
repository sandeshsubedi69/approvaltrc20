const express = require('express');
const auth = require('../middleware/auth');
const { encode } = require('../linkCodec');

const router = express.Router();

router.post('/generate', auth, function (req, res) {
  var amount = parseFloat(req.body.amount);
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valid amount required' });
  }
  var slug = encode(amount, process.env.LINK_SECRET);
  res.json({ slug: slug, url: '/' + slug });
});

module.exports = router;
