const express = require('express');
const router = express.Router();
const { createInvoice } = require('../controllers/invoiceController');

// Endpoint untuk membuat invoice
router.post('/create-invoice', createInvoice);

module.exports = router;
