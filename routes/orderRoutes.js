const express = require('express');
const router = express.Router();
const { createOrder, getOrder, updatePaymentStatus } = require('../controllers/orderController');

router.post('/orders', createOrder);
router.get('/orders/:orderId', getOrder);
router.put('/orders/:orderId/payment-status', updatePaymentStatus);

module.exports = router;