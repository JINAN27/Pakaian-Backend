const express = require('express');
const router = express.Router();

const { 
  getProvinces, 
  getCities, 
  getDistricts, 
  calculateShippingCost,
  confirmShipping
} = require('../controllers/shippingController');

router.get('/provinces', getProvinces);
router.get('/cities/:provinceId', getCities);
router.get('/districts/:cityId', getDistricts);
router.post('/shipping-cost/:orderId', calculateShippingCost);
router.post('/orders/:orderId/confirm-shipping', confirmShipping);

module.exports = router;