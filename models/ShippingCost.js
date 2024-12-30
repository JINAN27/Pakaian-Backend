const mongoose = require('mongoose');

const shippingCostSchema = new mongoose.Schema({
  province: {
    type: String,
    required: true,
  },
  city: {
    type: String,
    required: true,
  },
  district: {
    type: String,
    required: true,
  },
  cost: {
    type: Number,
    required: true,
  },
});

module.exports = mongoose.model('ShippingCost', shippingCostSchema);
