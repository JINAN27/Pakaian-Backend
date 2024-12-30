const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  products: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true },
  }],
  totalAmount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['belum dibayar', 'sudah dibayar', 'sedang dikirim', 'selesai'], 
    default: 'belum dibayar' 
  },
  bankDetails: {
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true }
  },
  shippingDetails: {
    province: { type: String },
    city: { type: String },
    district: { type: String },
    cost: { type: Number },
    address: { type: String },
    postalCode: { type: String }
  },
  createdAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

module.exports = Order;