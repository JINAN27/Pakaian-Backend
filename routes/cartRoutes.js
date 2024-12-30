// routes/cartRoutes.js
const express = require('express');
const router = express.Router();
const CartController = require('../controllers/CartController');

// Menambah produk ke dalam keranjang
router.post('/add', CartController.addToCart);
 
// Mendapatkan keranjang berdasarkan userId
router.get('/:userId', CartController.getCart);

// Menghapus produk dari keranjang
router.delete('/remove', CartController.removeFromCart);

// Memperbarui kuantitas produk di keranjang
router.put('/update', CartController.updateCart);

module.exports = router;
