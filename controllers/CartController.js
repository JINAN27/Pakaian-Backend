// controllers/CartController.js
const Cart = require('../models/Cart');
const Product = require('../models/Product');

// Menambah produk ke dalam keranjang
exports.addToCart = async (req, res) => {
  const { userId, productId, quantity } = req.body;

  if (quantity <= 0) {
    return res.status(400).json({ message: 'Quantity must be greater than zero' });
  }

  try {
    // Cari produk berdasarkan ID
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Pastikan stok mencukupi
    if (product.stock < quantity) {
      return res.status(400).json({ message: 'Insufficient stock for the requested quantity' });
    }

    // Cari keranjang pengguna
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      // Jika keranjang tidak ada, buat keranjang baru
      cart = new Cart({
        userId,
        items: [{ productId, quantity }],
      });
    } else {
      // Jika keranjang sudah ada, periksa apakah produk sudah ada
      const itemIndex = cart.items.findIndex((item) => item.productId.toString() === productId);

      if (itemIndex > -1) {
        // Jika produk sudah ada, tambahkan kuantitasnya
        cart.items[itemIndex].quantity += quantity;
      } else {
        // Jika produk belum ada, tambahkan produk baru ke dalam keranjang
        cart.items.push({ productId, quantity });
      }
    }

    await cart.save();
    res.status(201).json(cart);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// Mendapatkan keranjang berdasarkan userId
exports.getCart = async (req, res) => {
  const { userId } = req.params;

  try {
    const cart = await Cart.findOne({ userId }).populate('items.productId', 'name price stock'); // Populate produk untuk mengambil detail produk

    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    res.status(200).json(cart);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// Menghapus produk dari keranjang
exports.removeFromCart = async (req, res) => {
  const { userId, productId } = req.body;

  try {
    const cart = await Cart.findOne({ userId });

    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    const itemIndex = cart.items.findIndex((item) => item.productId.toString() === productId);

    if (itemIndex === -1) {
      return res.status(404).json({ message: 'Product not found in cart' });
    }

    // Hapus produk dari keranjang
    cart.items.splice(itemIndex, 1);
    await cart.save();

    res.status(200).json({ message: 'Product removed from cart', cart });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// Memperbarui kuantitas produk di keranjang
exports.updateCart = async (req, res) => {
  const { userId, productId, quantity } = req.body;

  if (quantity <= 0) {
    return res.status(400).json({ message: 'Quantity must be greater than zero' });
  }

  try {
    const cart = await Cart.findOne({ userId });

    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    const itemIndex = cart.items.findIndex((item) => item.productId.toString() === productId);

    if (itemIndex === -1) {
      return res.status(404).json({ message: 'Product not found in cart' });
    }

    // Update kuantitas produk
    cart.items[itemIndex].quantity = quantity;
    await cart.save();

    res.status(200).json({ message: 'Cart updated successfully', cart });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};
