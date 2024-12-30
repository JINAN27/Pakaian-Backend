const Product = require('../models/Product');
const ShippingCost = require('../models/ShippingCost');

// Fungsi untuk membuat invoice
exports.createInvoice = async (req, res) => {
  const { productId, quantity, province, city, district } = req.body;

  try {
    // Mendapatkan data produk
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Mendapatkan ongkir berdasarkan wilayah
    const shippingCost = await ShippingCost.findOne({ province, city, district });
    if (!shippingCost) {
      return res.status(404).json({ message: 'Shipping cost not found' });
    }

    // Menghitung total
    const totalProductPrice = product.price * quantity;
    const totalCost = totalProductPrice + shippingCost.cost;

    // Membuat invoice
    const invoice = {
      productId: product._id,
      name: product.name,
      price: product.price,
      description: product.description,
      quantity,
      shippingCost: shippingCost.cost,
      total: totalCost,
    };

    res.status(200).json({ invoice });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};
