const Product = require('../models/Product');  // Import model produk

// Fungsi untuk membuat produk
exports.createProduct = async (req, res) => {
  try {
    const { name, price, description, stock, size, color, brand } = req.body;
    let imageUrl = null;

    // Jika gambar di-upload, simpan URL gambar
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    }

    // Validasi stock
    if (stock < 0) {
      return res.status(400).json({ message: "Stock cannot be negative" });
    }

    const newProduct = new Product({
      name,
      price,
      description,
      stock,
      size,
      color,
      brand,
      image: imageUrl,  // Simpan URL gambar
    });

    // Simpan produk ke MongoDB
    await newProduct.save();

    res.status(201).json({
      message: 'Product created successfully',
      product: newProduct,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Fungsi untuk mendapatkan semua produk
exports.getAllProducts = async (req, res) => {
  try {
    const products = await Product.find(); // Ambil semua produk
    res.status(200).json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Fungsi untuk mendapatkan produk berdasarkan ID
exports.getProductById = async (req, res) => {
  const { id } = req.params; // Ambil ID produk dari parameter URL

  try {
    const product = await Product.findById(id); // Cari produk berdasarkan ID
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.status(200).json(product); // Kirimkan data produk
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Fungsi untuk memperbarui produk berdasarkan ID
exports.updateProduct = async (req, res) => {
  const { id } = req.params;
  const { name, price, description, stock, size, color, brand } = req.body;
  let imageUrl = null;

  // Jika gambar di-upload, simpan URL gambar
  if (req.file) {
    imageUrl = `/uploads/${req.file.filename}`;
  }

  try {
    // Validasi stock
    if (stock < 0) {
      return res.status(400).json({ message: "Stock cannot be negative" });
    }

    // Cari produk berdasarkan ID dan perbarui dengan data baru
    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      {
        name,
        price,
        description,
        stock,
        size,
        color,
        brand,
        image: imageUrl,  // Update gambar jika ada
      },
      { new: true } // Mengembalikan produk yang sudah diperbarui
    );

    if (!updatedProduct) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json({
      message: 'Product updated successfully',
      product: updatedProduct,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Fungsi untuk menghapus produk berdasarkan ID
exports.deleteProduct = async (req, res) => {
  const { id } = req.params; // Ambil ID produk dari parameter URL

  try {
    // Hapus produk berdasarkan ID
    const deletedProduct = await Product.findByIdAndDelete(id);

    if (!deletedProduct) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json({
      message: 'Product deleted successfully',
      product: deletedProduct,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};
