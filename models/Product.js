const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,  // Nama produk wajib diisi
  },
  price: {
    type: Number,
    required: true,  // Harga produk wajib diisi
  },
  description: {
    type: String,
    required: false, // Deskripsi produk opsional
  },
  stock: {  
    type: Number,
    required: true,  // Pastikan stock selalu diisi
    default: 0,      // Set default ke 0 jika tidak diisi
  },
  size: {           // Menambahkan field ukuran produk
    type: String,
    required: false, // Ukuran produk opsional
  },
  color: {          // Menambahkan field warna produk
    type: String,
    required: false, // Warna produk opsional
  },
  brand: {          // Menambahkan field merk produk
    type: String,
    required: false, // Merk produk opsional
  },
  image: {           // Menambahkan field untuk gambar produk
    type: String,
    required: false, // Gambar produk opsional
  },
});

const Product = mongoose.model('Product', productSchema);

module.exports = Product;
