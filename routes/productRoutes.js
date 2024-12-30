const express = require('express');
const router = express.Router();
const productController = require('../controllers/productController');
const multer = require('multer');

// Konfigurasi multer untuk menyimpan gambar di folder 'uploads/'
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');  // Tempat penyimpanan gambar
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);  // Menamai file dengan timestamp agar unik
  }
});

const upload = multer({ storage: storage });

// Mendapatkan semua produk
router.get('/', productController.getAllProducts);

// Mendapatkan produk berdasarkan ID
router.get('/:id', productController.getProductById);

// Menambahkan produk baru dengan gambar
router.post('/', upload.single('image'), productController.createProduct);

// Memperbarui produk berdasarkan ID dengan gambar (optional)
router.put('/:id', upload.single('image'), productController.updateProduct);

// Menghapus produk berdasarkan ID
router.delete('/:id', productController.deleteProduct);

module.exports = router;
