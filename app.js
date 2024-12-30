// app.js
const express = require('express');
const connectDB = require('./config/database');
const productRoutes = require('./routes/productRoutes');
const cartRoutes = require('./routes/cartRoutes'); // Pastikan hanya ini yang digunakan
const authRoutes = require('./routes/authRoutes');
const shippingRoutes = require('./routes/shippingRoutes');
const invoiceRoutes = require('./routes/invoiceRoutes');
const orderRoutes = require('./routes/orderRoutes'); 
const cors = require('cors');

require('dotenv').config();

const app = express();

// Koneksi ke database
connectDB();

// Middleware untuk parsing JSON
app.use(express.json());

app.use(cors());

// Middleware untuk mengakses folder uploads
app.use('/uploads', express.static('uploads')); // Menyajikan file di folder uploads

// Rute untuk produk
app.use('/api/products', productRoutes);

// Rute untuk cart
app.use('/api/cart', cartRoutes);  // Gunakan hanya satu rute untuk cart

// Rute untuk autentikasi
app.use('/api/auth', authRoutes);

// Rute tambahan lainnya
app.use('/api', shippingRoutes);
app.use('/api', invoiceRoutes);
app.use('/api', orderRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
