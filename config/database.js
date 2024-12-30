const mongoose = require('mongoose');
require('dotenv').config(); // Pastikan dotenv di-load

const connectDB = async () => {
  try {
    // Menggunakan DB_URI dari file .env
    await mongoose.connect(process.env.DB_URI);
    console.log('MongoDB connected');
  } catch (err) {
    console.error('Database connection error:', err.message);
    process.exit(1); // Menghentikan aplikasi jika gagal
  }
};

module.exports = connectDB;
