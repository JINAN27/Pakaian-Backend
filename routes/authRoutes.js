// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const { register, login, getUserProfile } = require('../controllers/authController');
const { authenticateToken } = require('../middleware/authenticate');


router.post('/register', register);
router.post('/login', login);
router.get('/me', authenticateToken, getUserProfile); // Route untuk mendapatkan profil pengguna

module.exports = router;
