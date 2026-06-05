const express = require('express');
const router = express.Router();
const { register, login, getProfile } = require('../controllers/authController');
const { registerValidator, loginValidator } = require('../validators/authValidator');
const { protect } = require('../middlewares/authMiddleware');

// Register route
router.post('/register', registerValidator, register);

// Login route
router.post('/login', loginValidator, login);

// Get profile route (protected)
router.get('/profile', protect, getProfile);

module.exports = router;