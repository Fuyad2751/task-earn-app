const express = require('express');
const router = express.Router();
const { protect } = require('../middlewares/authMiddleware');
const { getPackages } = require('../controllers/packageController');

router.get('/', protect, getPackages);

module.exports = router;