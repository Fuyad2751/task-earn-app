const express = require('express');
const router = express.Router();
const { protect } = require('../middlewares/authMiddleware');
const { getHistory, requestWithdrawal } = require('../controllers/paymentController');

router.get('/history', protect, getHistory);
router.post('/withdraw', protect, requestWithdrawal);

module.exports = router;