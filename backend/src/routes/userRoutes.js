const express = require('express');
const router = express.Router();
const { protect } = require('../middlewares/authMiddleware');
const User = require('../models/User');
const { sendResponse, sendError } = require('../utils/responseHelper');

// Get dashboard stats
router.get('/dashboard', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('activePackage')
      .select('-password');

    sendResponse(res, 200, true, 'Dashboard data fetched', {
      user,
      stats: {
        balance: user.balance,
        totalEarnings: user.totalEarnings,
        completedTasks: user.completedTasks
      }
    });
  } catch (error) {
    sendError(res, 500, 'Server error');
  }
});

// Update profile
router.put('/profile', protect, async (req, res) => {
  try {
    const { fullName, phone } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { fullName, phone },
      { new: true }
    );
    sendResponse(res, 200, true, 'Profile updated', { user });
  } catch (error) {
    sendError(res, 500, 'Server error');
  }
});

module.exports = router;