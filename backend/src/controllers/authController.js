const User = require('../models/User');
const { generateToken } = require('../utils/jwtHelper');
const { sendResponse, sendError } = require('../utils/responseHelper');
const { validationResult } = require('express-validator');

// @desc    Register user
// @route   POST /api/auth/register
const register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 400, errors.array()[0].msg);
    }

    const { fullName, email, phone, password, referralCode } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return sendError(res, 400, 'User already exists with this email or phone');
    }

    const userData = { fullName, email, phone, password };

    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        userData.referredBy = referrer._id;
      }
    }

    const user = await User.create(userData);
    const token = generateToken(user._id);

    sendResponse(res, 201, true, 'Registration successful', {
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        totalEarnings: user.totalEarnings,
        completedTasks: user.completedTasks,
        referralCode: user.referralCode,
        role: user.role
      },
      token
    });
  } catch (error) {
    console.error('Register Error:', error);
    sendError(res, 500, 'Server error during registration');
  }
};

// @desc    Login user
// @route   POST /api/auth/login
const login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 400, errors.array()[0].msg);
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return sendError(res, 401, 'Invalid email or password');
    }

    if (!user.isActive) {
      return sendError(res, 401, 'Account is deactivated. Contact support.');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return sendError(res, 401, 'Invalid email or password');
    }

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id);

    sendResponse(res, 200, true, 'Login successful', {
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        totalEarnings: user.totalEarnings,
        completedTasks: user.completedTasks,
        referralCode: user.referralCode,
        role: user.role,
        avatar: user.avatar
      },
      token
    });
  } catch (error) {
    console.error('Login Error:', error);
    sendError(res, 500, 'Server error during login');
  }
};

// @desc    Get current user profile
// @route   GET /api/auth/profile
const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('activePackage');
    if (!user) {
      return sendError(res, 404, 'User not found');
    }
    sendResponse(res, 200, true, 'Profile fetched successfully', { user });
  } catch (error) {
    console.error('GetProfile Error:', error);
    sendError(res, 500, 'Server error');
  }
};

module.exports = { register, login, getProfile };