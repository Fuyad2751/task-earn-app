const User = require('../models/User');
const { generateToken } = require('../utils/jwtHelper');
const { sendResponse, sendError } = require('../utils/responseHelper');
const { validationResult } = require('express-validator');

const register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 400, errors.array()[0].msg);
    }

    const { fullName, email, phone, password, referralCode } = req.body;

    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return sendError(res, 400, 'User already exists with this email');
    }

    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findByReferralCode(referralCode);
      if (referrer) {
        referredBy = referrer.id;
      }
    }

    const user = await User.create({ fullName, email, phone, password, referredBy });
    const token = generateToken(user.id);

    sendResponse(res, 201, true, 'Registration successful', {
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        totalEarnings: user.total_earnings,
        completedTasks: user.completed_tasks,
        referralCode: user.referral_code,
        role: user.role
      },
      token
    });
  } catch (error) {
    console.error('Register Error:', error);
    sendError(res, 500, 'Server error during registration');
  }
};

const login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, 400, errors.array()[0].msg);
    }

    const { email, password } = req.body;

    const user = await User.findByEmail(email);
    if (!user) {
      return sendError(res, 401, 'Invalid email or password');
    }

    const isMatch = await User.comparePassword(password, user.password);
    if (!isMatch) {
      return sendError(res, 401, 'Invalid email or password');
    }

    await User.updateLastLogin(user.id);
    const token = generateToken(user.id);

    sendResponse(res, 200, true, 'Login successful', {
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        totalEarnings: user.total_earnings,
        completedTasks: user.completed_tasks,
        referralCode: user.referral_code,
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

const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
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