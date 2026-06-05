const Transaction = require('../models/Transaction');
const User = require('../models/User');
const { sendResponse, sendError } = require('../utils/responseHelper');

// @desc    Get transaction history
// @route   GET /api/payments/history
const getHistory = async (req, res) => {
  try {
    const transactions = await Transaction.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    sendResponse(res, 200, true, 'Transaction history fetched', { transactions });
  } catch (error) {
    console.error('GetHistory Error:', error);
    sendError(res, 500, 'Server error');
  }
};

// @desc    Request withdrawal
// @route   POST /api/payments/withdraw
const requestWithdrawal = async (req, res) => {
  try {
    const { amount, paymentMethod, accountNumber } = req.body;

    if (amount < 100) {
      return sendError(res, 400, 'Minimum withdrawal amount is ৳100');
    }

    const user = await User.findById(req.user._id);
    if (user.balance < amount) {
      return sendError(res, 400, 'Insufficient balance');
    }

    const transaction = await Transaction.create({
      user: req.user._id,
      type: 'withdrawal',
      amount,
      paymentMethod,
      status: 'pending',
      description: `Withdrawal request via ${paymentMethod}`,
      metadata: { accountNumber }
    });

    user.balance -= amount;
    await user.save();

    sendResponse(res, 201, true, 'Withdrawal request submitted', { transaction });
  } catch (error) {
    console.error('Withdrawal Error:', error);
    sendError(res, 500, 'Server error');
  }
};

module.exports = { getHistory, requestWithdrawal };