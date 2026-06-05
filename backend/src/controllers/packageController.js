const Package = require('../models/Package');
const { sendResponse, sendError } = require('../utils/responseHelper');

// @desc    Get all packages
// @route   GET /api/packages
const getPackages = async (req, res) => {
  try {
    const packages = await Package.find({ isActive: true });
    sendResponse(res, 200, true, 'Packages fetched successfully', { packages });
  } catch (error) {
    console.error('GetPackages Error:', error);
    sendError(res, 500, 'Server error');
  }
};

module.exports = { getPackages };