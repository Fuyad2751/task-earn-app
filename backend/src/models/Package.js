const mongoose = require('mongoose');

const packageSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Package name is required'],
    trim: true
  },
  description: {
    type: String,
    required: [true, 'Package description is required']
  },
  price: {
    type: Number,
    required: [true, 'Package price is required'],
    min: 0
  },
  dailyTaskLimit: {
    type: Number,
    required: true,
    default: 5
  },
  dailyEarningLimit: {
    type: Number,
    required: true,
    default: 100
  },
  referralBonus: {
    type: Number,
    default: 10
  },
  features: [{
    type: String
  }],
  duration: {
    type: Number, // in days
    default: 30
  },
  isActive: {
    type: Boolean,
    default: true
  },
  color: {
    type: String,
    default: '#007bff'
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Package', packageSchema);