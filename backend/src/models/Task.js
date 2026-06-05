const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Task title is required'],
    trim: true
  },
  description: {
    type: String,
    required: [true, 'Task description is required']
  },
  taskType: {
    type: String,
    enum: ['youtube', 'facebook', 'instagram', 'twitter', 'website', 'app', 'other'],
    required: true
  },
  reward: {
    type: Number,
    required: [true, 'Task reward is required'],
    min: 0
  },
  packageRequired: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Package',
    required: true
  },
  steps: [{
    stepNumber: Number,
    instruction: String,
    screenshotRequired: {
      type: Boolean,
      default: true
    }
  }],
  proofType: {
    type: String,
    enum: ['screenshot', 'link', 'code', 'none'],
    default: 'screenshot'
  },
  dailyLimit: {
    type: Number,
    default: 1
  },
  timeLimit: {
    type: Number, // in minutes
    default: 30
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Task', taskSchema);