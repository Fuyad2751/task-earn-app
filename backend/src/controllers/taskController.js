const Task = require('../models/Task');
const UserTask = require('../models/UserTask');
const User = require('../models/User');
const { sendResponse, sendError } = require('../utils/responseHelper');

// @desc    Get all tasks
// @route   GET /api/tasks
const getTasks = async (req, res) => {
  try {
    const tasks = await Task.find({ isActive: true });
    sendResponse(res, 200, true, 'Tasks fetched successfully', { tasks });
  } catch (error) {
    console.error('GetTasks Error:', error);
    sendError(res, 500, 'Server error');
  }
};

// @desc    Submit a task
// @route   POST /api/tasks/submit
const submitTask = async (req, res) => {
  try {
    const { taskId, proof } = req.body;

    const task = await Task.findById(taskId);
    if (!task) {
      return sendError(res, 404, 'Task not found');
    }

    const userTask = await UserTask.create({
      user: req.user._id,
      task: taskId,
      proof,
      status: 'submitted',
      submittedAt: new Date(),
      reward: task.reward
    });

    sendResponse(res, 201, true, 'Task submitted successfully', { userTask });
  } catch (error) {
    console.error('SubmitTask Error:', error);
    sendError(res, 500, 'Server error');
  }
};

module.exports = { getTasks, submitTask };