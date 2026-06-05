const express = require('express');
const router = express.Router();
const { protect } = require('../middlewares/authMiddleware');
const { getTasks, submitTask } = require('../controllers/taskController');

router.get('/', protect, getTasks);
router.post('/submit', protect, submitTask);

module.exports = router;