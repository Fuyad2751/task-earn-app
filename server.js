const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
const pool = new Pool({ connectionString: process.env.DB_URL });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

async function isAdmin(req, res, next) {
  const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.user.id]);
  if (user.rows[0]?.role === 'admin') return next();
  res.status(403).json({ error: 'Admin only' });
}

app.post('/api/register', async (req, res) => {
  const { username, password, mobile, referralCode } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const refCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  let referrerId = null;
  if (referralCode) {
    const refUser = await pool.query('SELECT id FROM users WHERE referral_code=$1', [referralCode]);
    if (refUser.rows[0]) referrerId = refUser.rows[0].id;
  }
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, mobile, referral_code, referrer_id) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [username, hashed, mobile, refCode, referrerId]
    );
    const token = jwt.sign({ id: result.rows[0].id, username }, process.env.JWT_SECRET);
    res.json({ token, username });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await pool.query('SELECT id, username, password_hash, status FROM users WHERE username=$1', [username]);
  if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.rows[0].status === 'blocked') return res.status(403).json({ error: 'Account blocked' });
  const match = await bcrypt.compare(password, user.rows[0].password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.rows[0].id, username }, process.env.JWT_SECRET);
  res.json({ token, username: user.rows[0].username });
});

app.get('/api/packages', async (req, res) => {
  const packages = await pool.query('SELECT * FROM level_packages ORDER BY level');
  res.json(packages.rows);
});

app.get('/api/my-tasks', authenticate, async (req, res) => {
  const user = await pool.query('SELECT level FROM users WHERE id=$1', [req.user.id]);
  const userLevel = user.rows[0].level;
  const tasks = await pool.query('SELECT * FROM tasks WHERE level=$1', [userLevel]);
  const today = new Date().toISOString().slice(0,10);
  const completed = await pool.query(
    'SELECT task_id FROM user_daily_tasks WHERE user_id=$1 AND completed_date=$2',
    [req.user.id, today]
  );
  const completedIds = completed.rows.map(r => r.task_id);
  const tasksWithStatus = tasks.rows.map(t => ({ ...t, completed: completedIds.includes(t.id) }));
  res.json(tasksWithStatus);
});

app.post('/api/complete-task', authenticate, async (req, res) => {
  const { taskId } = req.body;
  const userId = req.user.id;
  const today = new Date().toISOString().slice(0,10);
  
  const task = await pool.query('SELECT level FROM tasks WHERE id=$1', [taskId]);
  if (task.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
  const taskLevel = task.rows[0].level;
  
  const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
  if (user.rows[0].level < taskLevel) return res.status(403).json({ error: 'Level mismatch' });
  
  const done = await pool.query(
    'SELECT id FROM user_daily_tasks WHERE user_id=$1 AND task_id=$2 AND completed_date=$3',
    [userId, taskId, today]
  );
  if (done.rows.length) return res.status(400).json({ error: 'Task already completed today' });
  
  const pkg = await pool.query('SELECT task_rate FROM level_packages WHERE level=$1', [taskLevel]);
  const rate = parseFloat(pkg.rows[0].task_rate);
  
  await pool.query(
    'INSERT INTO user_daily_tasks (user_id, task_id, completed_date, earned) VALUES ($1,$2,$3,$4)',
    [userId, taskId, today, rate]
  );
  await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2', [rate, userId]);
  
  res.json({ success: true, earned: rate });
});

app.post('/api/request-package', authenticate, upload.single('screenshot'), async (req, res) => {
  const { level, transactionId } = req.body;
  const userId = req.user.id;
  const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
  if (user.rows[0].level >= parseInt(level)) return res.status(400).json({ error: 'You already have this level or higher' });
  
  const pkg = await pool.query('SELECT price FROM level_packages WHERE level=$1', [level]);
  const amount = pkg.rows[0].price;
  const screenshotPath = req.file ? `/uploads/${req.file.filename}` : null;
  
  await pool.query(
    'INSERT INTO purchase_requests (user_id, level, amount, transaction_id, screenshot) VALUES ($1,$2,$3,$4,$5)',
    [userId, level, amount, transactionId, screenshotPath]
  );
  res.json({ success: true, message: 'Request submitted. Admin will verify.' });
});

app.post('/api/request-withdraw', authenticate, async (req, res) => {
  const { amount } = req.body;
  const userId = req.user.id;
  const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
  const pkg = await pool.query('SELECT min_withdraw FROM level_packages WHERE level=$1', [user.rows[0].level]);
  const minWithdraw = parseFloat(pkg.rows[0].min_withdraw);
  if (amount < minWithdraw) return res.status(400).json({ error: `Minimum withdrawal is ${minWithdraw} Tk` });
  
  const balance = await pool.query('SELECT total_earnings - total_withdrawn AS balance FROM users WHERE id=$1', [userId]);
  if (balance.rows[0].balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  
  const today = new Date().getDay();
  if (today === 5) return res.status(400).json({ error: 'Withdrawals are not processed on Fridays' });
  
  await pool.query(
    'INSERT INTO withdrawal_requests (user_id, amount) VALUES ($1,$2)',
    [userId, amount]
  );
  res.json({ success: true, message: 'Withdrawal request submitted. Will be processed within 24 hours.' });
});

app.get('/api/profile', authenticate, async (req, res) => {
  const user = await pool.query(
    'SELECT username, mobile, level, total_earnings, total_withdrawn, status, referral_code FROM users WHERE id=$1',
    [req.user.id]
  );
  const balance = user.rows[0].total_earnings - user.rows[0].total_withdrawn;
  res.json({ ...user.rows[0], balance });
});

app.get('/api/live-withdrawals', async (req, res) => {
  const live = await pool.query('SELECT username, amount, created_at FROM live_withdrawals ORDER BY created_at DESC LIMIT 10');
  res.json(live.rows);
});

app.get('/admin/pending-packages', authenticate, isAdmin, async (req, res) => {
  const pending = await pool.query(`
    SELECT pr.*, u.username 
    FROM purchase_requests pr
    JOIN users u ON u.id = pr.user_id
    WHERE pr.status='pending'
  `);
  res.json(pending.rows);
});

app.post('/admin/approve-package', authenticate, isAdmin, async (req, res) => {
  const { requestId } = req.body;
  const adminId = req.user.id;
  const request = await pool.query('SELECT user_id, level, amount FROM purchase_requests WHERE id=$1 AND status=$2', [requestId, 'pending']);
  if (request.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  const { user_id, level, amount } = request.rows[0];
  
  await pool.query('UPDATE users SET level=$1 WHERE id=$2 AND level<$1', [level, user_id]);
  await pool.query('UPDATE purchase_requests SET status=$1, verified_by=$2, verified_at=NOW() WHERE id=$3', ['approved', adminId, requestId]);
  res.json({ success: true });
});

app.get('/admin/pending-withdrawals', authenticate, isAdmin, async (req, res) => {
  const pending = await pool.query(`
    SELECT wr.*, u.username, u.mobile, u.total_earnings, u.total_withdrawn
    FROM withdrawal_requests wr
    JOIN users u ON u.id = wr.user_id
    WHERE wr.status='pending'
  `);
  res.json(pending.rows);
});

app.post('/admin/process-withdraw', authenticate, isAdmin, async (req, res) => {
  const { withdrawalId } = req.body;
  const withdraw = await pool.query('SELECT user_id, amount FROM withdrawal_requests WHERE id=$1 AND status=$2', [withdrawalId, 'pending']);
  if (withdraw.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  const { user_id, amount } = withdraw.rows[0];
  
  const balance = await pool.query('SELECT total_earnings - total_withdrawn AS balance FROM users WHERE id=$1', [user_id]);
  if (balance.rows[0].balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  
  await pool.query('UPDATE users SET total_withdrawn = total_withdrawn + $1 WHERE id=$2', [amount, user_id]);
  await pool.query('UPDATE withdrawal_requests SET status=$1, processed_at=NOW() WHERE id=$2', ['approved', withdrawalId]);
  
  const user = await pool.query('SELECT username FROM users WHERE id=$1', [user_id]);
  await pool.query('INSERT INTO live_withdrawals (username, amount) VALUES ($1,$2)', [user.rows[0].username, amount]);
  
  res.json({ success: true });
});

app.get('/admin/users', authenticate, isAdmin, async (req, res) => {
  const users = await pool.query('SELECT id, username, mobile, level, total_earnings, status, referral_code FROM users');
  res.json(users.rows);
});

app.post('/admin/toggle-user-status', authenticate, isAdmin, async (req, res) => {
  const { userId, status } = req.body;
  await pool.query('UPDATE users SET status=$1 WHERE id=$2', [status, userId]);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// ভিডিও টাস্ক কমপ্লিট API
app.post('/api/complete-video-task', authenticate, async (req, res) => {
  const { taskId, reward } = req.body;
  const userId = req.user.id;
  const today = new Date().toISOString().slice(0,10);
  
  try {
    // টাস্ক আগে কমপ্লিট হয়েছে কিনা চেক করুন
    const alreadyCompleted = await pool.query(
      'SELECT id FROM user_tasks WHERE user_id=$1 AND task_id=$2 AND completed_date=$3',
      [userId, taskId, today]
    );
    
    if (alreadyCompleted.rows.length > 0) {
      return res.status(400).json({ error: 'Task already completed today' });
    }
    
    // পয়েন্ট যোগ করুন
    await pool.query(
      'INSERT INTO user_tasks (user_id, task_id, completed_date, points_earned) VALUES ($1, $2, $3, $4)',
      [userId, taskId, today, reward]
    );
    
    await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2', [reward, userId]);
    
    res.json({ success: true, earned: reward });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// রেফারেল তালিকা API
app.get('/api/my-referrals', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const referrals = await pool.query(`
      SELECT u.username, u.level, u.created_at as joined, 
             CASE 
               WHEN u.referrer_id = $1 THEN 1
               WHEN r2.referrer_id = $1 THEN 2
               WHEN r3.referrer_id = $1 THEN 3
             END as generation
      FROM users u
      LEFT JOIN users r2 ON u.referrer_id = r2.id
      LEFT JOIN users r3 ON r2.referrer_id = r3.id
      WHERE u.referrer_id = $1 OR r2.referrer_id = $1 OR r3.referrer_id = $1
    `, [userId]);
    
    res.json(referrals.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});