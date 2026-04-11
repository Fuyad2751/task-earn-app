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

// ============ রেজিস্ট্রেশন API ============
app.post('/api/register', async (req, res) => {
  const { username, password, mobile, referralCode } = req.body;
  
  try {
    const hashed = await bcrypt.hash(password, 10);
    
    let refCode;
    let isUnique = false;
    while (!isUnique) {
      refCode = Math.random().toString(36).substring(2, 8).toUpperCase();
      const existing = await pool.query('SELECT id FROM users WHERE referral_code = $1', [refCode]);
      if (existing.rows.length === 0) isUnique = true;
    }
    
    let referrerId = null;
    
    if (referralCode && referralCode.trim() !== '') {
      const refUser = await pool.query(
        'SELECT id FROM users WHERE referral_code = $1', 
        [referralCode.toUpperCase().trim()]
      );
      if (refUser.rows.length > 0) {
        referrerId = refUser.rows[0].id;
      }
    }
    
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, mobile, referral_code, referrer_id, level, total_earnings, total_withdrawn, status, created_at) 
       VALUES ($1, $2, $3, $4, $5, 1, 0, 0, 'active', NOW()) RETURNING id`,
      [username, hashed, mobile, refCode, referrerId]
    );
    
    const token = jwt.sign({ id: result.rows[0].id, username }, process.env.JWT_SECRET);
    res.json({ token, username });
    
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).json({ error: 'Username already exists' });
  }
});

// ============ লগইন API ============
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

// ============ প্যাকেজ API ============
app.get('/api/packages', async (req, res) => {
  const packages = await pool.query('SELECT * FROM level_packages ORDER BY level');
  res.json(packages.rows);
});

// ============ টাস্ক API - শুধু বর্তমান লেভেলের টাস্ক দেখাবে ============
app.get('/api/my-tasks', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const user = await pool.query('SELECT level FROM users WHERE id = $1', [userId]);
    const userLevel = user.rows[0].level;
    
    if (userLevel === 1) {
      const hasPackage = await pool.query(
        'SELECT id FROM purchase_requests WHERE user_id = $1 AND level = 1 AND status = $2',
        [userId, 'approved']
      );
      
      if (hasPackage.rows.length === 0) {
        return res.json({ 
          noPackage: true, 
          message: 'টাস্ক শুরু করতে লেভেল 1 প্যাকেজ কিনুন!',
          packagePrice: 500
        });
      }
    }
    
    const tasks = await pool.query(
      `SELECT t.*, lp.task_rate 
       FROM tasks t 
       JOIN level_packages lp ON t.level = lp.level 
       WHERE t.level = $1 
       ORDER BY t.id`,
      [userLevel]
    );
    
    const today = new Date().toISOString().slice(0, 10);
    const completed = await pool.query(
      'SELECT task_id FROM user_daily_tasks WHERE user_id = $1 AND completed_date = $2',
      [userId, today]
    );
    const completedIds = completed.rows.map(r => r.task_id);
    
    const tasksWithStatus = tasks.rows.map(t => ({ 
      ...t, 
      completed: completedIds.includes(t.id),
      task_rate: parseFloat(t.task_rate)
    }));
    
    res.json(tasksWithStatus);
    
  } catch (err) {
    console.error('Tasks API error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ টাস্ক কমপ্লিট API ============
app.post('/api/complete-task', authenticate, async (req, res) => {
  const { taskId } = req.body;
  const userId = req.user.id;
  const today = new Date().toISOString().slice(0,10);
  
  try {
    const task = await pool.query('SELECT level, points_reward FROM tasks WHERE id=$1', [taskId]);
    if (task.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    const taskLevel = task.rows[0].level;
    const reward = parseFloat(task.rows[0].points_reward);
    
    const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
    if (user.rows[0].level < taskLevel) {
      return res.status(403).json({ error: 'Level mismatch' });
    }
    
    const done = await pool.query(
      'SELECT id FROM user_daily_tasks WHERE user_id=$1 AND task_id=$2 AND completed_date=$3',
      [userId, taskId, today]
    );
    if (done.rows.length) {
      return res.status(400).json({ error: 'Task already completed today' });
    }
    
    await pool.query(
      'INSERT INTO user_daily_tasks (user_id, task_id, completed_date, earned) VALUES ($1,$2,$3,$4)',
      [userId, taskId, today, reward]
    );
    
    await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2', [reward, userId]);
    
    await distributeTaskCommission(userId, reward, taskLevel);
    
    res.json({ success: true, earned: reward });
    
  } catch (err) {
    console.error('Task completion error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ প্যাকেজ ক্রয় রিকোয়েস্ট API ============
app.post('/api/request-package', authenticate, upload.single('screenshot'), async (req, res) => {
  const { level, transactionId } = req.body;
  const userId = req.user.id;
  const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
  if (user.rows[0].level >= parseInt(level)) return res.status(400).json({ error: 'You already have this level or higher' });
  
  const pkg = await pool.query('SELECT price FROM level_packages WHERE level=$1', [level]);
  const amount = pkg.rows[0].price;
  const screenshotPath = req.file ? `/uploads/${req.file.filename}` : null;
  
  await pool.query(
    'INSERT INTO purchase_requests (user_id, level, amount, transaction_id, screenshot, status) VALUES ($1,$2,$3,$4,$5, $6)',
    [userId, level, amount, transactionId, screenshotPath, 'pending']
  );
  res.json({ success: true, message: 'Request submitted. Admin will verify.' });
});

// ============ উত্তোলন রিকোয়েস্ট API ============
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
    'INSERT INTO withdrawal_requests (user_id, amount, status) VALUES ($1,$2,$3)',
    [userId, amount, 'pending']
  );
  res.json({ success: true, message: 'Withdrawal request submitted. Will be processed within 24 hours.' });
});

// ============ প্রোফাইল API ============
app.get('/api/profile', authenticate, async (req, res) => {
  const user = await pool.query(
    'SELECT id, username, mobile, level, total_earnings, total_withdrawn, status, referral_code, created_at FROM users WHERE id=$1',
    [req.user.id]
  );
  const balance = user.rows[0].total_earnings - user.rows[0].total_withdrawn;
  res.json({ ...user.rows[0], balance });
});

// ============ লাইভ উত্তোলন API ============
app.get('/api/live-withdrawals', async (req, res) => {
  const live = await pool.query('SELECT username, amount, created_at FROM live_withdrawals ORDER BY created_at DESC LIMIT 10');
  res.json(live.rows);
});

// ============ রেফারেল তালিকা API ============
app.get('/api/my-referrals', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const gen1 = await pool.query(`
      SELECT id, username, level, created_at as joined, '1st' as generation
      FROM users 
      WHERE referrer_id = $1
      ORDER BY created_at DESC
    `, [userId]);
    
    const gen2 = await pool.query(`
      SELECT u.id, u.username, u.level, u.created_at as joined, '2nd' as generation
      FROM users u
      INNER JOIN users r1 ON u.referrer_id = r1.id
      WHERE r1.referrer_id = $1
      ORDER BY u.created_at DESC
    `, [userId]);
    
    const gen3 = await pool.query(`
      SELECT u.id, u.username, u.level, u.created_at as joined, '3rd' as generation
      FROM users u
      INNER JOIN users r1 ON u.referrer_id = r1.id
      INNER JOIN users r2 ON r1.referrer_id = r2.id
      WHERE r2.referrer_id = $1
      ORDER BY u.created_at DESC
    `, [userId]);
    
    const allReferrals = [...gen1.rows, ...gen2.rows, ...gen3.rows];
    const counts = {
      gen1: gen1.rows.length,
      gen2: gen2.rows.length,
      gen3: gen3.rows.length,
      total: allReferrals.length
    };
    
    res.json({ success: true, referrals: allReferrals, counts: counts });
    
  } catch (err) {
    console.error('Referral API error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ রেফারেল কমিশন API ============
app.get('/api/referral-commission', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const result = await pool.query(`
      SELECT COALESCE(SUM(amount), 0) as total_commission
      FROM referral_commissions
      WHERE referrer_id = $1
    `, [userId]);
    
    res.json({ total_commission: parseFloat(result.rows[0].total_commission) });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ চেক ইউজার টাস্ক করতে পারবে কিনা ============
app.get('/api/can-do-task', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
    const userLevel = user.rows[0].level;
    
    if (userLevel > 1) {
      return res.json({ canDo: true, level: userLevel });
    }
    
    const hasPackage = await pool.query(
      'SELECT id FROM purchase_requests WHERE user_id=$1 AND level=1 AND status=$2',
      [userId, 'approved']
    );
    
    if (hasPackage.rows.length > 0) {
      return res.json({ canDo: true, level: userLevel });
    }
    
    res.json({ 
      canDo: false, 
      level: userLevel,
      message: 'টাস্ক শুরু করতে লেভেল 1 প্যাকেজ কিনুন!',
      packagePrice: 500
    });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ব্যালেন্স রিকোয়েস্ট API ============
// ইউজার: ব্যালেন্স রিকোয়েস্ট করুন
app.post('/api/request-balance', authenticate, async (req, res) => {
  const { amount, transactionId, paymentMethod } = req.body;
  const userId = req.user.id;
  
  try {
    if (!amount || amount < 100) return res.status(400).json({ error: 'ন্যূনতম ১০০ টাকা আবেদন করতে পারবেন' });
    if (!transactionId) return res.status(400).json({ error: 'ট্রানজাকশন আইডি দিন' });
    
    await pool.query(
      `INSERT INTO balance_requests (user_id, amount, transaction_id, payment_method, status, requested_at) 
       VALUES ($1, $2, $3, $4, 'pending', NOW())`,
      [userId, amount, transactionId, paymentMethod || 'mobile_banking']
    );
    res.json({ success: true, message: 'আবেদন জমা হয়েছে। অ্যাডমিন যাচাই করে ব্যালেন্স যোগ করবেন।' });
  } catch (err) { 
    console.error('Balance request error:', err);
    res.status(500).json({ error: err.message }); 
  }
});

// ============ অ্যাডমিন API ============
// অ্যাডমিন: ব্যালেন্স যোগ করুন
app.post('/admin/add-balance', authenticate, isAdmin, async (req, res) => {
  const { userId, amount } = req.body;
  
  try {
    await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id = $2', [amount, userId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// অ্যাডমিন: পেন্ডিং প্যাকেজ
app.get('/admin/pending-packages', authenticate, isAdmin, async (req, res) => {
  const pending = await pool.query(`
    SELECT pr.*, u.username 
    FROM purchase_requests pr
    JOIN users u ON u.id = pr.user_id
    WHERE pr.status='pending'
  `);
  res.json(pending.rows);
});

// অ্যাডমিন: প্যাকেজ অ্যাপ্রুভ
app.post('/admin/approve-package', authenticate, isAdmin, async (req, res) => {
  const { requestId } = req.body;
  
  try {
    const request = await pool.query(
      'SELECT user_id, level, amount FROM purchase_requests WHERE id=$1 AND status=$2',
      [requestId, 'pending']
    );
    if (request.rows.length === 0) {
      return res.status(404).json({ error: 'Not found' });
    }
    
    const { user_id, level, amount } = request.rows[0];
    
    await pool.query('UPDATE users SET level=$1 WHERE id=$2 AND level<$1', [level, user_id]);
    await pool.query('UPDATE purchase_requests SET status=$1, verified_at=NOW() WHERE id=$2', ['approved', requestId]);
    
    await distributePackageCommission(user_id, level, amount);
    
    res.json({ success: true });
    
  } catch (err) {
    console.error('Package approval error:', err);
    res.status(500).json({ error: err.message });
  }
});

// অ্যাডমিন: পেন্ডিং ব্যালেন্স রিকোয়েস্ট দেখুন
app.get('/admin/pending-balance-requests', authenticate, isAdmin, async (req, res) => {
  try {
    const requests = await pool.query(`
      SELECT br.*, u.username, u.mobile, u.total_earnings, u.total_withdrawn
      FROM balance_requests br
      JOIN users u ON u.id = br.user_id
      WHERE br.status = 'pending'
      ORDER BY br.requested_at ASC
    `);
    res.json(requests.rows);
  } catch (err) { 
    console.error('Pending balance requests error:', err);
    res.status(500).json({ error: err.message }); 
  }
});

// অ্যাডমিন: ব্যালেন্স রিকোয়েস্ট অ্যাপ্রুভ করুন
app.post('/admin/approve-balance-request', authenticate, isAdmin, async (req, res) => {
  const { requestId } = req.body;
  try {
    const request = await pool.query('SELECT user_id, amount FROM balance_requests WHERE id = $1 AND status = $2', [requestId, 'pending']);
    if (request.rows.length === 0) return res.status(404).json({ error: 'রিকোয়েস্ট পাওয়া যায়নি' });
    const { user_id, amount } = request.rows[0];
    await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id = $2', [amount, user_id]);
    await pool.query('UPDATE balance_requests SET status = $1, processed_at = NOW() WHERE id = $2', ['approved', requestId]);
    res.json({ success: true });
  } catch (err) { 
    console.error('Approve balance error:', err);
    res.status(500).json({ error: err.message }); 
  }
});

// অ্যাডমিন: ব্যালেন্স রিকোয়েস্ট রিজেক্ট করুন
app.post('/admin/reject-balance-request', authenticate, isAdmin, async (req, res) => {
  const { requestId, note } = req.body;
  try {
    await pool.query('UPDATE balance_requests SET status = $1, note = $2, processed_at = NOW() WHERE id = $3', ['rejected', note || '', requestId]);
    res.json({ success: true });
  } catch (err) { 
    console.error('Reject balance error:', err);
    res.status(500).json({ error: err.message }); 
  }
});

// অ্যাডমিন: পেন্ডিং উত্তোলন
app.get('/admin/pending-withdrawals', authenticate, isAdmin, async (req, res) => {
  const pending = await pool.query(`
    SELECT wr.*, u.username, u.mobile, u.total_earnings, u.total_withdrawn
    FROM withdrawal_requests wr
    JOIN users u ON u.id = wr.user_id
    WHERE wr.status='pending'
  `);
  res.json(pending.rows);
});

// অ্যাডমিন: উত্তোলন প্রসেস
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

// অ্যাডমিন: ইউজার ম্যানেজমেন্ট
app.get('/admin/users', authenticate, isAdmin, async (req, res) => {
  const users = await pool.query('SELECT id, username, mobile, level, total_earnings, total_withdrawn, status, referral_code, created_at FROM users');
  res.json(users.rows);
});

app.post('/admin/toggle-user-status', authenticate, isAdmin, async (req, res) => {
  const { userId, status } = req.body;
  await pool.query('UPDATE users SET status=$1 WHERE id=$2', [status, userId]);
  res.json({ success: true });
});

// ============ কমিশন বিতরণ ফাংশন ============
async function distributePackageCommission(userId, newLevel, packageAmount) {
  try {
    const user = await pool.query('SELECT referrer_id FROM users WHERE id=$1', [userId]);
    let currentReferrerId = user.rows[0]?.referrer_id;
    let generation = 1;
    
    const commissionRates = { 1: 0.10, 2: 0.05, 3: 0.02 };
    
    while (currentReferrerId && generation <= 3) {
      const referrer = await pool.query('SELECT id, level, username FROM users WHERE id=$1', [currentReferrerId]);
      
      if (referrer.rows.length > 0) {
        const referrerId = referrer.rows[0].id;
        const referrerLevel = referrer.rows[0].level;
        
        if (referrerLevel >= newLevel) {
          const commission = packageAmount * commissionRates[generation];
          
          if (commission > 0) {
            await pool.query(
              `INSERT INTO referral_commissions 
               (referrer_id, referred_user_id, commission_type, amount, level_gap, created_at) 
               VALUES ($1, $2, $3, $4, $5, NOW())`,
              [referrerId, userId, 'package', commission, generation]
            );
            
            await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2', [commission, referrerId]);
          }
        }
      }
      
      const nextUser = await pool.query('SELECT referrer_id FROM users WHERE id=$1', [currentReferrerId]);
      currentReferrerId = nextUser.rows[0]?.referrer_id;
      generation++;
    }
    
  } catch (err) {
    console.error('Commission distribution error:', err);
  }
}

async function distributeTaskCommission(userId, taskReward, taskLevel) {
  try {
    const user = await pool.query('SELECT referrer_id FROM users WHERE id=$1', [userId]);
    let currentReferrerId = user.rows[0]?.referrer_id;
    let generation = 1;
    
    const commissionRates = { 1: 0.05, 2: 0.02, 3: 0.01 };
    
    while (currentReferrerId && generation <= 3) {
      const referrer = await pool.query('SELECT id, level, username FROM users WHERE id=$1', [currentReferrerId]);
      
      if (referrer.rows.length > 0) {
        const referrerId = referrer.rows[0].id;
        const referrerLevel = referrer.rows[0].level;
        
        if (referrerLevel >= taskLevel) {
          const commission = taskReward * commissionRates[generation];
          
          if (commission > 0) {
            await pool.query(
              `INSERT INTO referral_commissions 
               (referrer_id, referred_user_id, commission_type, amount, level_gap, created_at) 
               VALUES ($1, $2, $3, $4, $5, NOW())`,
              [referrerId, userId, 'daily_task', commission, generation]
            );
            
            await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2', [commission, referrerId]);
          }
        }
      }
      
      const nextUser = await pool.query('SELECT referrer_id FROM users WHERE id=$1', [currentReferrerId]);
      currentReferrerId = nextUser.rows[0]?.referrer_id;
      generation++;
    }
    
  } catch (err) {
    console.error('Task commission error:', err);
  }
}

// ============ সার্ভার স্টার্ট ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
app.post('/api/request-package', authenticate, async (req, res) => {
  const { level, transactionId, useBalance } = req.body;
  const userId = req.user.id;
  const user = await pool.query('SELECT level, total_earnings, total_withdrawn FROM users WHERE id=$1', [userId]);
  
  if (user.rows[0].level >= parseInt(level)) {
    return res.status(400).json({ error: 'You already have this level or higher' });
  }
  
  const pkg = await pool.query('SELECT price FROM level_packages WHERE level=$1', [level]);
  const amount = pkg.rows[0].price;
  
  // যদি ব্যালেন্স ব্যবহার করে কেনে, তাহলে ব্যালেন্স চেক করুন
  if (useBalance) {
    const balance = user.rows[0].total_earnings - user.rows[0].total_withdrawn;
    if (balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
  }
  
  await pool.query(
    'INSERT INTO purchase_requests (user_id, level, amount, transaction_id, status) VALUES ($1,$2,$3,$4,$5)',
    [userId, level, amount, transactionId, 'pending']
  );
  res.json({ success: true, message: 'Request submitted. Admin will verify.' });
});
// ============ প্যাকেজ ক্রয় API (অটোমেটিক) ============
app.post('/api/buy-package', authenticate, async (req, res) => {
  const { level } = req.body;
  const userId = req.user.id;
  
  try {
    const user = await pool.query('SELECT level, total_earnings, total_withdrawn FROM users WHERE id=$1', [userId]);
    const userLevel = user.rows[0].level;
    
    if (userLevel >= level) {
      return res.status(400).json({ error: 'You already have this level or higher' });
    }
    
    const pkg = await pool.query('SELECT price FROM level_packages WHERE level=$1', [level]);
    const packagePrice = pkg.rows[0].price;
    const userBalance = user.rows[0].total_earnings - user.rows[0].total_withdrawn;
    
    if (userBalance >= packagePrice) {
      // ব্যালেন্স suficiente - অটোমেটিক লেভেল আপগ্রেড
      await pool.query('UPDATE users SET level = $1 WHERE id = $2', [level, userId]);
      
      // ব্যালেন্স থেকে টাকা কাটুন
      await pool.query('UPDATE users SET total_withdrawn = total_withdrawn + $1 WHERE id = $2', [packagePrice, userId]);
      
      // রেফারেল কমিশন বিতরণ
      await distributePackageCommission(userId, level, packagePrice);
      
      res.json({ 
        success: true, 
        message: `অভিনন্দন! আপনি লেভেল ${level} এ আপগ্রেড হয়েছেন!`,
        autoApproved: true
      });
    } else {
      // ব্যালেন্স কম - অ্যাডমিন অ্যাপ্রুভ প্রয়োজন
      const needAmount = packagePrice - userBalance;
      res.json({ 
        success: false, 
        needBalance: true,
        needAmount: needAmount,
        message: `আপনার ব্যালেন্স কম। ${needAmount} টাকা যোগ করতে ব্যালেন্স রিকোয়েস্ট করুন।`
      });
    }
    
  } catch (err) {
    console.error('Package buy error:', err);
    res.status(500).json({ error: err.message });
  }
});