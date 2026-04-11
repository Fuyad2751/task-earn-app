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
// রেফারেল তালিকা API - বাস্তব ডাটাবেস থেকে
app.get('/api/my-referrals', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    // ১ম জেনারেশন (সরাসরি রেফারেল)
    const gen1 = await pool.query(`
      SELECT id, username, level, created_at as joined, '1st' as generation
      FROM users 
      WHERE referrer_id = $1
      ORDER BY created_at DESC
    `, [userId]);
    
    // ২য় জেনারেশন (রেফারেলের রেফারেল)
    const gen2 = await pool.query(`
      SELECT u.id, u.username, u.level, u.created_at as joined, '2nd' as generation
      FROM users u
      INNER JOIN users r1 ON u.referrer_id = r1.id
      WHERE r1.referrer_id = $1
      ORDER BY u.created_at DESC
    `, [userId]);
    
    // ৩য় জেনারেশন
    const gen3 = await pool.query(`
      SELECT u.id, u.username, u.level, u.created_at as joined, '3rd' as generation
      FROM users u
      INNER JOIN users r1 ON u.referrer_id = r1.id
      INNER JOIN users r2 ON r1.referrer_id = r2.id
      WHERE r2.referrer_id = $1
      ORDER BY u.created_at DESC
    `, [userId]);
    
    // সব জেনারেশন একত্রিত করুন
    const allReferrals = [...gen1.rows, ...gen2.rows, ...gen3.rows];
    
    // জেনারেশন ভিত্তিক কাউন্ট
    const counts = {
      gen1: gen1.rows.length,
      gen2: gen2.rows.length,
      gen3: gen3.rows.length,
      total: allReferrals.length
    };
    
    res.json({
      success: true,
      referrals: allReferrals,
      counts: counts
    });
    
  } catch (err) {
    console.error('Referral API error:', err);
    res.status(500).json({ error: err.message });
  }
});

// রেফারেল কমিশন ট্র্যাক করার API
app.get('/api/referral-commission', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    // ইউজারের মোট রেফারেল কমিশন
    const result = await pool.query(`
      SELECT COALESCE(SUM(amount), 0) as total_commission
      FROM referral_commissions
      WHERE referrer_id = $1
    `, [userId]);
    
    // জেনারেশন ভিত্তিক কমিশন
    const byGeneration = await pool.query(`
      SELECT level_gap, COALESCE(SUM(amount), 0) as total
      FROM referral_commissions
      WHERE referrer_id = $1
      GROUP BY level_gap
      ORDER BY level_gap
    `, [userId]);
    
    res.json({
      success: true,
      total_commission: parseFloat(result.rows[0].total_commission),
      by_generation: byGeneration.rows
    });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// টাস্ক লোড করার API - শুধু আনলক করা লেভেলের জন্য
app.get('/api/my-tasks', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    // ইউজারের লেভেল ও আনলক করা লেভেল চেক করুন
    const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
    const userLevel = user.rows[0].level;
    
    // ইউজার কতগুলো লেভেল আনলক করেছে তা চেক করুন
    const unlocked = await pool.query(
      'SELECT level_no FROM user_unlocked_levels WHERE user_id=$1',
      [userId]
    );
    
    // যদি কোন লেভেল আনলক না করে (শুধু ডিফল্ট লেভেল 1 না থাকলে)
    if (userLevel === 1 && unlocked.rows.length === 0) {
      // চেক করুন ইউজার ডিফল্ট লেভেল 1 এর প্যাকেজ কিনেছে কিনা
      const hasPackage = await pool.query(
        'SELECT id FROM purchase_requests WHERE user_id=$1 AND level=1 AND status="completed"',
        [userId]
      );
      
      if (hasPackage.rows.length === 0) {
        return res.json({ 
          noPackage: true, 
          message: 'টাস্ক শুরু করতে প্যাকেজ কিনুন!',
          level: 1,
          packagePrice: 500
        });
      }
    }
    
    // আনলক করা লেভেলের টাস্ক দেখান
    const tasks = await pool.query(
      'SELECT t.*, lp.task_rate FROM tasks t JOIN level_packages lp ON t.level = lp.level WHERE t.level <= $1 ORDER BY t.level, t.id',
      [userLevel]
    );
    
    const today = new Date().toISOString().slice(0,10);
    const completed = await pool.query(
      'SELECT task_id FROM user_daily_tasks WHERE user_id=$1 AND completed_date=$2',
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
    res.status(500).json({ error: err.message });
  }
});

// চেক করুন ইউজার টাস্ক করতে পারবে কিনা
app.get('/api/can-do-task', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
    const userLevel = user.rows[0].level;
    
    // চেক করুন ইউজার প্যাকেজ কিনেছে কিনা (লেভেল 1 এর বেশি হলে নিশ্চয়ই কিনেছে)
    if (userLevel > 1) {
      return res.json({ canDo: true, level: userLevel });
    }
    
    // লেভেল 1 এর জন্য প্যাকেজ চেক করুন
    const hasPackage = await pool.query(
      'SELECT id FROM purchase_requests WHERE user_id=$1 AND level=1 AND status="completed"',
      [userId]
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
// রেজিস্ট্রেশন API - রেফারেল কোড সহ
app.post('/api/register', async (req, res) => {
  const { username, password, mobile, referralCode } = req.body;
  
  try {
    const hashed = await bcrypt.hash(password, 10);
    const refCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    let referrerId = null;
    let referrerLevel = 0;
    
    // রেফারেল কোড চেক করুন
    if (referralCode && referralCode.trim() !== '') {
      const refUser = await pool.query(
        'SELECT id, level FROM users WHERE referral_code = $1', 
        [referralCode.toUpperCase()]
      );
      if (refUser.rows.length > 0) {
        referrerId = refUser.rows[0].id;
        referrerLevel = refUser.rows[0].level;
      }
    }
    
    // নতুন ইউজার তৈরি করুন
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, mobile, referral_code, referrer_id, level) 
       VALUES ($1, $2, $3, $4, $5, 1) RETURNING id, username`,
      [username, hashed, mobile, refCode, referrerId]
    );
    
    const newUserId = result.rows[0].id;
    const token = jwt.sign({ id: newUserId, username }, process.env.JWT_SECRET);
    
    res.json({ 
      token, 
      username,
      message: referrerId ? 'রেফারেল কোড সফলভাবে যুক্ত হয়েছে' : 'অ্যাকাউন্ট তৈরি সম্পন্ন'
    });
    
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).json({ error: 'Username already exists or invalid data' });
  }
});
// প্যাকেজ অ্যাপ্রুভ করার API - রেফারেল কমিশন সহ
app.post('/admin/approve-package', authenticate, isAdmin, async (req, res) => {
  const { requestId } = req.body;
  const adminId = req.user.id;
  
  try {
    const request = await pool.query(
      'SELECT user_id, level, amount FROM purchase_requests WHERE id=$1 AND status=$2',
      [requestId, 'pending']
    );
    if (request.rows.length === 0) {
      return res.status(404).json({ error: 'Not found' });
    }
    
    const { user_id, level, amount } = request.rows[0];
    
    // ইউজারের লেভেল আপডেট করুন
    await pool.query(
      'UPDATE users SET level=$1 WHERE id=$2 AND level<$1',
      [level, user_id]
    );
    
    // রেফারেল কমিশন বিতরণ করুন (৩ জেনারেশন পর্যন্ত)
    await distributePackageCommission(user_id, level, amount);
    
    // রিকোয়েস্ট আপডেট করুন
    await pool.query(
      `UPDATE purchase_requests 
       SET status='approved', verified_by=$1, verified_at=NOW() 
       WHERE id=$2`,
      [adminId, requestId]
    );
    
    res.json({ success: true });
    
  } catch (err) {
    console.error('Package approval error:', err);
    res.status(500).json({ error: err.message });
  }
});

// প্যাকেজ কমিশন বিতরণ ফাংশন
async function distributePackageCommission(userId, newLevel, packageAmount) {
  try {
    // ইউজারের রেফারার খুঁজুন
    const user = await pool.query(
      'SELECT referrer_id, level FROM users WHERE id=$1',
      [userId]
    );
    
    let currentReferrerId = user.rows[0]?.referrer_id;
    let generation = 1;
    
    // কমিশনের হার: 1st=10%, 2nd=5%, 3rd=2%
    const commissionRates = { 1: 0.10, 2: 0.05, 3: 0.02 };
    
    while (currentReferrerId && generation <= 3) {
      // রেফারারের তথ্য নিন
      const referrer = await pool.query(
        'SELECT id, level, username FROM users WHERE id=$1',
        [currentReferrerId]
      );
      
      if (referrer.rows.length > 0) {
        const referrerId = referrer.rows[0].id;
        const referrerLevel = referrer.rows[0].level;
        
        // শর্ত: রেফারারের লেভেল নতুন ইউজারের লেভেলের সমান বা বেশি হতে হবে
        if (referrerLevel >= newLevel) {
          const commission = packageAmount * commissionRates[generation];
          
          if (commission > 0) {
            // কমিশন রেকর্ড করুন
            await pool.query(
              `INSERT INTO referral_commissions 
               (referrer_id, referred_user_id, commission_type, amount, level_gap, created_at) 
               VALUES ($1, $2, $3, $4, $5, NOW())`,
              [referrerId, userId, 'package', commission, generation]
            );
            
            // রেফারারের ব্যালেন্স আপডেট করুন
            await pool.query(
              'UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2',
              [commission, referrerId]
            );
            
            console.log(`${generation}st gen commission: ${commission} to ${referrer.rows[0].username}`);
          }
        }
      }
      
      // পরবর্তী রেফারারের জন্য
      const nextUser = await pool.query(
        'SELECT referrer_id FROM users WHERE id=$1',
        [currentReferrerId]
      );
      currentReferrerId = nextUser.rows[0]?.referrer_id;
      generation++;
    }
    
  } catch (err) {
    console.error('Commission distribution error:', err);
  }
}
// টাস্ক কমপ্লিটের সময় রেফারেল কমিশন
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
    
    // ইউজারের লেভেল চেক করুন
    const user = await pool.query('SELECT level FROM users WHERE id=$1', [userId]);
    if (user.rows[0].level < taskLevel) {
      return res.status(403).json({ error: 'Level mismatch' });
    }
    
    // টাস্ক ইতিমধ্যে কমপ্লিট কিনা চেক করুন
    const done = await pool.query(
      'SELECT id FROM user_daily_tasks WHERE user_id=$1 AND task_id=$2 AND completed_date=$3',
      [userId, taskId, today]
    );
    if (done.rows.length) {
      return res.status(400).json({ error: 'Task already completed today' });
    }
    
    // টাস্ক কমপ্লিট লগ করুন
    await pool.query(
      'INSERT INTO user_daily_tasks (user_id, task_id, completed_date, earned) VALUES ($1,$2,$3,$4)',
      [userId, taskId, today, reward]
    );
    
    // ইউজারের ব্যালেন্স আপডেট করুন
    await pool.query(
      'UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2',
      [reward, userId]
    );
    
    // দৈনিক আয় ট্র্যাক করুন
    const dailyKey = `dailyEarning_${userId}`;
    const currentDaily = JSON.parse(localStorage.getItem(dailyKey) || '0');
    localStorage.setItem(dailyKey, currentDaily + reward);
    
    // রেফারেল কমিশন বিতরণ করুন (টাস্কের জন্য)
    await distributeTaskCommission(userId, reward, taskLevel);
    
    res.json({ success: true, earned: reward });
    
  } catch (err) {
    console.error('Task completion error:', err);
    res.status(500).json({ error: err.message });
  }
});

// টাস্ক কমিশন বিতরণ ফাংশন
async function distributeTaskCommission(userId, taskReward, taskLevel) {
  try {
    const user = await pool.query('SELECT referrer_id, level FROM users WHERE id=$1', [userId]);
    let currentReferrerId = user.rows[0]?.referrer_id;
    let generation = 1;
    
    // টাস্ক কমিশনের হার: 1st=5%, 2nd=2%, 3rd=1%
    const commissionRates = { 1: 0.05, 2: 0.02, 3: 0.01 };
    
    while (currentReferrerId && generation <= 3) {
      const referrer = await pool.query(
        'SELECT id, level, username FROM users WHERE id=$1',
        [currentReferrerId]
      );
      
      if (referrer.rows.length > 0) {
        const referrerId = referrer.rows[0].id;
        const referrerLevel = referrer.rows[0].level;
        
        // শর্ত: রেফারারের লেভেল ইউজারের লেভেলের সমান বা বেশি হতে হবে
        if (referrerLevel >= taskLevel) {
          const commission = taskReward * commissionRates[generation];
          
          if (commission > 0) {
            await pool.query(
              `INSERT INTO referral_commissions 
               (referrer_id, referred_user_id, commission_type, amount, level_gap, created_at) 
               VALUES ($1, $2, $3, $4, $5, NOW())`,
              [referrerId, userId, 'daily_task', commission, generation]
            );
            
            await pool.query(
              'UPDATE users SET total_earnings = total_earnings + $1 WHERE id=$2',
              [commission, referrerId]
            );
          }
        }
      }
      
      const nextUser = await pool.query(
        'SELECT referrer_id FROM users WHERE id=$1',
        [currentReferrerId]
      );
      currentReferrerId = nextUser.rows[0]?.referrer_id;
      generation++;
    }
    
  } catch (err) {
    console.error('Task commission error:', err);
  }
}