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

// মডেল ফাইলের জন্য সঠিক হেডার সেট করুন
app.use('/models', express.static('public/models', {
    setHeaders: (res, path) => {
        if (path.endsWith('.json')) {
            res.setHeader('Content-Type', 'application/json');
        } else if (path.endsWith('.shard1') || path.endsWith('.shard2')) {
            res.setHeader('Content-Type', 'application/octet-stream');
        }
        res.setHeader('Access-Control-Allow-Origin', '*');
    }
}));

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

// ============ সাইট সেটিংস API ============
app.get('/api/site-settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM site_settings WHERE id = 1');
        res.json(result.rows[0] || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/face-verification-status', async (req, res) => {
    try {
        const result = await pool.query('SELECT face_verification_enabled FROM site_settings WHERE id = 1');
        const isEnabled = result.rows[0]?.face_verification_enabled !== false;
        res.json({ enabled: isEnabled });
    } catch (err) {
        res.json({ enabled: true });
    }
});

// ============ রেজিস্ট্রেশন API (লেভেল 0 দিয়ে) ============
app.post('/api/register', async (req, res) => {
    const { username, password, mobile, referralCode, faceDescriptor } = req.body;
    
    try {
        const settings = await pool.query('SELECT face_verification_enabled FROM site_settings WHERE id = 1');
        const faceVerificationRequired = settings.rows[0]?.face_verification_enabled !== false;
        
        if (faceVerificationRequired && (!faceDescriptor || faceDescriptor.length === 0)) {
            return res.status(400).json({ error: 'ফেস ভেরিফিকেশন প্রয়োজন!' });
        }
        
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
            const refUser = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referralCode.toUpperCase().trim()]);
            if (refUser.rows.length > 0) referrerId = refUser.rows[0].id;
        }
        
        // ✅ লেভেল 0 দিয়ে ইউজার তৈরি করুন (এখানে 1 এর জায়গায় 0 বসান)
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, mobile, referral_code, referrer_id, level, total_earnings, total_withdrawn, status, created_at, purchase_date) 
             VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 'active', NOW(), NOW()) RETURNING id`,
            [username, hashed, mobile, refCode, referrerId]
        );
        
        const userId = result.rows[0].id;
        
        if (faceVerificationRequired && faceDescriptor) {
            await pool.query(
                'INSERT INTO face_descriptors (user_id, descriptor) VALUES ($1, $2)',
                [userId, JSON.stringify(faceDescriptor)]
            );
        }
        
        const token = jwt.sign({ id: userId, username }, process.env.JWT_SECRET);
        res.json({ token, username });
        
    } catch (err) {
        console.error('Registration error:', err);
        res.status(400).json({ error: 'Username already exists or invalid data' });
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

// ============ টাস্ক API (লেভেল 0 সাপোর্ট সহ) ============
app.get('/api/my-tasks', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const user = await pool.query('SELECT level FROM users WHERE id = $1', [userId]);
    const userLevel = user.rows[0].level;
    
    // ✅ লেভেল 0 এর জন্য প্যাকেজ চেক করবেন না
    // শুধু লেভেল 1 এর জন্য প্যাকেজ চেক করুন
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
    
    const tasksWithData = tasks.rows.map(t => ({
      ...t,
      completed: completedIds.includes(t.id),
      task_rate: parseFloat(t.task_rate),
      video_url: t.video_url || 'https://www.youtube.com/embed/dQw4w9WgXcQ',
      question: t.question || 'ভিডিওটি সম্পর্কে আপনার মতামত কী?',
      options: t.options || ['ভিডিওটি ভালো ছিল', 'ভিডিওটি তথ্যমূলক ছিল', 'ভিডিওটি দরকারী ছিল', 'ভিডিওটি চমৎকার ছিল']
    }));
    
    res.json(tasksWithData);
    
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

// ============ প্যাকেজ ক্রয় API (লেভেল 0 থেকে আপগ্রেড) ============
app.post('/api/buy-package', authenticate, async (req, res) => {
  const { level } = req.body;
  const userId = req.user.id;
  
  try {
    const user = await pool.query('SELECT level, total_earnings, total_withdrawn, purchase_date FROM users WHERE id=$1', [userId]);
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userLevel = user.rows[0].level;
    
    if (userLevel >= level) {
      return res.status(400).json({ error: `আপনি ইতিমধ্যে লেভেল ${userLevel} এ আছেন!` });
    }
    
    const pkg = await pool.query('SELECT price, expiry_days FROM level_packages WHERE level=$1', [level]);
    const packagePrice = pkg.rows[0].price;
    const expiryDays = pkg.rows[0].expiry_days || 0;
    const userBalance = user.rows[0].total_earnings - user.rows[0].total_withdrawn;
    
    if (userBalance >= packagePrice) {
      // ব্যালেন্স suficiente - অটোমেটিক লেভেল আপগ্রেড
      await pool.query('UPDATE users SET level = $1, purchase_date = NOW() WHERE id = $2', [level, userId]);
      await pool.query('UPDATE users SET total_withdrawn = total_withdrawn + $1 WHERE id = $2', [packagePrice, userId]);
      await distributePackageCommission(userId, level, packagePrice);
      
      let expiryMessage = '';
      if (expiryDays > 0) {
        expiryMessage = ` এই প্যাকেজের মেয়াদ ${expiryDays} দিন। ক্রয় তারিখ: ${new Date().toLocaleDateString()}`;
      }
      
      res.json({ 
        success: true, 
        message: `অভিনন্দন! আপনি লেভেল ${level} এ আপগ্রেড হয়েছেন!${expiryMessage}`,
        autoApproved: true,
        expiryDays: expiryDays
      });
    } else {
      const needAmount = packagePrice - userBalance;
      res.json({ 
        success: false, 
        needBalance: true,
        needAmount: needAmount,
        packagePrice: packagePrice,
        userBalance: userBalance,
        message: `আপনার ব্যালেন্স কম। ${needAmount} টাকা পেমেন্ট করুন।`
      });
    }
    
  } catch (err) {
    console.error('Package buy error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ প্রোফাইল API ============
app.get('/api/profile', authenticate, async (req, res) => {
  const user = await pool.query(
    'SELECT id, username, mobile, level, total_earnings, total_withdrawn, status, referral_code, profile_pic, created_at, purchase_date FROM users WHERE id=$1',
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

// ============ রেফারেল API ============
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

// ============ উত্তোলন একাউন্ট API ============
app.post('/api/create-withdrawal-account', authenticate, async (req, res) => {
  const { accountName, accountNumber, accountType, withdrawPassword } = req.body;
  const userId = req.user.id;
  
  try {
    if (!accountName || !accountNumber || !withdrawPassword) {
      return res.status(400).json({ error: 'সব ঘর পূরণ করুন' });
    }
    
    const existing = await pool.query(
      'SELECT id FROM withdrawal_accounts WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'আপনার ইতিমধ্যে একটি একাউন্ট আছে। পরিবর্তন করতে অ্যাডমিনে যোগাযোগ করুন।' });
    }
    
    await pool.query(
      `INSERT INTO withdrawal_accounts (user_id, account_name, account_number, account_type, withdraw_password, is_active, is_verified, requested_at) 
       VALUES ($1, $2, $3, $4, $5, true, false, NOW())`,
      [userId, accountName, accountNumber, accountType || 'bkash', withdrawPassword]
    );
    
    res.json({ success: true, message: 'উত্তোলন একাউন্ট তৈরি করা হয়েছে। অ্যাডমিন যাচাই করবেন।' });
    
  } catch (err) {
    console.error('Create account error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/my-withdrawal-account', authenticate, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const account = await pool.query(
      'SELECT * FROM withdrawal_accounts WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    res.json(account.rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ উত্তোলন রিকোয়েস্ট API ============
app.post('/api/request-withdraw', authenticate, async (req, res) => {
  const { amount, withdrawPassword } = req.body;
  const userId = req.user.id;
  const today = new Date().toISOString().slice(0,10);
  
  try {
    const account = await pool.query(
      'SELECT * FROM withdrawal_accounts WHERE user_id = $1 AND is_active = true AND is_verified = true',
      [userId]
    );
    
    if (account.rows.length === 0) {
      return res.status(400).json({ error: 'আপনার উত্তোলন একাউন্ট নেই বা ভেরিফাই করা হয়নি' });
    }
    
    if (account.rows[0].withdraw_password !== withdrawPassword) {
      return res.status(400).json({ error: 'উত্তোলন পাসওয়ার্ড ভুল!' });
    }
    
    const todayWithdraw = await pool.query(
      'SELECT id FROM withdrawal_requests WHERE user_id = $1 AND DATE(requested_at) = $2',
      [userId, today]
    );
    
    if (todayWithdraw.rows.length > 0) {
      return res.status(400).json({ error: 'আপনি আজ ইতিমধ্যে একটি উত্তোলন আবেদন করেছেন। আগামীকাল চেষ্টা করুন।' });
    }
    
    const user = await pool.query('SELECT level, total_earnings, total_withdrawn FROM users WHERE id=$1', [userId]);
    const pkg = await pool.query('SELECT min_withdraw FROM level_packages WHERE level=$1', [user.rows[0].level]);
    const minWithdraw = parseFloat(pkg.rows[0].min_withdraw);
    
    if (amount < minWithdraw) {
      return res.status(400).json({ error: `ন্যূনতম উত্তোলন ${minWithdraw} টাকা` });
    }
    
    const balance = user.rows[0].total_earnings - user.rows[0].total_withdrawn;
    if (balance < amount) {
      return res.status(400).json({ error: 'পর্যাপ্ত ব্যালেন্স নেই' });
    }
    
    const fee = amount * 0.10;
    const netAmount = amount - fee;
    
    await pool.query(
      'UPDATE users SET total_withdrawn = total_withdrawn + $1 WHERE id = $2',
      [amount, userId]
    );
    
    await pool.query(
      `INSERT INTO withdrawal_requests (user_id, amount, fee, net_amount, account_id, withdraw_password, status, requested_at) 
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW())`,
      [userId, amount, fee, netAmount, account.rows[0].id, withdrawPassword]
    );
    
    res.json({ 
      success: true, 
      message: `উত্তোলন আবেদন জমা হয়েছে। ${amount} টাকা আপনার ব্যালেন্স থেকে কেটে নেওয়া হয়েছে। অ্যাডমিন অ্যাপ্রুভ দিলে ${netAmount} টাকা আপনার একাউন্টে পাঠানো হবে।` 
    });
    
  } catch (err) {
    console.error('Withdraw request error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ অ্যাডমিন API ============
app.post('/admin/add-balance', authenticate, isAdmin, async (req, res) => {
  const { userId, amount } = req.body;
  await pool.query('UPDATE users SET total_earnings = total_earnings + $1 WHERE id = $2', [amount, userId]);
  res.json({ success: true });
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
  
  try {
    const request = await pool.query(
      'SELECT user_id, level, amount FROM purchase_requests WHERE id=$1 AND status=$2',
      [requestId, 'pending']
    );
    if (request.rows.length === 0) {
      return res.status(404).json({ error: 'Not found' });
    }
    
    const { user_id, level, amount } = request.rows[0];
    
    await pool.query('UPDATE users SET level=$1, purchase_date=NOW() WHERE id=$2 AND level<$1', [level, user_id]);
    await pool.query('UPDATE purchase_requests SET status=$1, verified_at=NOW() WHERE id=$2', ['approved', requestId]);
    
    await distributePackageCommission(user_id, level, amount);
    
    res.json({ success: true });
    
  } catch (err) {
    console.error('Package approval error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/pending-withdrawals', authenticate, isAdmin, async (req, res) => {
  try {
    const pending = await pool.query(`
      SELECT wr.*, u.username, u.mobile, wa.account_name, wa.account_number, wa.account_type
      FROM withdrawal_requests wr
      JOIN users u ON u.id = wr.user_id
      JOIN withdrawal_accounts wa ON wa.id = wr.account_id
      WHERE wr.status = 'pending'
      ORDER BY wr.requested_at ASC
    `);
    res.json(pending.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/process-withdraw', authenticate, isAdmin, async (req, res) => {
  const { withdrawalId } = req.body;
  
  try {
    const withdraw = await pool.query(
      'SELECT user_id, amount, net_amount FROM withdrawal_requests WHERE id = $1 AND status = $2',
      [withdrawalId, 'pending']
    );
    if (withdraw.rows.length === 0) {
      return res.status(404).json({ error: 'রিকোয়েস্ট পাওয়া যায়নি' });
    }
    
    await pool.query(
      'UPDATE withdrawal_requests SET status = $1, processed_at = NOW() WHERE id = $2',
      ['approved', withdrawalId]
    );
    
    const user = await pool.query('SELECT username FROM users WHERE id = $1', [withdraw.rows[0].user_id]);
    await pool.query(
      'INSERT INTO live_withdrawals (username, amount) VALUES ($1, $2)',
      [user.rows[0].username, withdraw.rows[0].net_amount]
    );
    
    res.json({ success: true });
    
  } catch (err) {
    console.error('Process withdraw error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/reject-withdraw', authenticate, isAdmin, async (req, res) => {
  const { withdrawalId, reason } = req.body;
  
  try {
    const withdraw = await pool.query(
      'SELECT user_id, amount FROM withdrawal_requests WHERE id = $1 AND status = $2',
      [withdrawalId, 'pending']
    );
    if (withdraw.rows.length === 0) {
      return res.status(404).json({ error: 'রিকোয়েস্ট পাওয়া যায়নি' });
    }
    
    const { user_id, amount } = withdraw.rows[0];
    
    await pool.query(
      'UPDATE users SET total_withdrawn = total_withdrawn - $1 WHERE id = $2',
      [amount, user_id]
    );
    
    await pool.query(
      'UPDATE withdrawal_requests SET status = $1, note = $2, processed_at = NOW() WHERE id = $3',
      ['rejected', reason || 'অ্যাডমিন দ্বারা বাতিল', withdrawalId]
    );
    
    res.json({ success: true });
    
  } catch (err) {
    console.error('Reject withdraw error:', err);
    res.status(500).json({ error: err.message });
  }
});

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

// ============ ফেস ভেরিফিকেশন API ============
app.post('/api/save-face-descriptor', authenticate, async (req, res) => {
    const { descriptor } = req.body;
    const userId = req.user.id;
    
    try {
        await pool.query('DELETE FROM face_descriptors WHERE user_id = $1', [userId]);
        await pool.query(
            'INSERT INTO face_descriptors (user_id, descriptor) VALUES ($1, $2)',
            [userId, JSON.stringify(descriptor)]
        );
        res.json({ success: true, message: 'ফেস নিবন্ধন সম্পন্ন!' });
    } catch (err) {
        console.error('Save face error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/match-face', authenticate, async (req, res) => {
    const { descriptor } = req.body;
    const userId = req.user.id;
    
    try {
        const result = await pool.query(
            'SELECT descriptor FROM face_descriptors WHERE user_id = $1',
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'আপনার ফেস নিবন্ধন নেই। প্রথমে নিবন্ধন করুন।' });
        }
        
        const savedDescriptor = JSON.parse(result.rows[0].descriptor);
        
        let distance = 0;
        for (let i = 0; i < descriptor.length; i++) {
            distance += Math.pow(descriptor[i] - savedDescriptor[i], 2);
        }
        distance = Math.sqrt(distance);
        
        const isMatch = distance < 0.6;
        
        res.json({ 
            success: isMatch, 
            distance: distance,
            message: isMatch ? 'ভেরিফিকেশন সফল!' : 'মুখ মেলানো যায়নি!'
        });
        
    } catch (err) {
        console.error('Match face error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ============ প্রোফাইল পিক আপলোড API ============
const profileUpload = multer({ 
    storage: multer.diskStorage({
        destination: 'uploads/profiles/',
        filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
    }),
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('শুধু ছবি ফাইল অনুমোদিত (jpg, png, gif)'));
        }
    }
}).single('profile_pic');

app.post('/api/upload-profile-pic', authenticate, (req, res) => {
    profileUpload(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'কোনো ছবি নির্বাচন করা হয়নি' });
        }
        
        const userId = req.user.id;
        const profilePicUrl = `/uploads/profiles/${req.file.filename}`;
        
        try {
            await pool.query('UPDATE users SET profile_pic = $1 WHERE id = $2', [profilePicUrl, userId]);
            res.json({ success: true, profile_pic: profilePicUrl });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
});

app.get('/api/check-profile-pic', authenticate, async (req, res) => {
    const userId = req.user.id;
    
    try {
        const result = await pool.query('SELECT profile_pic FROM users WHERE id = $1', [userId]);
        res.json({ hasProfilePic: !!result.rows[0]?.profile_pic });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ অ্যাডমিন কন্ট্রোল API ============
app.post('/admin/update-site-settings', authenticate, isAdmin, async (req, res) => {
    const { site_name, theme_color, face_verification_enabled, withdrawal_fee_percent, default_min_withdraw } = req.body;
    
    try {
        await pool.query(
            `UPDATE site_settings 
             SET site_name = COALESCE($1, site_name),
                 theme_color = COALESCE($2, theme_color),
                 face_verification_enabled = COALESCE($3, face_verification_enabled),
                 withdrawal_fee_percent = COALESCE($4, withdrawal_fee_percent),
                 default_min_withdraw = COALESCE($5, default_min_withdraw),
                 updated_at = NOW()
             WHERE id = 1`,
            [site_name, theme_color, face_verification_enabled, withdrawal_fee_percent, default_min_withdraw]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/admin/update-package', authenticate, isAdmin, async (req, res) => {
    const { level, price, daily_tasks, task_rate, min_withdraw, expiry_days } = req.body;
    
    try {
        await pool.query(
            `UPDATE level_packages 
             SET price = $1, daily_tasks = $2, task_rate = $3, min_withdraw = $4, expiry_days = $5 
             WHERE level = $6`,
            [price, daily_tasks, task_rate, min_withdraw, expiry_days || 0, level]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/admin/update-referral-rates', authenticate, isAdmin, async (req, res) => {
    const { gen1, gen2, gen3 } = req.body;
    
    try {
        const rates = JSON.stringify({ gen1: parseFloat(gen1), gen2: parseFloat(gen2), gen3: parseFloat(gen3) });
        await pool.query(
            `UPDATE site_settings SET referral_rates = $1, updated_at = NOW() WHERE id = 1`,
            [rates]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/admin/toggle-face-verification', authenticate, isAdmin, async (req, res) => {
    const { enabled } = req.body;
    
    try {
        await pool.query(
            `UPDATE site_settings SET face_verification_enabled = $1, updated_at = NOW() WHERE id = 1`,
            [enabled]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// নতুন লেভেল যোগ করুন
app.post('/admin/add-new-level', authenticate, isAdmin, async (req, res) => {
    const { level, price, daily_tasks, task_rate, min_withdraw } = req.body;
    try {
        await pool.query('INSERT INTO level_packages (level, price, daily_tasks, task_rate, min_withdraw) VALUES ($1, $2, $3, $4, $5)', [level, price, daily_tasks, task_rate, min_withdraw]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ইউজার লেভেল পরিবর্তন করুন
app.post('/admin/change-user-level', authenticate, isAdmin, async (req, res) => {
    const { userId, level } = req.body;
    try {
        await pool.query('UPDATE users SET level = $1, purchase_date = NOW() WHERE id = $2', [level, userId]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// প্যাকেজ মেয়াদ নির্ধারণ করুন
app.post('/admin/set-package-expiry', authenticate, isAdmin, async (req, res) => {
    const { level, expiry_days } = req.body;
    try {
        await pool.query('UPDATE level_packages SET expiry_days = $1 WHERE level = $2', [expiry_days, level]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// সবাইকে বিজ্ঞপ্তি দিন
app.post('/admin/send-notification-to-all', authenticate, isAdmin, async (req, res) => {
    const { title, message } = req.body;
    try {
        await pool.query('INSERT INTO notifications (title, message, created_at) VALUES ($1, $2, NOW())', [title, message]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// নির্দিষ্ট ইউজারকে বিজ্ঞপ্তি দিন
app.post('/admin/send-notification-to-user', authenticate, isAdmin, async (req, res) => {
    const { userId, title, message } = req.body;
    try {
        await pool.query('INSERT INTO notifications (user_id, title, message, created_at) VALUES ($1, $2, $3, NOW())', [userId, title, message]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ইউজারের নোটিফিকেশন দেখার API
app.get('/api/my-notifications', authenticate, async (req, res) => {
    const userId = req.user.id;
    try {
        const notifications = await pool.query(
            `SELECT * FROM notifications 
             WHERE user_id IS NULL OR user_id = $1 
             ORDER BY created_at DESC LIMIT 10`,
            [userId]
        );
        res.json(notifications.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ইউজারের টাস্ক বন্ধ/চালু করুন
app.post('/admin/block-user-tasks', authenticate, isAdmin, async (req, res) => {
    const { userId, blocked } = req.body;
    try {
        await pool.query('UPDATE users SET tasks_blocked = $1 WHERE id = $2', [blocked, userId]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// সবাইকে বন্ধ করুন
app.post('/admin/block-all-users', authenticate, isAdmin, async (req, res) => {
    try {
        await pool.query('UPDATE users SET tasks_blocked = true WHERE role != $1', ['admin']);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// নির্দিষ্ট তারিখে বন্ধ রাখুন
app.post('/admin/block-on-date', authenticate, isAdmin, async (req, res) => {
    const { date, blocked } = req.body;
    try {
        await pool.query('INSERT INTO blocked_dates (block_date, is_blocked) VALUES ($1, $2) ON CONFLICT (block_date) DO UPDATE SET is_blocked = $2', [date, blocked]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ চেক ইউজার টাস্ক করতে পারবে কিনা (লেভেল 0 সাপোর্ট সহ) ============
app.get('/api/can-do-task', authenticate, async (req, res) => {
    const userId = req.user.id;
    
    try {
        const user = await pool.query('SELECT level, tasks_blocked, status FROM users WHERE id = $1', [userId]);
        
        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (user.rows[0].status === 'blocked') {
            return res.json({ canDo: false, message: 'আপনার অ্যাকাউন্ট ব্লক করা আছে। অ্যাডমিনের সাথে যোগাযোগ করুন।' });
        }
        
        if (user.rows[0].tasks_blocked === true) {
            return res.json({ canDo: false, message: 'আপনার টাস্ক করা বন্ধ আছে। অ্যাডমিনের সাথে যোগাযোগ করুন।' });
        }
        
        const today = new Date().toISOString().slice(0, 10);
        const blockedDate = await pool.query(
            'SELECT id FROM blocked_dates WHERE block_date = $1 AND is_blocked = true',
            [today]
        );
        if (blockedDate.rows.length > 0) {
            return res.json({ canDo: false, message: 'আজকে টাস্ক বন্ধ রাখা হয়েছে।' });
        }
        
        const userLevel = user.rows[0].level;
        
        // ✅ লেভেল 0 এর জন্য প্যাকেজ চেক করবেন না (সরাসরি টাস্ক করতে পারবে)
        if (userLevel === 1) {
            const hasPackage = await pool.query(
                'SELECT id FROM purchase_requests WHERE user_id = $1 AND level = 1 AND status = $2',
                [userId, 'approved']
            );
            
            if (hasPackage.rows.length === 0) {
                return res.json({ 
                    canDo: false, 
                    message: 'টাস্ক শুরু করতে লেভেল 1 প্যাকেজ কিনুন!',
                    packagePrice: 500
                });
            }
        }
        
        res.json({ canDo: true, level: userLevel });
        
    } catch (err) {
        console.error('Can-do-task error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ============ সার্ভার স্টার্ট ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// ============ অ্যাডমিন: পাসওয়ার্ড রিসেট API ============

// লগইন পাসওয়ার্ড রিসেট
app.post('/admin/reset-login-password', authenticate, isAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    
    try {
        if (!newPassword || newPassword.length < 4) {
            return res.status(400).json({ error: 'পাসওয়ার্ড কমপক্ষে 4 অক্ষরের হতে হবে!' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// উত্তোলন পাসওয়ার্ড রিসেট
app.post('/admin/reset-withdraw-password', authenticate, isAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    
    try {
        if (!newPassword || newPassword.length < 4) {
            return res.status(400).json({ error: 'পাসওয়ার্ড কমপক্ষে 4 অক্ষরের হতে হবে!' });
        }
        
        await pool.query(
            'UPDATE withdrawal_accounts SET withdraw_password = $1 WHERE user_id = $2 AND is_active = true',
            [newPassword, userId]
        );
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});