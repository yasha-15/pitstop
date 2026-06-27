require('dotenv').config();
const express      = require('express');
const path         = require('path');
const fs           = require('fs');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const nodemailer   = require('nodemailer');
const { v4: uuid } = require('uuid');
const initSqlJs    = require('sql.js');
const cookieParser = require('cookie-parser');

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3000;
const BASE_URL   = process.env.BASE_URL   || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_dev_secret_change_me';
const JWT_EXPIRY = '365d';
// On Railway/cloud the app dir may be read-only; use /tmp for the DB
const DB_PATH    = process.env.DB_PATH || path.join(__dirname, 'db.sqlite');

// ─── Database (sql.js — pure JS, no native build needed) ─────────────────────
let db;

async function initDb() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT    NOT NULL,
      email         TEXT    NOT NULL UNIQUE,
      password_hash TEXT,
      verified      INTEGER NOT NULL DEFAULT 0,
      created_at    DATETIME DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS otps (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      email      TEXT    NOT NULL,
      otp        TEXT    NOT NULL,
      name       TEXT,
      expires_at DATETIME NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS reset_tokens (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      token      TEXT    NOT NULL UNIQUE,
      expires_at DATETIME NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS communities (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT    NOT NULL,
      owner_id    INTEGER NOT NULL,
      created_at  DATETIME DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS community_members (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      community_id INTEGER NOT NULL,
      user_id      INTEGER NOT NULL,
      joined_at    DATETIME DEFAULT (datetime('now')),
      UNIQUE(community_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS community_invites (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      community_id INTEGER NOT NULL,
      email        TEXT    NOT NULL,
      token        TEXT    NOT NULL UNIQUE,
      expires_at   DATETIME NOT NULL,
      used         INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      text        TEXT    NOT NULL,
      done        INTEGER NOT NULL DEFAULT 0,
      created_at  DATETIME DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS polls (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      community_id INTEGER NOT NULL,
      creator_id   INTEGER NOT NULL,
      question     TEXT NOT NULL,
      created_at   DATETIME DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS poll_options (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      poll_id   INTEGER NOT NULL,
      option_text TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS poll_votes (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      poll_id   INTEGER NOT NULL,
      option_id INTEGER NOT NULL,
      user_id   INTEGER NOT NULL,
      UNIQUE(poll_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      community_id INTEGER NOT NULL,
      user_id      INTEGER NOT NULL,
      text         TEXT NOT NULL,
      created_at   DATETIME DEFAULT (datetime('now'))
    );
  `);

  // Dynamically add columns if they don't exist
  try {
    db.run('ALTER TABLE community_members ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
  } catch (e) {
    // Column already exists
  }

  try {
    db.run('ALTER TABLE users ADD COLUMN profile_pic TEXT');
  } catch (e) {
    // Column already exists
  }

  saveDb();
  console.log('  ✓  Database ready');
}

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Helper: run a query and save
function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

// Helper: get one row
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

// Helper: get all rows
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ─── Email transporter (Google Apps Script HTTP Relay) ─────────────────────────
async function sendMail({ to, subject, html }) {
  const url = process.env.EMAIL_SCRIPT_URL || 'https://script.google.com/macros/s/AKfycbyHfk49kHS3JjB28jCLb6hsnOjCJml5AGdh8L-XdPSDCca9K9j4pY1bwWymmxC3tdE/exec';
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to, subject, html })
  });
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const result = await response.json();
  if (result.status !== 'success') {
    throw new Error(result.error || 'Failed to send email via Apps Script relay.');
  }
}

// ─── Email templates ──────────────────────────────────────────────────────────
function otpEmailHtml(name, otp) {
  return `
  <div style="font-family:'Courier New',monospace;background:#111318;color:#c9d1d9;padding:36px;border-radius:12px;max-width:480px;margin:0 auto;">
    <p style="color:#4ec9b0;margin:0 0 8px;">// pitstop</p>
    <h2 style="margin:0 0 24px;font-size:20px;">Your verification code</h2>
    <p style="margin:0 0 8px;">Hi <strong>${name}</strong>,</p>
    <p style="margin:0 0 24px;color:#8b949e;">Use the code below to verify your email. It expires in <strong style="color:#c9d1d9;">10 minutes</strong>.</p>
    <div style="background:#1c2028;border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:20px;text-align:center;letter-spacing:0.3em;font-size:32px;color:#28c840;margin-bottom:24px;">${otp}</div>
    <p style="color:#555c6e;font-size:12px;margin:0;">If you didn't request this, you can safely ignore this email.</p>
  </div>`;
}

function resetEmailHtml(resetUrl) {
  return `
  <div style="font-family:'Courier New',monospace;background:#111318;color:#c9d1d9;padding:36px;border-radius:12px;max-width:480px;margin:0 auto;">
    <p style="color:#4ec9b0;margin:0 0 8px;">// pitstop</p>
    <h2 style="margin:0 0 24px;font-size:20px;">Reset your password</h2>
    <p style="margin:0 0 24px;color:#8b949e;">Click the button below to reset your password. This link expires in <strong style="color:#c9d1d9;">1 hour</strong>.</p>
    <a href="${resetUrl}" style="display:inline-block;background:#1a4d2a;border:1.5px solid #28c840;color:#28c840;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:14px;letter-spacing:0.04em;">reset password &rarr;</a>
    <p style="color:#555c6e;font-size:12px;margin-top:24px;">If you didn't request a password reset, you can safely ignore this email.</p>
    <p style="color:#404855;font-size:11px;margin:8px 0 0;word-break:break-all;">Or copy this link: ${resetUrl}</p>
  </div>`;
}

function communityInviteEmailHtml(inviterName, communityName, joinUrl) {
  return `
  <div style="font-family:'Courier New',monospace;background:#111318;color:#c9d1d9;padding:36px;border-radius:12px;max-width:480px;margin:0 auto;">
    <p style="color:#4ec9b0;margin:0 0 8px;">// pitstop</p>
    <h2 style="margin:0 0 24px;font-size:20px;">You've been invited to a community</h2>
    <p style="margin:0 0 8px;"><strong>${inviterName}</strong> has invited you to join the community <strong style="color:#28c840;">${communityName}</strong>.</p>
    <p style="margin:0 0 24px;color:#8b949e;">Click the button below to join. This invite expires in <strong style="color:#c9d1d9;">48 hours</strong>.</p>
    <a href="${joinUrl}" style="display:inline-block;background:#1a4d2a;border:1.5px solid #28c840;color:#28c840;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:14px;letter-spacing:0.04em;">join community &rarr;</a>
    <p style="color:#555c6e;font-size:12px;margin-top:24px;">You need a Pitstop account to join. If you don't have one, you'll be prompted to create one.</p>
    <p style="color:#404855;font-size:11px;margin:8px 0 0;word-break:break-all;">Or copy this link: ${joinUrl}</p>
  </div>`;
}

// ─── JWT middleware ────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
}

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(__dirname));

app.get('/', (_req, res) => res.redirect('/auth.html'));

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── 1. Send OTP ───────────────────────────────────────────────────────────────
app.post('/api/auth/send-otp', async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required.' });

  const emailLower = email.toLowerCase().trim();
  const existing   = dbGet('SELECT verified FROM users WHERE email = ?', [emailLower]);
  if (existing?.verified) {
    return res.status(409).json({ error: 'An account with this email already exists. Please log in.' });
  }

  const otp     = generateOTP();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  dbRun('UPDATE otps SET used = 1 WHERE email = ?', [emailLower]);
  dbRun('INSERT INTO otps (email, otp, name, expires_at) VALUES (?, ?, ?, ?)', [emailLower, otp, name, expires]);

  try {
    await sendMail({ to: emailLower, subject: 'Your Pitstop verification code', html: otpEmailHtml(name, otp) });
    res.json({ message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ error: 'Failed to send email. Check your .env EMAIL_USER and EMAIL_PASS.' });
  }
});

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── 2. Verify OTP ─────────────────────────────────────────────────────────────
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required.' });

  const emailLower = email.toLowerCase().trim();
  const record = dbGet(
    'SELECT * FROM otps WHERE email = ? AND used = 0 ORDER BY id DESC LIMIT 1',
    [emailLower]
  );

  if (!record)                              return res.status(400).json({ error: 'No OTP found. Please request a new one.' });
  if (new Date(record.expires_at) < new Date()) return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
  if (record.otp !== otp.trim())            return res.status(400).json({ error: 'Invalid OTP. Please try again.' });

  dbRun('UPDATE otps SET used = 1 WHERE id = ?', [record.id]);

  const verifyToken = jwt.sign(
    { email: emailLower, name: record.name, step: 'otp_verified' },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  res.json({ message: 'OTP verified.', verifyToken });
});

// ── 3. Complete signup ────────────────────────────────────────────────────────
app.post('/api/auth/complete-signup', async (req, res) => {
  const { verifyToken, password } = req.body;
  if (!verifyToken || !password) return res.status(400).json({ error: 'Missing fields.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  let decoded;
  try { decoded = jwt.verify(verifyToken, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Verification token expired. Please start over.' }); }

  if (decoded.step !== 'otp_verified') return res.status(401).json({ error: 'Invalid verification token.' });

  const { email, name } = decoded;
  const hash = await bcrypt.hash(password, 12);

  const existing = dbGet('SELECT id FROM users WHERE email = ?', [email]);
  if (existing) {
    dbRun('UPDATE users SET name = ?, password_hash = ?, verified = 1 WHERE email = ?', [name, hash, email]);
  } else {
    dbRun('INSERT INTO users (name, email, password_hash, verified) VALUES (?, ?, ?, 1)', [name, email, hash]);
  }

  const user  = dbGet('SELECT id, name, email FROM users WHERE email = ?', [email]);
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRY });

  res.cookie('token', token, { httpOnly: true, maxAge: 365 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ message: 'Account created.', token, user: { name: user.name, email: user.email } });
});

// ── 4. Login ──────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const emailLower = email.toLowerCase().trim();
  const user = dbGet('SELECT * FROM users WHERE email = ? AND verified = 1', [emailLower]);
  if (!user) return res.status(401).json({ error: 'No verified account found with this email.' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect password.' });

  const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.cookie('token', token, { httpOnly: true, maxAge: 365 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ message: 'Logged in.', token, user: { name: user.name, email: user.email, profile_pic: user.profile_pic } });
});

// ── 5. Forgot password ────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const emailLower = email.toLowerCase().trim();
  const user = dbGet('SELECT * FROM users WHERE email = ? AND verified = 1', [emailLower]);

  if (!user) return res.json({ message: 'If an account exists, a reset link has been sent.' });

  const token   = uuid();
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();

  dbRun('UPDATE reset_tokens SET used = 1 WHERE user_id = ?', [user.id]);
  dbRun('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expires]);

  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const reqBaseUrl = `${protocol}://${host}`;
  const resetUrl = `${reqBaseUrl}/reset-password.html?token=${token}`;

  try {
    await sendMail({ to: emailLower, subject: 'Reset your Pitstop password', html: resetEmailHtml(resetUrl) });
  } catch (err) {
    console.error('Email error:', err.message);
    return res.status(500).json({ error: 'Failed to send reset email. Check your credentials.' });
  }

  res.json({ message: 'If an account exists, a reset link has been sent.' });
});

// ── 6. Reset password ─────────────────────────────────────────────────────────
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Missing fields.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const record = dbGet('SELECT * FROM reset_tokens WHERE token = ? AND used = 0', [token]);
  if (!record) return res.status(400).json({ error: 'Invalid or already-used reset link.' });
  if (new Date(record.expires_at) < new Date()) return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });

  const hash = await bcrypt.hash(password, 12);
  dbRun('UPDATE users SET password_hash = ? WHERE id = ?', [hash, record.user_id]);
  dbRun('UPDATE reset_tokens SET used = 1 WHERE id = ?', [record.id]);

  res.json({ message: 'Password reset successfully. You can now log in.' });
});

// ── 7. Me (auth check) ────────────────────────────────────────────────────────
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = dbGet('SELECT id, name, email, profile_pic FROM users WHERE id = ?', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user });
});

// ── 8. Logout ─────────────────────────────────────────────────────────────────
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out.' });
});

// ── 9. Update profile (name, avatar) ───────────────────────────────────────────
app.post('/api/user/update-profile', requireAuth, (req, res) => {
  const { name, profilePic } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required.' });

  dbRun('UPDATE users SET name = ?, profile_pic = ? WHERE id = ?', [name.trim(), profilePic || null, req.user.id]);
  const user = dbGet('SELECT id, name, email, profile_pic FROM users WHERE id = ?', [req.user.id]);
  res.json({ message: 'Profile updated.', user });
});

// ── 10. Change password ────────────────────────────────────────────────────────
app.post('/api/user/change-password', requireAuth, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password is required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const hash = await bcrypt.hash(password, 12);
  dbRun('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
  res.json({ message: 'Password changed successfully.' });
});

// ══════════════════════════════════════════════════════════════════════════════
//  TASK ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Get all tasks for user
app.get('/api/tasks', requireAuth, (req, res) => {
  const tasks = dbAll('SELECT id, text, done FROM tasks WHERE user_id = ? ORDER BY id ASC', [req.user.id]);
  res.json({ tasks });
});

// Add a task
app.post('/api/tasks', requireAuth, (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Task text is required.' });
  dbRun('INSERT INTO tasks (user_id, text, done) VALUES (?, ?, 0)', [req.user.id, text.trim()]);
  const task = dbGet('SELECT id, text, done FROM tasks WHERE user_id = ? ORDER BY id DESC LIMIT 1', [req.user.id]);
  res.json({ task });
});

// Toggle a task
app.post('/api/tasks/toggle', requireAuth, (req, res) => {
  const { id, done } = req.body;
  if (id === undefined || done === undefined) return res.status(400).json({ error: 'Missing fields.' });
  dbRun('UPDATE tasks SET done = ? WHERE id = ? AND user_id = ?', [done ? 1 : 0, id, req.user.id]);
  res.json({ message: 'Task updated.' });
});

// Delete a task
app.post('/api/tasks/delete', requireAuth, (req, res) => {
  const { id } = req.body;
  if (id === undefined) return res.status(400).json({ error: 'Missing task ID.' });
  dbRun('DELETE FROM tasks WHERE id = ? AND user_id = ?', [id, req.user.id]);
  res.json({ message: 'Task deleted.' });
});

// Sync local tasks (bulk save)
app.post('/api/tasks/sync', requireAuth, (req, res) => {
  const { tasks } = req.body;
  if (!Array.isArray(tasks)) return res.status(400).json({ error: 'Tasks array is required.' });
  for (const t of tasks) {
    if (t.text && t.text.trim()) {
      dbRun('INSERT INTO tasks (user_id, text, done) VALUES (?, ?, ?)', [req.user.id, t.text.trim(), t.done ? 1 : 0]);
    }
  }
  res.json({ message: 'Tasks synced successfully.' });
});

// ══════════════════════════════════════════════════════════════════════════════
//  COMMUNITY ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── 1. Create community ───────────────────────────────────────────────────────
app.post('/api/communities/create', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Community name is required.' });

  dbRun('INSERT INTO communities (name, owner_id) VALUES (?, ?)', [name.trim(), req.user.id]);
  const community = dbGet('SELECT * FROM communities WHERE owner_id = ? ORDER BY id DESC LIMIT 1', [req.user.id]);

  // Automatically add creator as member and admin
  dbRun('INSERT OR IGNORE INTO community_members (community_id, user_id, is_admin) VALUES (?, ?, 1)', [community.id, req.user.id]);

  res.json({ message: 'Community created.', community });
});

// ── 2. Send invite emails ─────────────────────────────────────────────────────
app.post('/api/communities/invite', requireAuth, async (req, res) => {
  const { communityId, emails } = req.body;
  if (!communityId || !emails || !emails.length) {
    return res.status(400).json({ error: 'Community ID and at least one email are required.' });
  }

  const community = dbGet('SELECT * FROM communities WHERE id = ?', [communityId]);
  if (!community) return res.status(404).json({ error: 'Community not found.' });

  // Only owner or members can invite
  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  const inviter = dbGet('SELECT name FROM users WHERE id = ?', [req.user.id]);
  const results = [];

  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const reqBaseUrl = `${protocol}://${host}`;

  for (const rawEmail of emails) {
    const email = rawEmail.toLowerCase().trim();
    if (!email) continue;

    const token   = uuid();
    const expires = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();

    // Invalidate old unused invites for same email+community
    dbRun('UPDATE community_invites SET used = 1 WHERE community_id = ? AND email = ? AND used = 0', [communityId, email]);
    dbRun('INSERT INTO community_invites (community_id, email, token, expires_at) VALUES (?, ?, ?, ?)', [communityId, email, token, expires]);

    const joinUrl = `${reqBaseUrl}/join.html?token=${token}`;
    try {
      await sendMail({
        to: email,
        subject: `${inviter.name} invited you to "${community.name}" on Pitstop`,
        html: communityInviteEmailHtml(inviter.name, community.name, joinUrl),
      });
      results.push({ email, status: 'sent' });
    } catch (err) {
      console.error('Invite email error:', err.message);
      results.push({ email, status: 'failed' });
    }
  }

  res.json({ message: 'Invites processed.', results });
});

// ── 2b. Get or Create Direct Shareable Invite Link ─────────────────────────────
app.get('/api/communities/:id/direct-invite', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const community = dbGet('SELECT * FROM communities WHERE id = ?', [communityId]);
  if (!community) return res.status(404).json({ error: 'Community not found.' });

  // Verify membership
  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  // Find active general invite link (email is "", used is 0, not expired)
  let invite = dbGet('SELECT token FROM community_invites WHERE community_id = ? AND email = "" AND used = 0 AND datetime(expires_at) > datetime("now") LIMIT 1', [communityId]);
  
  if (!invite) {
    const token = uuid();
    const expires = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
    dbRun('INSERT INTO community_invites (community_id, email, token, expires_at) VALUES (?, "", ?, ?)', [communityId, token, expires]);
    invite = { token };
  }

  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const reqBaseUrl = `${protocol}://${host}`;

  const directLink = `${reqBaseUrl}/join.html?token=${invite.token}`;
  res.json({ directLink });
});

// ── 3. Join via token ─────────────────────────────────────────────────────────
app.get('/api/communities/join', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token is required.' });

  const invite = dbGet('SELECT * FROM community_invites WHERE token = ? AND used = 0', [token]);
  if (!invite) return res.status(400).json({ error: 'Invalid or already-used invite link.' });
  if (new Date(invite.expires_at) < new Date()) return res.status(400).json({ error: 'Invite link has expired.' });

  const community = dbGet('SELECT * FROM communities WHERE id = ?', [invite.community_id]);

  let user = null;
  if (invite.email && invite.email !== '') {
    // Email-specific invite
    user = dbGet('SELECT id, name, email FROM users WHERE email = ? AND verified = 1', [invite.email]);
    if (!user) {
      return res.status(403).json({
        error: 'no_account',
        message: `You don't have an account on Pitstop. Create one to join "${community.name}".`,
        communityName: community.name,
      });
    }
  } else {
    // General direct invite link
    const authHeader = req.headers.authorization;
    const cookieToken = req.cookies && req.cookies.token;
    const tokenStr = cookieToken || (authHeader && authHeader.split(' ')[1]);
    
    if (!tokenStr) {
      return res.status(401).json({
        error: 'not_logged_in',
        message: `You must log in to join "${community.name}".`,
        communityName: community.name
      });
    }
    try {
      const decoded = jwt.verify(tokenStr, JWT_SECRET);
      user = dbGet('SELECT id, name, email FROM users WHERE id = ? AND verified = 1', [decoded.id]);
    } catch (err) {
      return res.status(401).json({
        error: 'not_logged_in',
        message: `Session expired. Please log in to join "${community.name}".`,
        communityName: community.name
      });
    }
    if (!user) {
      return res.status(401).json({
        error: 'not_logged_in',
        message: `User account not found. Please log in again.`,
        communityName: community.name
      });
    }
  }

  // Check if already a member
  const alreadyMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [invite.community_id, user.id]);
  if (alreadyMember) {
    if (invite.email && invite.email !== '') {
      dbRun('UPDATE community_invites SET used = 1 WHERE id = ?', [invite.id]);
    }
    return res.json({ message: 'already_member', communityName: community.name, user: { name: user.name } });
  }

  // Join the community
  dbRun('INSERT OR IGNORE INTO community_members (community_id, user_id) VALUES (?, ?)', [invite.community_id, user.id]);
  if (invite.email && invite.email !== '') {
    dbRun('UPDATE community_invites SET used = 1 WHERE id = ?', [invite.id]);
  }

  res.json({ message: 'joined', communityName: community.name, user: { name: user.name } });
});

// ── 4. List my communities ────────────────────────────────────────────────────
app.get('/api/communities/mine', requireAuth, (req, res) => {
  const communities = dbAll(`
    SELECT c.id, c.name, c.owner_id,
           (SELECT COUNT(*) FROM community_members cm WHERE cm.community_id = c.id) AS member_count
    FROM communities c
    INNER JOIN community_members cm ON cm.community_id = c.id
    WHERE cm.user_id = ?
    ORDER BY c.created_at DESC
  `, [req.user.id]);

  // For each community, get members
  const result = communities.map(c => {
    const members = dbAll(`
      SELECT u.name, u.email
      FROM community_members cm
      INNER JOIN users u ON u.id = cm.user_id
      WHERE cm.community_id = ?
    `, [c.id]);
    return { ...c, members };
  });

  res.json({ communities: result });
});

// ── 5. Community Leaderboard ──────────────────────────────────────────────────
app.get('/api/communities/:id/leaderboard', requireAuth, (req, res) => {
  const communityId = req.params.id;

  // Verify membership
  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  const members = dbAll(`
    SELECT u.id, u.name, u.email, u.profile_pic,
           (SELECT COUNT(*) FROM tasks t WHERE t.user_id = u.id) AS total_tasks,
           (SELECT COUNT(*) FROM tasks t WHERE t.user_id = u.id AND t.done = 1) AS completed_tasks
    FROM community_members cm
    INNER JOIN users u ON u.id = cm.user_id
    WHERE cm.community_id = ?
  `, [communityId]);

  // Compute percentages and sort
  const leaderboard = members.map(m => {
    const total = m.total_tasks;
    const completed = m.completed_tasks;
    const percentage = total === 0 ? 0 : Math.round((completed / total) * 100);
    return {
      id: m.id,
      name: m.name,
      email: m.email,
      profile_pic: m.profile_pic,
      total_tasks: total,
      completed_tasks: completed,
      percentage
    };
  }).sort((a, b) => b.percentage - a.percentage || b.completed_tasks - a.completed_tasks || a.name.localeCompare(b.name));

  res.json({ leaderboard });
});

// ── 6. Get members list ────────────────────────────────────────────────────────
app.get('/api/communities/:id/members', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const isMember = dbGet('SELECT id, is_admin FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  const members = dbAll(`
    SELECT u.id, u.name, u.email, u.profile_pic, cm.is_admin
    FROM community_members cm
    INNER JOIN users u ON u.id = cm.user_id
    WHERE cm.community_id = ?
    ORDER BY cm.is_admin DESC, u.name ASC
  `, [communityId]);

  res.json({ members, currentUserIsAdmin: !!isMember.is_admin });
});

// ── 7. Promote member to admin ──────────────────────────────────────────────────
app.post('/api/communities/:id/promote', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'User ID is required.' });

  // Caller must be an admin
  const caller = dbGet('SELECT id, is_admin FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!caller || !caller.is_admin) return res.status(403).json({ error: 'Only admins can promote other members.' });

  dbRun('UPDATE community_members SET is_admin = 1 WHERE community_id = ? AND user_id = ?', [communityId, userId]);
  res.json({ message: 'Member promoted to admin.' });
});

// ── 7b. Exit community ──────────────────────────────────────────────────────────
app.post('/api/communities/:id/leave', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const community = dbGet('SELECT owner_id FROM communities WHERE id = ?', [communityId]);
  if (!community) return res.status(404).json({ error: 'Community not found.' });

  if (community.owner_id === req.user.id) {
    return res.status(400).json({ error: 'As the owner, you cannot leave the community. Delete the community instead.' });
  }

  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(400).json({ error: 'You are not a member of this community.' });

  dbRun('DELETE FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  res.json({ message: 'Left community successfully.' });
});

// ── 7c. Delete community ────────────────────────────────────────────────────────
app.post('/api/communities/:id/delete', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const community = dbGet('SELECT owner_id FROM communities WHERE id = ?', [communityId]);
  if (!community) return res.status(404).json({ error: 'Community not found.' });

  if (community.owner_id !== req.user.id) {
    return res.status(403).json({ error: 'Only the community owner can delete it.' });
  }

  // Delete all associations
  dbRun('DELETE FROM poll_options WHERE poll_id IN (SELECT id FROM polls WHERE community_id = ?)', [communityId]);
  dbRun('DELETE FROM poll_votes WHERE poll_id IN (SELECT id FROM polls WHERE community_id = ?)', [communityId]);
  dbRun('DELETE FROM polls WHERE community_id = ?', [communityId]);
  dbRun('DELETE FROM messages WHERE community_id = ?', [communityId]);
  dbRun('DELETE FROM community_invites WHERE community_id = ?', [communityId]);
  dbRun('DELETE FROM community_members WHERE community_id = ?', [communityId]);
  dbRun('DELETE FROM communities WHERE id = ?', [communityId]);

  res.json({ message: 'Community deleted successfully.' });
});

// ── 7d. Remove member (kick) ────────────────────────────────────────────────────
app.post('/api/communities/:id/remove-member', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'User ID is required.' });

  const community = dbGet('SELECT owner_id FROM communities WHERE id = ?', [communityId]);
  if (!community) return res.status(404).json({ error: 'Community not found.' });

  // Caller must be an admin
  const caller = dbGet('SELECT is_admin FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!caller || !caller.is_admin) {
    return res.status(403).json({ error: 'Only admins can remove members.' });
  }

  // Cannot remove owner
  if (community.owner_id === userId) {
    return res.status(400).json({ error: 'Cannot remove the community owner.' });
  }

  // Cannot remove oneself
  if (req.user.id === userId) {
    return res.status(400).json({ error: 'Use the exit community option to leave.' });
  }

  dbRun('DELETE FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, userId]);
  res.json({ message: 'Member removed successfully.' });
});

// ── 8. List polls ──────────────────────────────────────────────────────────────
app.get('/api/communities/:id/polls', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  const polls = dbAll('SELECT p.id, p.question, p.created_at, u.name as creator_name FROM polls p INNER JOIN users u ON u.id = p.creator_id WHERE p.community_id = ? ORDER BY p.created_at DESC', [communityId]);
  
  const result = polls.map(p => {
    const options = dbAll('SELECT id, option_text FROM poll_options WHERE poll_id = ?', [p.id]);
    
    // For each option, calculate votes
    const optionsWithVotes = options.map(o => {
      const votes = dbGet('SELECT COUNT(*) as count FROM poll_votes WHERE option_id = ?', [o.id]);
      return { ...o, votes: votes.count || 0 };
    });

    // Check if current user voted and which option
    const userVote = dbGet('SELECT option_id FROM poll_votes WHERE poll_id = ? AND user_id = ?', [p.id, req.user.id]);

    return {
      ...p,
      options: optionsWithVotes,
      votedOptionId: userVote ? userVote.option_id : null,
      totalVotes: optionsWithVotes.reduce((sum, opt) => sum + opt.votes, 0)
    };
  });

  res.json({ polls: result });
});

// ── 9. Create a poll ────────────────────────────────────────────────────────────
app.post('/api/communities/:id/polls', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const { question, options } = req.body;
  
  if (!question || !question.trim()) return res.status(400).json({ error: 'Question is required.' });
  if (!Array.isArray(options) || options.length < 2) return res.status(400).json({ error: 'At least two options are required.' });

  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  dbRun('INSERT INTO polls (community_id, creator_id, question) VALUES (?, ?, ?)', [communityId, req.user.id, question.trim()]);
  const poll = dbGet('SELECT id FROM polls WHERE community_id = ? AND creator_id = ? ORDER BY id DESC LIMIT 1', [communityId, req.user.id]);

  for (const opt of options) {
    if (opt && opt.trim()) {
      dbRun('INSERT INTO poll_options (poll_id, option_text) VALUES (?, ?)', [poll.id, opt.trim()]);
    }
  }

  res.json({ message: 'Poll created successfully.' });
});

// ── 10. Vote on a poll ──────────────────────────────────────────────────────────
app.post('/api/communities/:id/polls/vote', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const { pollId, optionId } = req.body;
  if (!pollId || !optionId) return res.status(400).json({ error: 'Poll ID and Option ID are required.' });

  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  // Delete previous vote for this poll and user
  dbRun('DELETE FROM poll_votes WHERE poll_id = ? AND user_id = ?', [pollId, req.user.id]);
  
  // Insert new vote
  dbRun('INSERT INTO poll_votes (poll_id, option_id, user_id) VALUES (?, ?, ?)', [pollId, optionId, req.user.id]);
  
  res.json({ message: 'Vote recorded.' });
});

// ── 11. Get chat messages ───────────────────────────────────────────────────────
app.get('/api/communities/:id/messages', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  const messages = dbAll(`
    SELECT m.id, m.text, m.created_at, u.name as user_name, u.email as user_email, u.profile_pic as user_profile_pic
    FROM messages m
    INNER JOIN users u ON u.id = m.user_id
    WHERE m.community_id = ?
    ORDER BY m.created_at ASC
    LIMIT 100
  `, [communityId]);

  res.json({ messages });
});

// ── 12. Post a chat message ──────────────────────────────────────────────────────
app.post('/api/communities/:id/messages', requireAuth, (req, res) => {
  const communityId = req.params.id;
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Message cannot be empty.' });

  const isMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [communityId, req.user.id]);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this community.' });

  dbRun('INSERT INTO messages (community_id, user_id, text, created_at) VALUES (?, ?, ?, ?)', [communityId, req.user.id, text.trim(), new Date().toISOString()]);
  res.json({ message: 'Message posted.' });
});

// ─── Error Handling Middleware ────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({ error: err.message || 'Something went wrong on the server.' });
});

// ─── Bootstrap ────────────────────────────────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`\n  ✓  Pitstop  →  http://localhost:${PORT}`);
    console.log(`  ✓  Auth page  →  http://localhost:${PORT}/auth.html\n`);
    if (!process.env.EMAIL_USER || process.env.EMAIL_USER === 'your_gmail@gmail.com') {
      console.warn('  ⚠  .env not configured — email features will not work.');
      console.warn('     Copy .env.example → .env and fill in your Gmail credentials.\n');
    }
  });
}).catch(err => {
  console.error('Failed to initialise DB:', err);
  process.exit(1);
});
