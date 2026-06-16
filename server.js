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
const JWT_EXPIRY = '7d';
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
  `);

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

// ─── Email transporter ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendMail({ to, subject, html }) {
  await transporter.sendMail({
    from: `"Pitstop" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
  });
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
app.use(express.json());
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

  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
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
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ message: 'Logged in.', token, user: { name: user.name, email: user.email } });
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

  const resetUrl = `${BASE_URL}/reset-password.html?token=${token}`;
  try {
    await sendMail({ to: emailLower, subject: 'Reset your Pitstop password', html: resetEmailHtml(resetUrl) });
  } catch (err) {
    console.error('Email error:', err.message);
    return res.status(500).json({ error: 'Failed to send reset email. Check your .env credentials.' });
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
  const user = dbGet('SELECT id, name, email FROM users WHERE id = ?', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user });
});

// ── 8. Logout ─────────────────────────────────────────────────────────────────
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out.' });
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

  // Automatically add creator as member
  dbRun('INSERT OR IGNORE INTO community_members (community_id, user_id) VALUES (?, ?)', [community.id, req.user.id]);

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

  for (const rawEmail of emails) {
    const email = rawEmail.toLowerCase().trim();
    if (!email) continue;

    const token   = uuid();
    const expires = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();

    // Invalidate old unused invites for same email+community
    dbRun('UPDATE community_invites SET used = 1 WHERE community_id = ? AND email = ? AND used = 0', [communityId, email]);
    dbRun('INSERT INTO community_invites (community_id, email, token, expires_at) VALUES (?, ?, ?, ?)', [communityId, email, token, expires]);

    const joinUrl = `${BASE_URL}/join.html?token=${token}`;
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

// ── 3. Join via token ─────────────────────────────────────────────────────────
app.get('/api/communities/join', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token is required.' });

  const invite = dbGet('SELECT * FROM community_invites WHERE token = ? AND used = 0', [token]);
  if (!invite) return res.status(400).json({ error: 'Invalid or already-used invite link.' });
  if (new Date(invite.expires_at) < new Date()) return res.status(400).json({ error: 'Invite link has expired.' });

  const community = dbGet('SELECT * FROM communities WHERE id = ?', [invite.community_id]);

  // Check if the invited email has a verified account
  const user = dbGet('SELECT id, name, email FROM users WHERE email = ? AND verified = 1', [invite.email]);
  if (!user) {
    return res.status(403).json({
      error: 'no_account',
      message: `You don't have an account on Pitstop. Create one to join "${community.name}".`,
      communityName: community.name,
    });
  }

  // Check if already a member
  const alreadyMember = dbGet('SELECT id FROM community_members WHERE community_id = ? AND user_id = ?', [invite.community_id, user.id]);
  if (alreadyMember) {
    dbRun('UPDATE community_invites SET used = 1 WHERE id = ?', [invite.id]);
    return res.json({ message: 'already_member', communityName: community.name, user: { name: user.name } });
  }

  // Join the community
  dbRun('INSERT OR IGNORE INTO community_members (community_id, user_id) VALUES (?, ?)', [invite.community_id, user.id]);
  dbRun('UPDATE community_invites SET used = 1 WHERE id = ?', [invite.id]);

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
