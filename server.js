// ============================================================
//  UniVerse University — Backend Server
//  Run: node server.js
//  API runs on: http://localhost:3000
// ============================================================

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const path       = require('path');
const fs         = require('fs');
const low        = require('lowdb');
const FileSync   = require('lowdb/adapters/FileSync');

// ── DB Setup (JSON file-based, no installation needed) ──────
const adapter = new FileSync('db.json');
const db      = low(adapter);

// Default structure
db.defaults({
  users:    [],
  contacts: [],
  settings: { adminEmail: 'admin@universe.edu.pk' }
}).write();

// ── App Setup ───────────────────────────────────────────────
const app    = express();
const PORT   = 3000;
const SECRET = 'universe_secret_key_2025'; // change in production!

app.use(cors());
app.use(express.json());

// Serve the HTML frontend from same folder (if placed there)
app.use(express.static(path.join(__dirname, 'public')));

// ── HELPERS ─────────────────────────────────────────────────
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ success: false, error: 'No token provided.' });
  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, error: 'Invalid or expired token.' });
  }
}

// ════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password, degree } = req.body;

    // Validate
    if (!full_name || !email || !password || !degree)
      return res.json({ success: false, error: 'All fields are required.' });

    if (password.length < 6)
      return res.json({ success: false, error: 'Password must be at least 6 characters.' });

    // Check duplicate email
    const exists = db.get('users').find({ email: email.toLowerCase() }).value();
    if (exists)
      return res.json({ success: false, error: 'This email is already registered.' });

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Save user
    const newUser = {
      id:         generateId(),
      full_name,
      email:      email.toLowerCase(),
      password:   hashed,
      degree,
      role:       'student',
      created_at: new Date().toISOString()
    };

    db.get('users').push(newUser).write();

    console.log(`[REGISTER] New student: ${full_name} | ${email} | ${degree}`);
    res.json({ success: true, message: 'Account created successfully.' });

  } catch (err) {
    console.error('[REGISTER ERROR]', err);
    res.status(500).json({ success: false, error: 'Server error. Try again.' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.json({ success: false, error: 'Email and password required.' });

    const user = db.get('users').find({ email: email.toLowerCase() }).value();
    if (!user)
      return res.json({ success: false, error: 'No account found with this email.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.json({ success: false, error: 'Incorrect password.' });

    // Generate JWT token (expires in 7 days)
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      SECRET,
      { expiresIn: '7d' }
    );

    console.log(`[LOGIN] ${user.full_name} logged in`);

    res.json({
      success: true,
      token,
      user: {
        id:        user.id,
        full_name: user.full_name,
        email:     user.email,
        degree:    user.degree,
        role:      user.role
      }
    });

  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    res.status(500).json({ success: false, error: 'Server error. Try again.' });
  }
});

// GET /api/me  (protected — requires token)
app.get('/api/me', verifyToken, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  if (!user) return res.json({ success: false, error: 'User not found.' });

  res.json({
    success: true,
    user: {
      id:        user.id,
      full_name: user.full_name,
      email:     user.email,
      degree:    user.degree,
      role:      user.role,
      created_at: user.created_at
    }
  });
});

// ════════════════════════════════════════════════════════════
//  CONTACT ROUTE
// ════════════════════════════════════════════════════════════

// POST /api/contact
app.post('/api/contact', (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !message)
      return res.json({ success: false, error: 'Name, email, and message are required.' });

    const contact = {
      id:         generateId(),
      name,
      email,
      subject:    subject || '(No subject)',
      message,
      created_at: new Date().toISOString(),
      read:       false
    };

    db.get('contacts').push(contact).write();
    console.log(`[CONTACT] Message from: ${name} | ${email}`);

    res.json({ success: true, message: 'Message received!' });

  } catch (err) {
    console.error('[CONTACT ERROR]', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
});

// ════════════════════════════════════════════════════════════
//  ADMIN ROUTES (protected)
// ════════════════════════════════════════════════════════════

// GET /api/admin/users  — list all students
app.get('/api/admin/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ success: false, error: 'Admin access only.' });

  const users = db.get('users').map(u => ({
    id:         u.id,
    full_name:  u.full_name,
    email:      u.email,
    degree:     u.degree,
    role:       u.role,
    created_at: u.created_at
  })).value();

  res.json({ success: true, count: users.length, users });
});

// GET /api/admin/contacts  — list all messages
app.get('/api/admin/contacts', verifyToken, (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ success: false, error: 'Admin access only.' });

  const contacts = db.get('contacts').value();
  res.json({ success: true, count: contacts.length, contacts });
});

// POST /api/admin/make-admin  — promote a user to admin by email
app.post('/api/admin/make-admin', verifyToken, (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ success: false, error: 'Admin access only.' });

  const { email } = req.body;
  const user = db.get('users').find({ email: email.toLowerCase() }).value();
  if (!user) return res.json({ success: false, error: 'User not found.' });

  db.get('users').find({ email: email.toLowerCase() }).assign({ role: 'admin' }).write();
  res.json({ success: true, message: `${user.full_name} is now an admin.` });
});

// ════════════════════════════════════════════════════════════
//  MAKE YOURSELF ADMIN (one-time setup route)
//  Visit: POST http://localhost:3000/api/setup-admin
//  Body: { "email": "your@email.com", "setup_key": "universe2025" }
// ════════════════════════════════════════════════════════════
app.post('/api/setup-admin', (req, res) => {
  const { email, setup_key } = req.body;

  if (setup_key !== 'universe2025')
    return res.json({ success: false, error: 'Invalid setup key.' });

  const user = db.get('users').find({ email: email.toLowerCase() }).value();
  if (!user)
    return res.json({ success: false, error: 'Register first, then run this.' });

  db.get('users').find({ email: email.toLowerCase() }).assign({ role: 'admin' }).write();
  console.log(`[SETUP] ${user.full_name} promoted to admin`);

  res.json({ success: true, message: `✅ ${user.full_name} is now the admin/owner!` });
});

// ── Start Server ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   UniVerse University Backend         ║');
  console.log(`  ║   Running on http://localhost:${PORT}   ║`);
  console.log('  ║   Database: db.json (auto-created)   ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
});
