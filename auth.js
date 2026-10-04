const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { q } = require('./db');

function secret() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 24) throw new Error('JWT_SECRET must be at least 24 characters');
  return s;
}

function signUser(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role, contact: user.contact },
    secret(),
    { expiresIn: '30d' }
  );
}

function safeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    user_id: row.id,
    name: row.name,
    contact: row.contact,
    role: row.role,
    user_role: row.role,
    wallet: Number(row.wallet_balance || 0),
    wallet_balance: Number(row.wallet_balance || 0),
    is_admin: row.role === 'admin',
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function ensurePrincipalAdmin() {
  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (!email || !password) return;
  const existing = await q('SELECT id FROM users WHERE LOWER(contact)=LOWER($1) LIMIT 1', [email]);
  const hash = await bcrypt.hash(password, 12);
  if (!existing.rows.length) {
    await q(`INSERT INTO users(name,contact,password_hash,role) VALUES($1,$2,$3,'admin')`, [process.env.ADMIN_NAME || 'FLEX TUPUP Admin', email, hash]);
  } else {
    await q(`UPDATE users SET role='admin', password_hash=$2, updated_at=NOW() WHERE id=$1`, [existing.rows[0].id, hash]);
  }
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Connexion requise.' });
    const payload = jwt.verify(token, secret());
    const result = await q('SELECT * FROM users WHERE id=$1 AND is_active=TRUE', [payload.sub]);
    if (!result.rows.length) return res.status(401).json({ error: 'USER_NOT_FOUND', message: 'Compte introuvable.' });
    req.user = safeUser(result.rows[0]);
    req.rawUser = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'INVALID_TOKEN', message: 'Session invalide ou expirée.' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin' && req.user?.is_admin !== true) {
    return res.status(403).json({ error: 'ADMIN_REQUIRED', message: 'Accès réservé à l’administrateur.' });
  }
  next();
}

module.exports = { bcrypt, signUser, safeUser, ensurePrincipalAdmin, authMiddleware, adminOnly };
