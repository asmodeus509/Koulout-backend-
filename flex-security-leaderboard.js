/**
 * FLEX TUPUP — Sécurité dépôts + journal anti-hack + Top recharges du mois
 * À brancher dans ton backend Express/PostgreSQL (flex-new-backend).
 *
 *   const flexSecurity = require('./flex-security-leaderboard');
 *   app.use(flexSecurity.guard(pool));                       // AVANT toutes les routes (bloque IP/users bannis + limite)
 *   app.use('/api', flexSecurity.router({ pool, requireAuth, requireAdmin }));
 *
 * IMPORTANT: ajuste les noms de tables/colonnes dans CFG ci-dessous pour qu'ils
 * correspondent à ta base. Je n'ai pas vu ton backend, donc ce sont des hypothèses.
 */
const express = require('express');

const CFG = {
  tz: 'America/Port-au-Prince',          // le mois change à minuit heure d'Haïti
  t: {
    users: 'users',                      // id, name (ou pseudo)
    deposits: 'wallet_deposits',         // id, user_id, amount, status, transaction_reference, confirmed_at
    wallets: 'wallets',                  // user_id, balance
  },
  userPseudoCol: 'name',                 // colonne affichée dans le Top (jamais email/téléphone)
  depositConfirmedValues: ['confirmed'], // statut final d'un dépôt validé
  leaderboardSize: 20,
};

const SQL_MIGRATION = `
CREATE TABLE IF NOT EXISTS security_events (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  type TEXT NOT NULL,            -- amount_tamper | admin_forbidden | login_failed | rate_limit | duplicate_tx | blocked_hit | bad_input
  severity TEXT NOT NULL DEFAULT 'medium',
  user_id TEXT, ip TEXT, path TEXT, details JSONB
);
CREATE INDEX IF NOT EXISTS security_events_created_idx ON security_events (created_at DESC);
CREATE TABLE IF NOT EXISTS security_blocks (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('ip','user')),
  value TEXT NOT NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (kind, value)
);
-- un même code de transaction ne peut jamais être utilisé deux fois
CREATE UNIQUE INDEX IF NOT EXISTS wallet_deposits_tx_unique ON ${CFG.t.deposits} (lower(transaction_reference));
CREATE INDEX IF NOT EXISTS wallet_deposits_confirmed_idx ON ${CFG.t.deposits} (confirmed_at) WHERE status = 'confirmed';
`;

const ipOf = req => String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();

async function logEvent(pool, req, type, severity, details, userId) {
  try {
    await pool.query(
      'INSERT INTO security_events (type, severity, user_id, ip, path, details) VALUES ($1,$2,$3,$4,$5,$6)',
      [type, severity || 'medium', userId ? String(userId) : (req.user && String(req.user.id)) || null, ipOf(req), req.originalUrl, details ? JSON.stringify(details) : null]
    );
  } catch (_) { /* le journal ne doit jamais casser une requête */ }
}

/* ---------- middleware global: IP/user bloqués + limiteur simple ---------- */
function guard(pool, opts = {}) {
  const WINDOW = opts.windowMs || 60_000, MAX = opts.max || 120, MAX_AUTH = opts.maxAuth || 10;
  const hits = new Map();
  let blocked = { ip: new Set(), user: new Set(), at: 0 };
  async function refresh() {
    if (Date.now() - blocked.at < 15_000) return;
    blocked.at = Date.now();
    try {
      const r = await pool.query('SELECT kind, value FROM security_blocks');
      blocked.ip = new Set(r.rows.filter(x => x.kind === 'ip').map(x => x.value));
      blocked.user = new Set(r.rows.filter(x => x.kind === 'user').map(x => x.value));
    } catch (_) {}
  }
  setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n - v.t > WINDOW) hits.delete(k); }, WINDOW).unref();
  return async (req, res, next) => {
    await refresh();
    const ip = ipOf(req);
    if (blocked.ip.has(ip)) { logEvent(pool, req, 'blocked_hit', 'low'); return res.status(403).json({ error: 'Accès refusé.' }); }
    const isAuthRoute = /\/(login|register|signup|auth)/i.test(req.path);
    const key = ip + (isAuthRoute ? '|auth' : '');
    const h = hits.get(key) || { n: 0, t: Date.now() };
    if (Date.now() - h.t > WINDOW) { h.n = 0; h.t = Date.now(); }
    h.n++; hits.set(key, h);
    if (h.n > (isAuthRoute ? MAX_AUTH : MAX)) {
      if (h.n === (isAuthRoute ? MAX_AUTH : MAX) + 1) logEvent(pool, req, 'rate_limit', 'high', { count: h.n });
      return res.status(429).json({ error: 'Trop de requêtes. Réessaie dans une minute.' });
    }
    // marque l'utilisateur bloqué si connecté plus tard (vérifié dans requireNotBlockedUser)
    req.flexBlockedUsers = blocked.user;
    // trace les refus admin (401/403 sur /admin) = tentative d'accès
    res.on('finish', () => {
      if (/\/admin\//.test(req.originalUrl) && (res.statusCode === 401 || res.statusCode === 403))
        logEvent(pool, req, 'admin_forbidden', 'high', { status: res.statusCode });
      if (isAuthRoute && res.statusCode === 401) logEvent(pool, req, 'login_failed', 'medium');
    });
    next();
  };
}

function router({ pool, requireAuth, requireAdmin }) {
  const r = express.Router();
  const T = CFG.t;

  /* ========== 1) CONFIRMATION DE DÉPÔT — MONTANT VERROUILLÉ ========== */
  // L'admin ne peut QUE confirmer ou refuser. Le crédit = le montant enregistré en base
  // quand le client a soumis le dépôt. Tout "amount" envoyé dans le body est ignoré ET signalé.
  r.post('/admin/deposits/:id/confirm', requireAuth, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(`SELECT * FROM ${T.deposits} WHERE id = $1 FOR UPDATE`, [req.params.id]);
      const dep = rows[0];
      if (!dep) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Dépôt introuvable.' }); }
      if (String(dep.status).toLowerCase() !== 'pending') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Ce dépôt est déjà traité.' }); }

      const sent = req.body && (req.body.amount ?? req.body.amount_htg ?? req.body.value);
      if (sent != null && Number(sent) !== Number(dep.amount)) {
        await client.query('ROLLBACK');
        await logEvent(pool, req, 'amount_tamper', 'critical', { deposit_id: dep.id, stored: Number(dep.amount), attempted: Number(sent) });
        return res.status(400).json({ error: 'Le montant d’un dépôt ne peut pas être modifié.' });
      }

      await client.query(`UPDATE ${T.deposits} SET status = 'confirmed', confirmed_at = now() WHERE id = $1`, [dep.id]);
      const w = await client.query(
        `INSERT INTO ${T.wallets} (user_id, balance) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET balance = ${T.wallets}.balance + EXCLUDED.balance
         RETURNING balance`, [dep.user_id, dep.amount]);
      await client.query('COMMIT');
      res.json({ ok: true, deposit: { id: dep.id, status: 'confirmed', amount: Number(dep.amount) }, balance: Number(w.rows[0].balance) });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      res.status(500).json({ error: 'Erreur serveur.' });
    } finally { client.release(); }
  });

  r.post('/admin/deposits/:id/refuse', requireAuth, requireAdmin, async (req, res) => {
    const { rowCount } = await pool.query(
      `UPDATE ${T.deposits} SET status = 'refused' WHERE id = $1 AND lower(status) = 'pending'`, [req.params.id]);
    if (!rowCount) return res.status(409).json({ error: 'Dépôt introuvable ou déjà traité.' });
    res.json({ ok: true });
  });

  /* ========== 2) JOURNAL DE SÉCURITÉ (admin) ========== */
  r.get('/admin/security/events', requireAuth, requireAdmin, async (req, res) => {
    const ev = await pool.query('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 200');
    const bl = await pool.query('SELECT * FROM security_blocks ORDER BY created_at DESC');
    const top = await pool.query(
      `SELECT ip, count(*)::int AS n, max(created_at) AS last_at FROM security_events
       WHERE created_at > now() - interval '24 hours' AND ip IS NOT NULL GROUP BY ip ORDER BY n DESC LIMIT 10`);
    res.json({ events: ev.rows, blocks: bl.rows, topIps: top.rows });
  });
  r.post('/admin/security/block', requireAuth, requireAdmin, async (req, res) => {
    const { kind, value, reason } = req.body || {};
    if (!['ip', 'user'].includes(kind) || !value) return res.status(400).json({ error: 'kind (ip|user) et value requis.' });
    await pool.query(
      'INSERT INTO security_blocks (kind, value, reason) VALUES ($1,$2,$3) ON CONFLICT (kind,value) DO UPDATE SET reason = EXCLUDED.reason',
      [kind, String(value), reason || null]);
    res.json({ ok: true });
  });
  r.post('/admin/security/unblock', requireAuth, requireAdmin, async (req, res) => {
    const { kind, value } = req.body || {};
    await pool.query('DELETE FROM security_blocks WHERE kind = $1 AND value = $2', [kind, String(value)]);
    res.json({ ok: true });
  });

  /* ========== 3) TOP RECHARGES DU MOIS (public: pseudo seulement) ========== */
  // Calculé à chaque requête sur le mois courant (heure d'Haïti) => se réinitialise tout seul le 1er du mois, sans cron.
  r.get('/leaderboard/monthly', async (req, res) => {
    const ok = CFG.depositConfirmedValues;
    const q = await pool.query(
      `SELECT u.${CFG.userPseudoCol} AS pseudo, SUM(d.amount) AS total, u.id AS uid
         FROM ${T.deposits} d JOIN ${T.users} u ON u.id = d.user_id
        WHERE d.status = ANY($1)
          AND d.confirmed_at >= date_trunc('month', now() AT TIME ZONE $2) AT TIME ZONE $2
        GROUP BY u.id, u.${CFG.userPseudoCol}
        ORDER BY total DESC, min(d.confirmed_at) ASC
        LIMIT $3`, [ok, CFG.tz, CFG.leaderboardSize]);
    const me = req.user && String(req.user.id);
    // On n'envoie JAMAIS le montant, l'email ni le téléphone: seulement rang + pseudo.
    res.set('Cache-Control', 'public, max-age=60').json({
      month: new Date().toISOString().slice(0, 7),
      top: q.rows.map((x, i) => ({ rank: i + 1, pseudo: x.pseudo, me: me ? String(x.uid) === me : false })),
    });
  });

  return r;
}

module.exports = { guard, router, logEvent, SQL_MIGRATION, CFG };
