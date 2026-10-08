'use strict';
/**
 * FLEX TUPUP — module backend (Express + PostgreSQL)
 * Remplace flex-security-leaderboard.js (ce fichier contient tout + détecte tes tables tout seul).
 *
 * Ce qu'il règle:
 *  - POST /orders           : commande payée avec le wallet = UNE transaction (verrou → solde → commande liée au client → débit)
 *  - GET  /orders           : chaque client voit SES commandes (filtrées par son compte)
 *  - PATCH|PUT /admin/orders/:id[/status] : Valider (aucun mouvement d'argent) / Refuser (remboursement 1 seule fois)
 *  - POST /admin/deposits/:id/confirm : l'admin peut CORRIGER le montant réellement reçu (prérempli avec le montant du client);
 *                                       chaque correction est journalisée (montant déclaré, montant crédité, admin)
 *  - GET  /leaderboard/monthly : Top 100 diamants du mois (pseudo + diamants, jamais d'argent), reset automatique le 1er
 *  - Sécurité: limiteur, IP/users bloqués, journal des tentatives, routes admin /admin/security/*
 *
 * BRANCHEMENT (dans ton server.js, après la création de `pool`, `requireAuth`, `requireAdmin`):
 *
 *    const flex = require('./flex-backend-module');
 *    await flex.init(pool);                                   // adapte/crée les colonnes nécessaires (sans rien supprimer)
 *    app.use(flex.guard(pool));                               // AVANT toutes les routes
 *    app.use(flex.router({ pool, requireAuth, requireAdmin })); // AVANT tes anciennes routes (pour qu'elles ne les masquent pas)
 *
 *  requireAuth doit remplir req.user.id ; requireAdmin doit refuser les non-admins.
 *  Au démarrage regarde les logs: la ligne "[FLEX] schéma détecté" montre quelles tables/colonnes ont été choisies.
 *  Variable optionnelle FLEX_WALLET_STORAGE = "wallets" ou "users.<colonne>" pour forcer où est stocké le solde.
 */
const express = require('express');

const CFG = {
  tz: 'America/Port-au-Prince',
  leaderboardSize: 100,
  maxDeposit: 1_000_000,          // plafond d'un dépôt confirmé par l'admin (HTG)
  refusedRegex: '^(refus|rejet|reject|annul|cancel|fail|chou)',
};

const S = { ready: false };

const ident = n => {
  if (!/^[A-Za-z0-9_]+$/.test(String(n))) throw new Error('identifiant SQL invalide: ' + n);
  return '"' + n + '"';
};
const ipOf = req => String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
const isTextType = t => /char|text/i.test(t || '');
const isNumType = t => /int|numeric|decimal|double|real|money/i.test(t || '');
const isTimeType = t => /timestamp|date/i.test(t || '');
const refusedRe = () => new RegExp(CFG.refusedRegex, 'i');

/* "110 Diamants", "1 000💎" → 110 / 1000 (sinon 0) */
function parseDiamonds(label) {
  const s = String(label == null ? '' : label);
  const m = s.match(/(\d[\d\s.,]*)\s*(?:diam|💎|dm\b)/i) || s.match(/^\s*(\d[\d\s.,]*)/);
  if (!m) return 0;
  const n = parseInt(m[1].replace(/[^0-9]/g, ''), 10);
  return Number.isFinite(n) ? n : 0;
}

/* ============================== INIT / DÉTECTION ============================== */
async function init(pool) {
  const q = (sql, p) => pool.query(sql, p);
  const tables = new Set((await q(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`)).rows.map(r => r.table_name));
  const colsOf = async t => {
    const r = await q(`SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1`, [t]);
    const m = {}; r.rows.forEach(x => { m[x.column_name] = x.data_type; }); return m;
  };

  /* ---- sécurité (tables propres à ce module) ---- */
  await q(`CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium', user_id TEXT, ip TEXT, path TEXT, details JSONB)`);
  await q(`CREATE INDEX IF NOT EXISTS security_events_created_idx ON security_events (created_at DESC)`);
  await q(`CREATE TABLE IF NOT EXISTS security_blocks (
    id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('ip','user')), value TEXT NOT NULL,
    reason TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (kind, value))`);

  /* ---- utilisateurs ---- */
  if (!tables.has('users')) throw new Error('[FLEX] table "users" introuvable: adapte S.users dans init()');
  const uc = await colsOf('users');
  if (!('id' in uc)) throw new Error('[FLEX] la table users doit avoir une colonne id');
  const pseudoCol = ['pseudo', 'username', 'name', 'full_name'].find(c => c in uc) || 'id';

  /* ---- commandes ---- */
  if (!tables.has('orders')) {
    await q(`CREATE TABLE orders (id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    tables.add('orders');
  }
  let oc = await colsOf('orders');
  if (!('id' in oc)) throw new Error('[FLEX] la table orders doit avoir une colonne id (clé primaire)');
  const OSPEC = {
    user:    { cands: ['user_id', 'userid', 'customer_id'],                         type: 'TEXT',                       ok: () => true },
    game:    { cands: ['game', 'game_name'],                                         type: 'TEXT',                       ok: isTextType },
    pack:    { cands: ['pack', 'plan', 'pack_name', 'product'],                      type: 'TEXT',                       ok: isTextType },
    diamonds:{ cands: ['diamonds'],                                                  type: 'INTEGER NOT NULL DEFAULT 0', ok: isNumType },
    price:   { cands: ['price', 'amount', 'total'],                                  type: 'NUMERIC',                    ok: isNumType },
    player:  { cands: ['player_id', 'playerid', 'player_uid', 'game_uid'],           type: 'TEXT',                       ok: isTextType },
    account: { cands: ['account_name', 'accountname', 'player_name', 'nickname'],    type: 'TEXT',                       ok: isTextType },
    phone:   { cands: ['phone', 'customer_phone'],                                   type: 'TEXT',                       ok: isTextType },
    status:  { cands: ['status'],                                                    type: `TEXT DEFAULT 'En attente'`,  ok: isTextType },
    payment: { cands: ['payment', 'payment_method'],                                 type: 'TEXT',                       ok: isTextType },
    cid:     { cands: ['client_order_id', 'order_id', 'reference', 'public_id'],     type: 'TEXT',                       ok: isTextType, add: 'client_order_id' },
    created: { cands: ['created_at', 'createdat', 'date'],                           type: 'TIMESTAMPTZ DEFAULT now()',  ok: isTimeType, add: 'created_at' },
  };
  const O = {};
  for (const [k, sp] of Object.entries(OSPEC)) {
    let col = sp.cands.find(c => c in oc && sp.ok(oc[c]));
    if (!col) {
      col = sp.add || sp.cands[0];
      await q(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS ${ident(col)} ${sp.type}`);
      oc[col] = 'added';
    }
    O[k] = col;
  }
  // une même commande ne peut pas être débitée deux fois pour le même client
  try { await q(`CREATE UNIQUE INDEX IF NOT EXISTS flex_orders_cid_unique ON orders (${ident(O.user)}, ${ident(O.cid)}) WHERE ${ident(O.cid)} IS NOT NULL`); } catch (_) { /* doublons anciens: on ignore */ }
  try { await q(`CREATE INDEX IF NOT EXISTS flex_orders_created_idx ON orders (${ident(O.created)})`); } catch (_) {}

  /* ---- dépôts ---- */
  const depTable = ['wallet_deposits', 'deposits', 'recharges'].find(t => tables.has(t)) || null;
  let D = null;
  if (depTable) {
    const dc = await colsOf(depTable);
    D = {
      table: depTable,
      amount: ['amount', 'amount_htg'].find(c => c in dc) || null,
      status: ['status'].find(c => c in dc) || null,
      user: ['user_id', 'userid', 'customer_id'].find(c => c in dc) || null,
    };
    for (const [k, col, type] of [['original', 'original_amount', 'NUMERIC'], ['note', 'admin_note', 'TEXT'], ['by', 'confirmed_by', 'TEXT'], ['at', 'confirmed_at', 'TIMESTAMPTZ']]) {
      if (!(col in dc)) await q(`ALTER TABLE ${ident(depTable)} ADD COLUMN IF NOT EXISTS ${col} ${type}`);
      D[k] = col;
    }
  }

  /* ---- stockage du solde ---- */
  let W = null;
  const forced = process.env.FLEX_WALLET_STORAGE;
  if (forced && forced.startsWith('users.')) W = { kind: 'col', col: forced.slice(6) };
  else if (forced === 'wallets') W = { kind: 'table' };
  else {
    let tableOk = false, tableRows = 0, colSum = 0;
    const colName = ['wallet', 'wallet_balance', 'balance', 'solde'].find(c => c in uc && isNumType(uc[c])) || null;
    if (tables.has('wallets')) {
      const wc = await colsOf('wallets');
      if ('user_id' in wc && 'balance' in wc) {
        tableOk = true;
        tableRows = Number((await q(`SELECT count(*) AS n FROM wallets WHERE balance <> 0`)).rows[0].n);
      }
    }
    if (colName) colSum = Number((await q(`SELECT count(*) AS n FROM users WHERE ${ident(colName)} <> 0`)).rows[0].n);
    if (tableOk && (tableRows >= colSum || !colName)) W = { kind: 'table' };
    else if (colName) W = { kind: 'col', col: colName };
    else {
      await q(`CREATE TABLE IF NOT EXISTS wallets (user_id TEXT PRIMARY KEY, balance NUMERIC NOT NULL DEFAULT 0)`);
      W = { kind: 'table' };
    }
  }

  /* ---- journal du wallet ---- */
  await q(`CREATE TABLE IF NOT EXISTS wallet_transactions (
    id BIGSERIAL PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL, amount NUMERIC NOT NULL, ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (type, ref))`);

  /* ---- packs (pour relire le vrai prix) ---- */
  let P = null;
  if (tables.has('packs')) {
    const pc = await colsOf('packs');
    P = {
      name: ['name', 'title', 'label'].find(c => c in pc) || null,
      price: ['price', 'price_htg', 'amount'].find(c => c in pc && isNumType(pc[c])) || null,
      qty: ['qty', 'diamonds', 'quantity'].find(c => c in pc && isNumType(pc[c])) || null,
    };
    if (!P.name || !P.price) P = null;
  }

  Object.assign(S, { ready: true, pseudoCol, O, D, W, P });
  console.log('[FLEX] schéma détecté', JSON.stringify({ users_pseudo: pseudoCol, orders: O, deposits: D, wallet: W, packs: P }));
}

/* ============================== SOLDE (adaptateur) ============================== */
async function lockBalance(c, uid) {
  if (S.W.kind === 'table') {
    await c.query(`INSERT INTO wallets (user_id, balance) SELECT $1, 0 WHERE NOT EXISTS (SELECT 1 FROM wallets WHERE user_id::text = $1)`, [uid]);
    const r = await c.query(`SELECT balance FROM wallets WHERE user_id::text = $1 FOR UPDATE`, [uid]);
    return Number(r.rows[0] ? r.rows[0].balance : 0);
  }
  const r = await c.query(`SELECT ${ident(S.W.col)} AS balance FROM users WHERE id::text = $1 FOR UPDATE`, [uid]);
  return Number(r.rows[0] ? r.rows[0].balance : 0);
}
async function addBalance(c, uid, delta) {
  if (S.W.kind === 'table') {
    const r = await c.query(`UPDATE wallets SET balance = balance + $2 WHERE user_id::text = $1 RETURNING balance`, [uid, delta]);
    return Number(r.rows[0].balance);
  }
  const r = await c.query(`UPDATE users SET ${ident(S.W.col)} = ${ident(S.W.col)} + $2 WHERE id::text = $1 RETURNING ${ident(S.W.col)} AS balance`, [uid, delta]);
  return Number(r.rows[0].balance);
}

/* ============================== JOURNAL / SÉCURITÉ ============================== */
async function logEvent(pool, req, type, severity, details, userId) {
  try {
    await pool.query(
      'INSERT INTO security_events (type, severity, user_id, ip, path, details) VALUES ($1,$2,$3,$4,$5,$6)',
      [type, severity || 'medium', userId ? String(userId) : (req.user && String(req.user.id)) || null, ipOf(req), req.originalUrl, details ? JSON.stringify(details) : null]);
  } catch (_) { /* le journal ne doit jamais casser une requête */ }
}

function guard(pool, opts = {}) {
  const WINDOW = opts.windowMs || 60_000, MAX = opts.max || 120, MAX_AUTH = opts.maxAuth || 10;
  const hits = new Map();
  const blocked = { ip: new Set(), user: new Set(), at: 0 };
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
    const lim = isAuthRoute ? MAX_AUTH : MAX;
    if (h.n > lim) {
      if (h.n === lim + 1) logEvent(pool, req, 'rate_limit', 'high', { count: h.n });
      return res.status(429).json({ error: 'Trop de requêtes. Réessaie dans une minute.' });
    }
    req.flexBlockedUsers = blocked.user;
    res.on('finish', () => {
      if (/\/admin\//.test(req.originalUrl) && (res.statusCode === 401 || res.statusCode === 403))
        logEvent(pool, req, 'admin_forbidden', 'high', { status: res.statusCode });
      if (isAuthRoute && res.statusCode === 401) logEvent(pool, req, 'login_failed', 'medium');
    });
    next();
  };
}

/* ============================== ROUTES ============================== */
function router({ pool, requireAuth, requireAdmin }) {
  const r = express.Router();
  const ready = (req, res, next) => S.ready ? next() : res.status(503).json({ error: 'Module FLEX non initialisé (appelle await flex.init(pool)).' });
  r.use(ready);

  const C = k => ident(S.O[k]);
  const normalize = row => ({
    ...row,
    id: row.id,
    order_id: row[S.O.cid] || row.id,
    game: row[S.O.game],
    pack: row[S.O.pack], plan: row[S.O.pack],
    diamonds: Number(row[S.O.diamonds]) || 0,
    price: Number(row[S.O.price]) || 0, amount: Number(row[S.O.price]) || 0,
    status: row[S.O.status] || 'En attente',
    payment: row[S.O.payment] || 'Wallet',
    playerId: row[S.O.player], accountName: row[S.O.account], phone: row[S.O.phone],
    date: row[S.O.created], created_at: row[S.O.created],
  });

  /* ---------- A) COMMANDE PAYÉE AVEC LE WALLET — débit atomique ---------- */
  r.post('/orders', requireAuth, async (req, res) => {
    const b = req.body || {};
    const uid = String(req.user.id);
    if (req.flexBlockedUsers && req.flexBlockedUsers.has(uid)) return res.status(403).json({ error: 'Compte bloqué.' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const cid = String(b.client_order_id || b.order_id || b.id || '').slice(0, 80) || null;

      // 1) même commande déjà reçue ? -> on la renvoie sans débiter une 2e fois
      if (cid) {
        const ex = await client.query(`SELECT * FROM orders WHERE ${C('user')}::text = $1 AND ${C('cid')}::text = $2 LIMIT 1`, [uid, cid]);
        if (ex.rows[0]) {
          const bal0 = await lockBalance(client, uid);
          await client.query('ROLLBACK');
          return res.json({ ok: true, order: normalize(ex.rows[0]), balance: bal0, duplicate: true });
        }
      }

      // 2) prix: relu en base si le pack existe, sinon prix reçu (signalé)
      let price = Number(b.price ?? b.amount), diamonds = Number(b.diamonds) || parseDiamonds(b.pack || b.plan);
      if (S.P) {
        try {
          const pk = await client.query(`SELECT ${ident(S.P.price)} AS price${S.P.qty ? `, ${ident(S.P.qty)} AS qty` : ''} FROM packs WHERE lower(${ident(S.P.name)}) = lower($1) LIMIT 1`, [String(b.pack || b.plan || '')]);
          if (pk.rows[0]) { price = Number(pk.rows[0].price); if (S.P.qty && Number(pk.rows[0].qty)) diamonds = Number(pk.rows[0].qty); }
          else logEvent(pool, req, 'price_unverified', 'medium', { pack: b.pack, price }, uid);
        } catch (_) { /* packs différent de prévu: on garde le prix reçu */ }
      }
      if (!Number.isFinite(price) || price <= 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Prix invalide.' }); }

      // 3) verrou du solde + contrôle
      const bal = await lockBalance(client, uid);
      if (bal < price) { await client.query('ROLLBACK'); return res.status(402).json({ insufficient: true, error: 'Solde insuffisant.', balance: bal }); }

      // 4) commande LIÉE au client
      const cols = [C('user'), C('game'), C('pack'), C('diamonds'), C('price'), C('player'), C('account'), C('phone'), C('status'), C('payment')];
      const vals = [uid, b.game || null, b.pack || b.plan || null, diamonds, price, b.playerId || b.player_id || b.uid || null,
        b.accountName || b.account_name || null, b.phone || b.customerPhone || null, 'En attente', 'Wallet'];
      if (cid) { cols.push(C('cid')); vals.push(cid); }
      const ins = await client.query(
        `INSERT INTO orders (${cols.join(',')}) VALUES (${vals.map((_, i) => '$' + (i + 1)).join(',')}) RETURNING *`, vals);
      const order = ins.rows[0];

      // 5) débit + journal
      const nb = await addBalance(client, uid, -price);
      await client.query(`INSERT INTO wallet_transactions (user_id, type, amount, ref) VALUES ($1,'order_debit',$2,$3)`, [uid, -price, String(order.id)]);
      await client.query('COMMIT');
      res.json({ ok: true, order: normalize(order), balance: nb, wallet: { balance: nb } });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      console.error('[FLEX] POST /orders', e.message);
      res.status(500).json({ error: 'Erreur serveur.' });
    } finally { client.release(); }
  });

  /* ---------- B) MES COMMANDES (chaque client voit seulement les siennes) ---------- */
  r.get('/orders', requireAuth, async (req, res) => {
    try {
      const q = await pool.query(`SELECT * FROM orders WHERE ${C('user')}::text = $1 ORDER BY ${C('created')} DESC LIMIT 200`, [String(req.user.id)]);
      res.set('Cache-Control', 'no-store').json({ orders: q.rows.map(normalize) });
    } catch (e) { console.error('[FLEX] GET /orders', e.message); res.status(500).json({ error: 'Erreur serveur.' }); }
  });

  /* ---------- C) ADMIN: VALIDER / REFUSER ---------- */
  async function setOrderStatus(req, res) {
    const status = String((req.body && req.body.status) || '').trim();
    if (!status) return res.status(400).json({ error: 'status requis.' });
    const refused = refusedRe().test(status);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const f = await client.query(`SELECT * FROM orders WHERE id::text = $1 OR ${C('cid')}::text = $1 LIMIT 1 FOR UPDATE`, [String(req.params.id)]);
      const o = f.rows[0];
      if (!o) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Commande introuvable.' }); }
      const wasRefused = refusedRe().test(String(o[S.O.status] || ''));
      if (wasRefused && !refused) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Commande déjà refusée.' }); }
      await client.query(`UPDATE orders SET ${C('status')} = $2 WHERE id = $1`, [o.id, status]);
      let balance = null;
      const owner = o[S.O.user] != null ? String(o[S.O.user]) : null;
      if (refused && !wasRefused && owner && /wallet/i.test(String(o[S.O.payment] || 'wallet'))) {
        const j = await client.query(`INSERT INTO wallet_transactions (user_id, type, amount, ref) VALUES ($1,'order_refund',$2,$3) ON CONFLICT DO NOTHING RETURNING id`, [owner, Number(o[S.O.price]), String(o.id)]);
        if (j.rows[0]) balance = await addBalance(client, owner, Number(o[S.O.price]));   // remboursement UNE seule fois
      }
      await client.query('COMMIT');
      res.json({ ok: true, order: normalize({ ...o, [S.O.status]: status }), refunded: balance != null, balance });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      console.error('[FLEX] order status', e.message);
      res.status(500).json({ error: 'Erreur serveur.' });
    } finally { client.release(); }
  }
  r.patch('/admin/orders/:id', requireAuth, requireAdmin, setOrderStatus);
  r.patch('/admin/orders/:id/status', requireAuth, requireAdmin, setOrderStatus);
  r.put('/admin/orders/:id', requireAuth, requireAdmin, setOrderStatus);

  /* ---------- D) DÉPÔT: confirmation avec montant corrigeable par l'admin ---------- */
  // Le formulaire admin est prérempli avec le montant déclaré par le client; l'admin peut le corriger (ex. 100 -> 165).
  // Le client est crédité du montant confirmé. Le montant d'origine est gardé (original_amount) et un événement est journalisé.
  r.post('/admin/deposits/:id/confirm', requireAuth, requireAdmin, async (req, res, next) => {
    if (!S.D || !S.D.amount || !S.D.status || !S.D.user) return next();   // schéma inconnu: ton ancienne route prend le relais
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const f = await client.query(`SELECT * FROM ${ident(S.D.table)} WHERE id::text = $1 LIMIT 1 FOR UPDATE`, [String(req.params.id)]);
      const dep = f.rows[0];
      if (!dep) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Dépôt introuvable.' }); }
      if (!/^(pending|en attente)$/i.test(String(dep[S.D.status] || 'pending'))) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Ce dépôt est déjà traité.' }); }

      const declared = Number(dep[S.D.amount]);
      const raw = req.body && (req.body.amount ?? req.body.amount_htg ?? req.body.value);
      const finalAmt = (raw == null || raw === '') ? declared : Number(raw);
      if (!Number.isFinite(finalAmt) || finalAmt <= 0 || finalAmt > CFG.maxDeposit) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Montant invalide (1 à ' + CFG.maxDeposit.toLocaleString('fr-FR') + ' HTG).' });
      }
      const note = String((req.body && (req.body.admin_note || req.body.note)) || '').slice(0, 200) || null;
      const uid = String(dep[S.D.user]);

      await client.query(
        `UPDATE ${ident(S.D.table)} SET ${ident(S.D.amount)} = $2, ${ident(S.D.status)} = 'confirmed', ${ident(S.D.at)} = now(),
                ${ident(S.D.original)} = COALESCE(${ident(S.D.original)}, $3), ${ident(S.D.note)} = $4, ${ident(S.D.by)} = $5 WHERE id = $1`,
        [dep.id, finalAmt, declared, note, req.user ? String(req.user.id) : null]);
      await lockBalance(client, uid);                       // crée la ligne wallet si besoin + verrou
      const balance = await addBalance(client, uid, finalAmt);
      await client.query(`INSERT INTO wallet_transactions (user_id, type, amount, ref) VALUES ($1,'deposit_credit',$2,$3) ON CONFLICT DO NOTHING`, [uid, finalAmt, String(dep.id)]);
      await client.query('COMMIT');
      if (finalAmt !== declared) await logEvent(pool, req, 'deposit_amount_adjusted', 'medium', { deposit_id: dep.id, declared, credited: finalAmt, note }, uid);
      res.json({ ok: true, deposit: { ...dep, id: dep.id, status: 'confirmed', amount: finalAmt, declared_amount: declared }, balance });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      console.error('[FLEX] deposit confirm', e.message);
      res.status(500).json({ error: 'Erreur serveur.' });
    } finally { client.release(); }
  });

  /* ---------- E) SÉCURITÉ (admin) ---------- */
  r.get('/admin/security/events', requireAuth, requireAdmin, async (req, res) => {
    const ev = await pool.query('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 200');
    const bl = await pool.query('SELECT * FROM security_blocks ORDER BY created_at DESC');
    const top = await pool.query(`SELECT ip, count(*)::int AS n, max(created_at) AS last_at FROM security_events
      WHERE created_at > now() - interval '24 hours' AND ip IS NOT NULL GROUP BY ip ORDER BY n DESC LIMIT 10`);
    res.json({ events: ev.rows, blocks: bl.rows, topIps: top.rows });
  });
  r.post('/admin/security/block', requireAuth, requireAdmin, async (req, res) => {
    const { kind, value, reason } = req.body || {};
    if (!['ip', 'user'].includes(kind) || !value) return res.status(400).json({ error: 'kind (ip|user) et value requis.' });
    await pool.query('INSERT INTO security_blocks (kind, value, reason) VALUES ($1,$2,$3) ON CONFLICT (kind,value) DO UPDATE SET reason = EXCLUDED.reason', [kind, String(value), reason || null]);
    res.json({ ok: true });
  });
  r.post('/admin/security/unblock', requireAuth, requireAdmin, async (req, res) => {
    const { kind, value } = req.body || {};
    await pool.query('DELETE FROM security_blocks WHERE kind = $1 AND value = $2', [kind, String(value)]);
    res.json({ ok: true });
  });
  r.get('/admin/flex/health', requireAuth, requireAdmin, (req, res) => {
    res.json({ ready: S.ready, pseudoCol: S.pseudoCol, orders: S.O, deposits: S.D, wallet: S.W, packs: S.P });
  });

  /* ---------- F) TOP 100 DIAMANTS DU MOIS ---------- */
  // Compte toutes les commandes payées du mois (heure d'Haïti) sauf refusées/annulées. Reset automatique le 1er, sans cron.
  r.get('/leaderboard/monthly', async (req, res) => {
    try {
      const dia = `COALESCE(NULLIF(o.${C('diamonds')}, 0),
        NULLIF(regexp_replace(substring(COALESCE(o.${C('pack')}, '') from '(\\d[\\d\\s.,]*)\\s*(?:[Dd][Ii][Aa][Mm]|💎)'), '[^0-9]', '', 'g'), '')::bigint, 0)`;
      const q = await pool.query(
        `SELECT u.id AS uid, u.${ident(S.pseudoCol)} AS pseudo, SUM(${dia})::bigint AS diamonds, MIN(o.${C('created')}) AS first_at
           FROM orders o JOIN users u ON u.id::text = o.${C('user')}::text
          WHERE o.${C('status')} !~* $1
            AND o.${C('created')} >= date_trunc('month', now() AT TIME ZONE $2) AT TIME ZONE $2
          GROUP BY u.id, u.${ident(S.pseudoCol)}
         HAVING SUM(${dia}) > 0
          ORDER BY diamonds DESC, first_at ASC
          LIMIT $3`, [CFG.refusedRegex, CFG.tz, CFG.leaderboardSize]);
      const me = req.user && String(req.user.id);
      res.set('Cache-Control', 'no-store').json({
        month: new Date().toISOString().slice(0, 7),
        top: q.rows.map((x, i) => ({ rank: i + 1, pseudo: x.pseudo != null ? String(x.pseudo) : 'Client', diamonds: Number(x.diamonds), me: me ? String(x.uid) === me : false })),
      });
    } catch (e) { console.error('[FLEX] leaderboard', e.message); res.status(500).json({ error: 'Erreur serveur.' }); }
  });

  return r;
}

module.exports = { init, guard, router, logEvent, parseDiamonds, CFG, _state: S };
