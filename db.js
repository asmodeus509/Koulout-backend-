const { Pool } = require('pg');

const hasDb = Boolean(process.env.DATABASE_URL);
const pool = hasDb
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
      max: 8,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 8000
    })
  : null;

async function q(text, params = [], client = pool) {
  if (!client) throw new Error('DATABASE_URL_MISSING');
  return client.query(text, params);
}

async function transaction(fn) {
  if (!pool) throw new Error('DATABASE_URL_MISSING');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function initDb() {
  if (!pool) return;
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL DEFAULT 'Client FLEX',
      contact TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'client',
      wallet_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wallet_deposits (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      method TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      transaction_reference TEXT NOT NULL,
      sender_phone TEXT NOT NULL DEFAULT '',
      note TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','refused')),
      credited_at TIMESTAMPTZ,
      confirmed_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ux_wallet_deposit_ref_method ON wallet_deposits(method, transaction_reference);
    CREATE INDEX IF NOT EXISTS ix_wallet_deposits_status_created ON wallet_deposits(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS ix_wallet_deposits_user_created ON wallet_deposits(user_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS payment_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      moncash_number TEXT NOT NULL DEFAULT '',
      natcash_number TEXT NOT NULL DEFAULT '50956701079',
      whatsapp TEXT NOT NULL DEFAULT '50956701079',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO payment_settings(id) VALUES (1) ON CONFLICT (id) DO NOTHING;

    CREATE TABLE IF NOT EXISTS games (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      image TEXT NOT NULL DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS packs (
      id BIGSERIAL PRIMARY KEY,
      game_id BIGINT NOT NULL REFERENCES games(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      qty INTEGER NOT NULL DEFAULT 0,
      price NUMERIC(14,2) NOT NULL DEFAULT 0,
      image TEXT NOT NULL DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      popular BOOLEAN NOT NULL DEFAULT FALSE,
      premium BOOLEAN NOT NULL DEFAULT FALSE,
      category TEXT NOT NULL DEFAULT 'Plans',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ix_packs_game ON packs(game_id, active, id);

    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      game TEXT NOT NULL,
      pack TEXT NOT NULL,
      price NUMERIC(14,2) NOT NULL DEFAULT 0,
      player_id TEXT NOT NULL DEFAULT '',
      account_name TEXT NOT NULL DEFAULT '',
      phone TEXT NOT NULL DEFAULT '',
      payment TEXT NOT NULL DEFAULT '',
      payment_method TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'En attente',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ix_orders_created ON orders(created_at DESC);

    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      type TEXT NOT NULL DEFAULT 'notice',
      title TEXT NOT NULL DEFAULT 'Notification',
      message TEXT NOT NULL DEFAULT '',
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      order_id TEXT,
      read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ix_notifications_created ON notifications(created_at DESC);
  `);
  // Non-destructive compatibility migrations for databases created by older FLEX TUPUP versions.
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_balance NUMERIC(14,2) NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'client'`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS sender_phone TEXT NOT NULL DEFAULT ''`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT ''`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS credited_at TIMESTAMPTZ`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS confirmed_by BIGINT`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await q(`ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS ux_wallet_deposit_ref_method ON wallet_deposits(method, transaction_reference)`);
  await q(`CREATE INDEX IF NOT EXISTS ix_wallet_deposits_status_created ON wallet_deposits(status, created_at DESC)`);
  await q(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS user_id BIGINT`);
  await q(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS read BOOLEAN NOT NULL DEFAULT FALSE`);
}

module.exports = { pool, q, transaction, initDb, hasDb };
