const fs = require('fs');
const path = require('path');
const assert = require('assert');
const root = path.join(__dirname, '..');
for (const f of ['server.js','db.js','auth.js','routes.js','package.json']) {
  assert.ok(fs.existsSync(path.join(root,f)), `missing ${f}`);
}
const routes = fs.readFileSync(path.join(root,'routes.js'),'utf8');
for (const needle of [
  "router.post('/api/wallet/deposits'",
  "router.get('/api/admin/deposits'",
  "router.patch('/api/admin/deposits/:id'",
  "status='confirmed'",
  'wallet_balance=wallet_balance+$2',
  "status='refused'",
  "router.post('/api/admin/deposits/:id/confirm'",
  "router.post('/api/admin/deposits/:id/refuse'",
  "router.post('/api/auth/login'",
  "router.get('/api/auth/me'",
  "router.get('/api/games/:id/packs'",
  "router.post('/api/admin/games/:gameId/packs'"
]) assert.ok(routes.includes(needle), `contract missing: ${needle}`);
console.log('FLEX TUPUP backend contract test: PASS');
