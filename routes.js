const express = require('express');
const { q, transaction } = require('./db');
const { bcrypt, signUser, safeUser, authMiddleware, adminOnly } = require('./auth');

const router = express.Router();
const MAX = Number(process.env.MAX_WALLET_DEPOSIT || 500000);
const MIN = Number(process.env.MIN_WALLET_DEPOSIT || 1);

const num = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : NaN;
};
const clean = (v, max = 500) => String(v ?? '').trim().slice(0, max);
function normalizeMethod(v) {
  const x = clean(v, 30).toLowerCase();
  if (x === 'moncash') return 'MonCash';
  if (x === 'natcash') return 'NatCash';
  return clean(v, 30) || 'MonCash';
}
function publicDeposit(row) {
  return {
    ...row,
    id: row.id,
    deposit_id: row.id,
    amount: Number(row.amount),
    user_id: row.user_id,
    status: row.status,
    method: row.method,
    payment_method: row.method,
    tx: row.transaction_reference,
    transaction_reference: row.transaction_reference,
    reference: row.transaction_reference,
    senderPhone: row.sender_phone,
    sender_phone: row.sender_phone,
    phone: row.sender_phone,
    date: row.created_at,
    credited_at: row.credited_at,
    confirmed_by: row.confirmed_by,
    customer: row.user_name,
    contact: row.user_contact
  };
}

router.get('/health', async (req,res) => {
  try {
    await q('SELECT 1');
    res.json({ ok:true, service:'flex-tupup-backend', database:'connected', time:new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ ok:false, service:'flex-tupup-backend', database:'unavailable', error:err.message });
  }
});

router.post('/api/auth/register', async (req,res,next) => {
  try {
    const name = clean(req.body.name || 'Client FLEX', 120);
    const contact = clean(req.body.contact || req.body.email || req.body.phone, 180).toLowerCase();
    const password = String(req.body.password || '');
    if (!contact || password.length < 6) return res.status(400).json({ error:'INVALID_INPUT', message:'Contact et mot de passe (6 caractères minimum) requis.' });
    const existing = await q('SELECT id FROM users WHERE LOWER(contact)=LOWER($1)', [contact]);
    if (existing.rows.length) return res.status(409).json({ error:'ACCOUNT_EXISTS', message:'Ce compte existe déjà.' });
    const hash = await bcrypt.hash(password, 12);
    const r = await q(`INSERT INTO users(name,contact,password_hash) VALUES($1,$2,$3) RETURNING *`, [name, contact, hash]);
    const user = safeUser(r.rows[0]);
    res.status(201).json({ user, token: signUser(r.rows[0]), access_token: signUser(r.rows[0]) });
  } catch(e){ next(e); }
});

router.post('/api/auth/login', async (req,res,next) => {
  try {
    const contact = clean(req.body.contact || req.body.email || req.body.phone, 180).toLowerCase();
    const password = String(req.body.password || '');
    const r = await q('SELECT * FROM users WHERE LOWER(contact)=LOWER($1) AND is_active=TRUE LIMIT 1',[contact]);
    if(!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password_hash))) return res.status(401).json({ error:'INVALID_CREDENTIALS', message:'Contact ou mot de passe incorrect.' });
    const user=r.rows[0]; const token=signUser(user);
    res.json({ user:safeUser(user), token, access_token:token });
  } catch(e){ next(e); }
});
router.get('/api/auth/me', authMiddleware, (req,res)=>res.json({user:req.user}));
router.get('/api/me', authMiddleware, (req,res)=>res.json({user:req.user}));

router.get('/api/wallet', authMiddleware, async (req,res,next)=>{
  try{
    const r=await q(`SELECT wallet_balance FROM users WHERE id=$1`,[req.user.id]);
    const balance=Number(r.rows[0]?.wallet_balance||0);
    res.json({ wallet:balance, balance, data:{wallet:balance,balance} });
  }catch(e){next(e)}
});

router.get('/api/wallet/deposits', authMiddleware, async (req,res,next)=>{
  try{
    const r=await q(`SELECT d.*,u.name user_name,u.contact user_contact FROM wallet_deposits d JOIN users u ON u.id=d.user_id WHERE d.user_id=$1 ORDER BY d.created_at DESC LIMIT 100`,[req.user.id]);
    res.json({ deposits:r.rows.map(publicDeposit) });
  }catch(e){next(e)}
});

router.post('/api/wallet/deposits', authMiddleware, async (req,res,next)=>{
  try{
    const amount=num(req.body.amount);
    const method=normalizeMethod(req.body.method || req.body.payment_method);
    const tx=clean(req.body.transaction_reference || req.body.tx || req.body.reference, 160);
    const phone=clean(req.body.sender_phone || req.body.senderPhone || req.body.phone, 40);
    const note=clean(req.body.note, 140);
    if(!Number.isFinite(amount)||amount<MIN||amount>MAX) return res.status(400).json({error:'INVALID_AMOUNT',message:`Montant invalide. Min ${MIN}, max ${MAX}.`});
    if(!tx) return res.status(400).json({error:'REFERENCE_REQUIRED',message:'Code de transaction requis.'});
    const dup=await q('SELECT id,status FROM wallet_deposits WHERE method=$1 AND transaction_reference=$2 LIMIT 1',[method,tx]);
    if(dup.rows.length) return res.status(409).json({error:'DUPLICATE_REFERENCE',message:'Cette référence de transaction existe déjà.',deposit_id:dup.rows[0].id,status:dup.rows[0].status});
    const r=await q(`INSERT INTO wallet_deposits(user_id,method,amount,transaction_reference,sender_phone,note,status) VALUES($1,$2,$3,$4,$5,$6,'pending') RETURNING *`,[req.user.id,method,amount,tx,phone,note]);
    const d=r.rows[0];
    await q(`INSERT INTO notifications(type,title,message,user_id) VALUES('wallet_deposit','Nouvelle recharge', $1, $2)`,[`Nouvelle recharge ${method} • ${amount} HTG • ${tx}`,req.user.id]);
    res.status(201).json({deposit:publicDeposit({...d,user_name:req.user.name,user_contact:req.user.contact}), data:{deposit:publicDeposit({...d,user_name:req.user.name,user_contact:req.user.contact})}});
  }catch(e){next(e)}
});

async function getDeposit(id, client=undefined, forUpdate=false){
  const r=await (client||require('./db').pool).query(`SELECT d.*,u.name user_name,u.contact user_contact FROM wallet_deposits d JOIN users u ON u.id=d.user_id WHERE d.id=$1 ${forUpdate?'FOR UPDATE':''}`,[id]);
  return r.rows[0] || null;
}

async function confirmDeposit(req,res,next){
  try{
    const id=req.params.id;
    const status=req.body.status==='refused'?'refused':'confirmed';
    const result=await transaction(async(client)=>{
      const dep=await getDeposit(id,client,true);
      if(!dep) { const e=new Error('DEPOSIT_NOT_FOUND'); e.status=404; throw e; }
      if(dep.status!=='pending') return {dep, changed:false};
      if(status==='refused'){
        const rr=await client.query(`UPDATE wallet_deposits SET status='refused',confirmed_by=$2,updated_at=NOW() WHERE id=$1 RETURNING *`,[id,req.user.id]);
        await client.query(`INSERT INTO notifications(type,title,message,user_id) VALUES('wallet_deposit_refused','Recharge refusée',$1,$2)`,[`Recharge ${dep.amount} HTG refusée.`,dep.user_id]);
        return {dep:{...rr.rows[0],user_name:dep.user_name,user_contact:dep.user_contact},changed:true};
      }
      const ur=await client.query(`UPDATE users SET wallet_balance=wallet_balance+$2,updated_at=NOW() WHERE id=$1 RETURNING wallet_balance,name,contact`,[dep.user_id,dep.amount]);
      if(!ur.rows.length){ const e=new Error('USER_NOT_FOUND');e.status=404;throw e; }
      const dr=await client.query(`UPDATE wallet_deposits SET status='confirmed',credited_at=NOW(),confirmed_by=$2,updated_at=NOW() WHERE id=$1 RETURNING *`,[id,req.user.id]);
      await client.query(`INSERT INTO notifications(type,title,message,user_id) VALUES('wallet_deposit_confirmed','Recharge confirmée',$1,$2)`,[`Votre Wallet a été crédité de ${dep.amount} HTG. Nouveau solde: ${ur.rows[0].wallet_balance} HTG.`,dep.user_id]);
      return {dep:{...dr.rows[0],user_name:dep.user_name,user_contact:dep.user_contact},changed:true,balance:Number(ur.rows[0].wallet_balance)};
    });
    const out=publicDeposit(result.dep);
    res.json({ok:true,deposit:out, data:{deposit:out}, changed:result.changed, balance:result.balance});
  }catch(e){next(e)}
}
router.patch('/api/admin/deposits/:id', authMiddleware, adminOnly, confirmDeposit);
router.post('/api/admin/deposits/:id/confirm', authMiddleware, adminOnly, (req,res,next)=>{ req.body={...(req.body||{}),status:'confirmed'}; confirmDeposit(req,res,next); });
router.post('/api/admin/deposits/:id/refuse', authMiddleware, adminOnly, (req,res,next)=>{ req.body={...(req.body||{}),status:'refused'}; confirmDeposit(req,res,next); });
// Explicit validation alias used by the current admin panel.
router.post('/api/admin/deposits/:id/validate', authMiddleware, adminOnly, (req,res,next)=>{ req.body={...(req.body||{}),status:req.body?.status==='refused'?'refused':'confirmed'}; confirmDeposit(req,res,next); });
router.patch('/api/wallet/deposits/:id', authMiddleware, adminOnly, confirmDeposit);
router.get('/api/admin/deposits', authMiddleware, adminOnly, async(req,res,next)=>{
  try{
    const r=await q(`SELECT d.*,u.name user_name,u.contact user_contact FROM wallet_deposits d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC LIMIT 100`);
    res.json({deposits:r.rows.map(publicDeposit), items:r.rows.map(publicDeposit)});
  }catch(e){next(e)}
});

router.get('/api/admin/users', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`SELECT * FROM users ORDER BY created_at DESC LIMIT 1000`);res.json({users:r.rows.map(safeUser)})}catch(e){next(e)}});

router.get('/api/games', async(req,res,next)=>{try{const r=await q(`SELECT * FROM games WHERE active=TRUE ORDER BY id`);res.json(r.rows.map(g=>({id:g.id,name:g.name,image:g.image,active:g.active})))}catch(e){next(e)}});
router.get('/api/admin/games', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`SELECT * FROM games ORDER BY id`);res.json({games:r.rows})}catch(e){next(e)}});
router.post('/api/admin/games', authMiddleware, adminOnly, async(req,res,next)=>{try{const name=clean(req.body.name,120);const image=clean(req.body.image||req.body.img,7000000);if(!name)return res.status(400).json({error:'NAME_REQUIRED'});const r=await q(`INSERT INTO games(name,image) VALUES($1,$2) RETURNING *`,[name,image]);res.status(201).json({game:r.rows[0]})}catch(e){if(e.code==='23505')return res.status(409).json({error:'GAME_EXISTS'});next(e)}});
router.put('/api/admin/games/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`UPDATE games SET name=COALESCE(NULLIF($2,''),name),image=COALESCE($3,image),updated_at=NOW() WHERE id=$1 RETURNING *`,[req.params.id,clean(req.body.name,120),clean(req.body.image||req.body.img,7000000)]);if(!r.rows.length)return res.status(404).json({error:'GAME_NOT_FOUND'});res.json({game:r.rows[0]})}catch(e){next(e)}});
router.delete('/api/admin/games/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`DELETE FROM games WHERE id=$1 RETURNING id`,[req.params.id]);if(!r.rows.length)return res.status(404).json({error:'GAME_NOT_FOUND'});res.json({ok:true,id:req.params.id})}catch(e){next(e)}});

router.get('/api/games/:id/packs', async(req,res,next)=>{try{const r=await q(`SELECT * FROM packs WHERE game_id=$1 AND active=TRUE ORDER BY id`,[req.params.id]);res.json({packs:r.rows.map(packPublic)})}catch(e){next(e)}});
function packPublic(p){return {id:p.id,name:p.name,qty:Number(p.qty),quantity:Number(p.qty),price:Number(p.price),image:p.image,active:p.active,popular:p.popular,premium:p.premium,category:p.category,game_id:p.game_id}}
router.get('/api/admin/games/:gameId/packs', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`SELECT * FROM packs WHERE game_id=$1 ORDER BY id`,[req.params.gameId]);res.json({packs:r.rows.map(packPublic)})}catch(e){next(e)}});
router.post('/api/admin/games/:gameId/packs', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`INSERT INTO packs(game_id,name,qty,price,image,active,popular,premium,category) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[req.params.gameId,clean(req.body.name||'Produit',160),Math.max(0,Math.trunc(num(req.body.qty||req.body.quantity||0)||0)),Math.max(0,num(req.body.price)||0),clean(req.body.image||req.body.img,7000000),req.body.active!==false,!!req.body.popular,!!req.body.premium,clean(req.body.category||'Plans',80)]);res.status(201).json({pack:packPublic(r.rows[0])})}catch(e){next(e)}});
router.put('/api/admin/games/:gameId/packs/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`UPDATE packs SET name=$3,qty=$4,price=$5,image=$6,active=$7,popular=$8,premium=$9,category=$10,updated_at=NOW() WHERE id=$1 AND game_id=$2 RETURNING *`,[req.params.id,req.params.gameId,clean(req.body.name||'Produit',160),Math.max(0,Math.trunc(num(req.body.qty||req.body.quantity||0)||0)),Math.max(0,num(req.body.price)||0),clean(req.body.image||req.body.img,7000000),req.body.active!==false,!!req.body.popular,!!req.body.premium,clean(req.body.category||'Plans',80)]);if(!r.rows.length)return res.status(404).json({error:'PACK_NOT_FOUND'});res.json({pack:packPublic(r.rows[0])})}catch(e){next(e)}});
router.delete('/api/admin/games/:gameId/packs/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`DELETE FROM packs WHERE id=$1 AND game_id=$2 RETURNING id`,[req.params.id,req.params.gameId]);if(!r.rows.length)return res.status(404).json({error:'PACK_NOT_FOUND'});res.json({ok:true,id:req.params.id})}catch(e){next(e)}});

router.post('/api/orders', authMiddleware, async(req,res,next)=>{try{const id=clean(req.body.id||req.body.order_id||`ORD-${Date.now()}`,120);const r=await q(`INSERT INTO orders(id,user_id,game,pack,price,player_id,account_name,phone,payment,payment_method,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO UPDATE SET updated_at=NOW() RETURNING *`,[id,req.user.id,clean(req.body.game,120),clean(req.body.pack||req.body.plan,160),Math.max(0,num(req.body.price||req.body.amount)||0),clean(req.body.player_id||req.body.playerId,120),clean(req.body.account_name||req.body.accountName,120),clean(req.body.phone||req.body.customerPhone,50),clean(req.body.payment,50),clean(req.body.payment_method,50),clean(req.body.status||'En attente',50)]);res.status(201).json({order:r.rows[0]})}catch(e){next(e)}});
router.get('/api/admin/orders', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`SELECT * FROM orders ORDER BY created_at DESC LIMIT 500`);res.json({orders:r.rows})}catch(e){next(e)}});
router.patch('/api/admin/orders/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`UPDATE orders SET status=$2,updated_at=NOW() WHERE id=$1 RETURNING *`,[req.params.id,clean(req.body.status,50)||'En attente']);if(!r.rows.length)return res.status(404).json({error:'ORDER_NOT_FOUND'});res.json({order:r.rows[0]})}catch(e){next(e)}});
router.patch('/api/admin/orders/:id/status', authMiddleware, adminOnly, async(req,res,next)=>{req.params.id=req.params.id; router.handle({method:'PATCH',url:`/api/admin/orders/${req.params.id}`,headers:req.headers,body:req.body,user:req.user},res,next)});
router.put('/api/admin/orders/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`UPDATE orders SET status=$2,updated_at=NOW() WHERE id=$1 RETURNING *`,[req.params.id,clean(req.body.status,50)||'En attente']);if(!r.rows.length)return res.status(404).json({error:'ORDER_NOT_FOUND'});res.json({order:r.rows[0]})}catch(e){next(e)}});

router.get('/api/payment-settings', async(req,res,next)=>{try{const r=await q('SELECT * FROM payment_settings WHERE id=1');const x=r.rows[0]||{};res.json({moncash:{number:x.moncash_number||''},natcash:{number:x.natcash_number||'50956701079'},whatsapp:x.whatsapp||'50956701079'})}catch(e){next(e)}});
router.get('/api/admin/payment-settings', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q('SELECT * FROM payment_settings WHERE id=1');const x=r.rows[0]||{};res.json({moncash:{number:x.moncash_number||''},natcash:{number:x.natcash_number||'50956701079'},whatsapp:x.whatsapp||'50956701079'})}catch(e){next(e)}});
router.put('/api/admin/payment-settings', authMiddleware, adminOnly, async(req,res,next)=>{try{const mon=clean(req.body.moncash?.number||req.body.moncash,40),nat=clean(req.body.natcash?.number||req.body.natcash||'50956701079',40),wa=clean(req.body.whatsapp||req.body.wa||'50956701079',40);const r=await q(`UPDATE payment_settings SET moncash_number=$1,natcash_number=$2,whatsapp=$3,updated_at=NOW() WHERE id=1 RETURNING *`,[mon,nat,wa]);res.json({ok:true,moncash:{number:r.rows[0].moncash_number},natcash:{number:r.rows[0].natcash_number},whatsapp:r.rows[0].whatsapp})}catch(e){next(e)}});
router.put('/api/admin/settings', authMiddleware, adminOnly, async(req,res,next)=>{try{await q(`UPDATE payment_settings SET whatsapp=$1,updated_at=NOW() WHERE id=1`,[clean(req.body.whatsapp||req.body.wa||'50956701079',40)]);res.json({ok:true})}catch(e){next(e)}});
router.put('/api/admin/config', authMiddleware, adminOnly, async(req,res,next)=>{try{await q(`UPDATE payment_settings SET whatsapp=$1,updated_at=NOW() WHERE id=1`,[clean(req.body.whatsapp||req.body.wa||'50956701079',40)]);res.json({ok:true})}catch(e){next(e)}});

router.get('/api/admin/notifications', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`SELECT n.*,o.id order_id FROM notifications n LEFT JOIN orders o ON o.id=n.order_id ORDER BY n.created_at DESC LIMIT 100`);res.json({notifications:r.rows})}catch(e){next(e)}});
router.post('/api/admin/notifications', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`INSERT INTO notifications(type,title,message,user_id,order_id,read) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[clean(req.body.type||'notice',50),clean(req.body.title||'Notification',160),clean(req.body.message,500),req.body.user_id||req.body.userId||null,req.body.order?.id||req.body.order_id||null,!!req.body.read]);res.status(201).json({notification:r.rows[0]})}catch(e){next(e)}});
router.patch('/api/admin/notifications/:id', authMiddleware, adminOnly, async(req,res,next)=>{try{const r=await q(`UPDATE notifications SET read=$2 WHERE id=$1 RETURNING *`,[req.params.id,!!req.body.read]);res.json({notification:r.rows[0]})}catch(e){next(e)}});

module.exports = router;
