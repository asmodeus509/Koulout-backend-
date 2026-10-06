// tutorial-routes.js — routes backend pour le tutoriel vidéo FLEX TUPUP
// Installation: npm i multer
// Dans ton server.js:  require('./tutorial-routes')(app, requireAdmin);
//   - `app` = ton app Express
//   - `requireAdmin` = ton middleware qui vérifie le token admin (celui que tu utilises déjà pour /admin/orders)
//
// ⚠ Render gratuit efface le disque à chaque redéploiement/redémarrage.
//   Pour garder la vidéo, mets plutôt un lien YouTube / Cloudinary dans le panel admin,
//   ou branche un Persistent Disk Render (monte-le sur /var/data et change DATA_DIR).

const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const CFG_FILE = path.join(DATA_DIR, 'tutorial.json');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => {
      const ext = (path.extname(file.originalname) || '.mp4').toLowerCase();
      cb(null, 'tuto-' + Date.now() + ext);
    },
  }),
  limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB
  fileFilter: (req, file, cb) => {
    cb(/^video\/(mp4|webm|quicktime)$/.test(file.mimetype) ? null : new Error('Format vidéo non supporté'), true);
  },
});

const readCfg = () => { try { return JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')); } catch (e) { return {}; } };

module.exports = function (app, requireAdmin) {
  // vidéos servies publiquement
  app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));

  // PUBLIC: config lue par les visiteurs
  app.get('/tutorial', (req, res) => res.json({ tutorial: readCfg() }));

  // ADMIN: enregistrer titre / texte / lien vidéo / actif
  app.put('/admin/tutorial', requireAdmin, express.json(), (req, res) => {
    const b = req.body || {};
    const cfg = {
      active: b.active !== false,
      title: String(b.title || '').slice(0, 120),
      subtitle: String(b.subtitle || '').slice(0, 240),
      videoUrl: String(b.videoUrl || '').slice(0, 600),
      updatedAt: new Date().toISOString(),
    };
    fs.writeFileSync(CFG_FILE, JSON.stringify(cfg));
    res.json({ success: true, tutorial: cfg });
  });

  // ADMIN: upload du fichier vidéo (champ "video") -> renvoie { url }
  app.post('/admin/tutorial/video', requireAdmin, (req, res) => {
    upload.single('video')(req, res, (err) => {
      if (err) return res.status(400).json({ success: false, message: err.message });
      if (!req.file) return res.status(400).json({ success: false, message: 'Aucun fichier reçu' });
      res.json({ success: true, url: '/uploads/' + req.file.filename });
    });
  });
};
