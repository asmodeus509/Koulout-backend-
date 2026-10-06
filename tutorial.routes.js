/**
 * tutorial.routes.js — Tutoriel vidéo FLEX TUPUP
 *
 * Routes:
 *   GET  /tutorial             (public)
 *   PUT  /admin/tutorial       (admin)  { active, title, subtitle, videoUrl }
 *   POST /admin/tutorial/video (admin)  multipart/form-data, champ "video"
 *
 * INSTALLATION
 * 1) npm i multer cloudinary
 * 2) Render > Environment: CLOUDINARY_URL=cloudinary://API_KEY:API_SECRET@CLOUD_NAME
 * 3) Dans server.js, après express.json() et CORS:
 *      require('./tutorial.routes')(app, pool, requireAdmin);
 *    -> remplace `pool` par ton client PostgreSQL réel
 *    -> remplace `requireAdmin` par le middleware admin réel
 *       (celui qui protège déjà tes autres routes /admin/...)
 * 4) CORS: autoriser PUT, header Authorization et le domaine Vercel.
 */

const multer = require('multer');
const cloudinary = require('cloudinary').v2; // lit CLOUDINARY_URL automatiquement

const ALLOWED = ['video/mp4', 'video/webm', 'video/quicktime'];
const MAX_SIZE = 100 * 1024 * 1024; // 100 MB

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SIZE },
  fileFilter: (req, file, cb) =>
    ALLOWED.includes(file.mimetype) ? cb(null, true) : cb(new Error('FORMAT_INVALIDE')),
});

module.exports = function (app, pool, requireAdmin) {
  pool
    .query(`CREATE TABLE IF NOT EXISTS tutorial_config (
      id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      active BOOLEAN NOT NULL DEFAULT false,
      title TEXT NOT NULL DEFAULT '',
      subtitle TEXT NOT NULL DEFAULT '',
      video_url TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`)
    .catch((e) => console.error('tutorial table:', e));

  const fmt = (r) => ({
    active: r ? r.active : false,
    title: r ? r.title : '',
    subtitle: r ? r.subtitle : '',
    videoUrl: r ? r.video_url : '',
  });

  // PUBLIC
  app.get('/tutorial', async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT * FROM tutorial_config WHERE id = 1');
      res.json({ success: true, tutorial: fmt(rows[0]) });
    } catch (e) {
      console.error(e);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
  });

  // ADMIN: sauvegarder la configuration
  app.put('/admin/tutorial', requireAdmin, async (req, res) => {
    try {
      const { active, title, subtitle, videoUrl } = req.body || {};
      if (videoUrl && !/^https:\/\//i.test(videoUrl)) {
        return res
          .status(400)
          .json({ success: false, message: 'videoUrl doit être une URL https' });
      }
      const { rows } = await pool.query(
        `INSERT INTO tutorial_config (id, active, title, subtitle, video_url)
         VALUES (1, COALESCE($1,false), COALESCE($2,''), COALESCE($3,''), COALESCE($4,''))
         ON CONFLICT (id) DO UPDATE SET
           active = COALESCE($1, tutorial_config.active),
           title = COALESCE($2, tutorial_config.title),
           subtitle = COALESCE($3, tutorial_config.subtitle),
           video_url = COALESCE($4, tutorial_config.video_url),
           updated_at = now()
         RETURNING *`,
        [
          typeof active === 'boolean' ? active : null,
          title ?? null,
          subtitle ?? null,
          videoUrl ?? null,
        ]
      );
      res.json({ success: true, tutorial: fmt(rows[0]) });
    } catch (e) {
      console.error(e);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
  });

  // ADMIN: upload de la vidéo (stockage permanent Cloudinary)
  app.post(
    '/admin/tutorial/video',
    requireAdmin,
    upload.single('video'),
    async (req, res) => {
      try {
        if (!req.file) {
          return res.status(400).json({ success: false, message: 'Champ "video" manquant' });
        }
        const result = await new Promise((resolve, reject) => {
          cloudinary.uploader
            .upload_stream(
              { resource_type: 'video', folder: 'flex-tupup/tutorial' },
              (err, r) => (err ? reject(err) : resolve(r))
            )
            .end(req.file.buffer);
        });
        await pool.query(
          `INSERT INTO tutorial_config (id, video_url) VALUES (1, $1)
           ON CONFLICT (id) DO UPDATE SET video_url = $1, updated_at = now()`,
          [result.secure_url]
        );
        res.json({ success: true, videoUrl: result.secure_url });
      } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: 'Upload échoué' });
      }
    }
  );

  // Erreurs multer (format / taille)
  app.use('/admin/tutorial/video', (err, req, res, next) => {
    const message =
      err.message === 'FORMAT_INVALIDE'
        ? 'Format accepté: MP4, WebM, MOV'
        : err.code === 'LIMIT_FILE_SIZE'
        ? 'Vidéo trop lourde (max 100 MB)'
        : 'Erreur upload';
    res.status(400).json({ success: false, message });
  });
};
