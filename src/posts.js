const express = require('express');
const jwt = require('jsonwebtoken');
const { getPool } = require('./db');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { verifierMedia } = require('./verification-media');

const router = express.Router();

const recevoirMediaPublication = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 25 * 1024 * 1024,
    files: 1,
    fields: 0
  },
  fileFilter: (req, file, cb) => {
    const typesAutorises = new Set([
      'image/jpeg',
      'image/png',
      'image/webp',
      'image/gif',
      'video/mp4',
      'video/webm',
      'video/quicktime'
    ]);

    if (!typesAutorises.has(file.mimetype)) {
      return cb(new Error('FORMAT_MEDIA_NON_AUTORISE'));
    }

    cb(null, true);
  }
});

function televerserMediaPublication(fichier) {
  return new Promise((resolve, reject) => {
    const flux = cloudinary.uploader.upload_stream({
      resource_type: 'auto',
      folder: 'jjm-facebook/publications'
    }, (erreur, resultat) => {
      if (erreur) return reject(erreur);

      if (!resultat || !resultat.secure_url) {
        return reject(new Error('URL_CLOUDINARY_ABSENTE'));
      }

      resolve(resultat);
    });

    flux.end(fichier.buffer);
  });
}

// Téléverser une photo ou une vidéo pour une publication.
router.post('/upload-media', authenticate, (req, res, next) => {
  recevoirMediaPublication.single('media')(req, res, (erreur) => {
    if (!erreur) return next();

    if (erreur instanceof multer.MulterError) {
      const message = erreur.code === 'LIMIT_FILE_SIZE'
        ? 'Le média dépasse la limite de 25 Mo.'
        : 'Le fichier envoyé est invalide ou trop volumineux.';

      return res.status(400).json({
        success: false,
        message
      });
    }

    if (erreur.message === 'FORMAT_MEDIA_NON_AUTORISE') {
      return res.status(415).json({
        success: false,
        message: 'Formats acceptés : JPEG, PNG, WEBP, GIF, MP4, WEBM et MOV.'
      });
    }

    return res.status(400).json({
      success: false,
      message: 'Impossible de recevoir ce fichier.'
    });
  });
}, async (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: 'Sélectionne une photo ou une vidéo.'
    });
  }

  try {
    const controle = await verifierMedia(
      req.file.buffer,
      req.file.mimetype,
      'publication'
    );

    if (!controle.valide) {
      return res.status(415).json({
        success: false,
        message: 'Le fichier est invalide ou son format réel ne correspond pas.'
      });
    }

    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(503).json({
        success: false,
        message: 'Le stockage des médias n’est pas configuré sur le serveur.'
      });
    }

    cloudinary.config({
      cloud_name: cloudName,
      api_key: apiKey,
      api_secret: apiSecret,
      secure: true
    });

    const media = await televerserMediaPublication(req.file);

    return res.status(201).json({
      success: true,
      message: 'Média téléversé avec succès.',
      media: {
        url: media.secure_url,
        type: media.resource_type
      }
    });
  } catch (erreur) {
    console.error('Erreur téléversement publication :', erreur.message);

    return res.status(502).json({
      success: false,
      message: 'Le téléversement du média a échoué.'
    });
  }
});

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  const secret = process.env.JWT_SECRET;

  if (!match || !secret || secret.length < 32) {
    return res.status(401).json({
      success: false,
      message: 'Authentification requise.'
    });
  }

  try {
    req.auth = jwt.verify(match[1], secret, {
      issuer: 'jjm-facebook'
    });

    if (!req.auth.sub || !/^[1-9]\d*$/.test(String(req.auth.sub))) {
      return res.status(401).json({
        success: false,
        message: 'Identifiant de session invalide.'
      });
    }

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: 'Session invalide ou expirée.'
    });
  }
}

function authenticateOptional(req, res, next) {
  const header = req.headers.authorization || '';

  if (!header.trim()) {
    req.auth = { sub: null };
    return next();
  }

  return authenticate(req, res, next);
}

function databaseRequired(req, res, next) {
  const pool = getPool();

  if (!pool) {
    return res.status(503).json({
      success: false,
      message: 'Base de données non configurée.'
    });
  }

  req.db = pool;
  next();
}

function mediaUrlValide(valeur) {
  if (typeof valeur !== 'string' || valeur.length > 2048) {
    return false;
  }

  try {
    const url = new URL(valeur);

    return url.protocol === 'https:'
      && Boolean(url.hostname)
      && !url.username
      && !url.password;
  } catch {
    return false;
  }
}

function identifiantValide(valeur) {
  return /^[1-9]\d*$/.test(String(valeur || ''))
    && Number.isSafeInteger(Number(valeur));
}

const visibiliteValide = valeur =>
  ['public', 'friends', 'private'].includes(valeur);

// Fil d'actualité : public, publications personnelles et amis acceptés.
router.get('/', databaseRequired, authenticateOptional, async (req, res, next) => {
  try {
    const result = await req.db.query(`
      SELECT
        p.id,
        p.user_id,
        p.content,
        p.media_url,
        p.visibility,
        p.created_at,
        p.updated_at,
        u.username,
        u.first_name,
        u.last_name,
        u.profile_picture,
        (
          SELECT COUNT(*)::int
          FROM reactions r
          WHERE r.post_id = p.id
            AND r.reaction_type = 'like'
        ) AS likes_count,
        (
          SELECT COUNT(*)::int
          FROM comments c
          WHERE c.post_id = p.id
        ) AS comments_count,
        EXISTS (
          SELECT 1
          FROM reactions r
          WHERE r.post_id = p.id
            AND r.user_id = $1
            AND r.reaction_type = 'like'
        ) AS liked_by_me
      FROM posts p
      JOIN users u ON u.id = p.user_id
      WHERE
        p.visibility = 'public'
        OR p.user_id = $1
        OR (
          p.visibility = 'friends'
          AND EXISTS (
            SELECT 1
            FROM friendships f
            WHERE f.status = 'accepted'
              AND (
                (f.requester_id = p.user_id AND f.receiver_id = $1)
                OR
                (f.requester_id = $1 AND f.receiver_id = p.user_id)
              )
          )
        )
      ORDER BY p.created_at DESC, p.id DESC
      LIMIT 50
    `, [req.auth.sub]);

    return res.json({
      success: true,
      posts: result.rows
    });
  } catch (err) {
    next(err);
  }
});

// Créer une publication textuelle ou comportant un lien HTTPS de média.
router.post('/', databaseRequired, authenticate, async (req, res, next) => {
  try {
    const content = typeof req.body?.content === 'string'
      ? req.body?.content.trim()
      : '';

    const visibility = req.body?.visibility === undefined
      ? 'public'
      : req.body?.visibility;

    const mediaUrl = req.body?.media_url === undefined
      || req.body?.media_url === null
      ? null
      : req.body.media_url;

    if (content.length > 5000) {
      return res.status(400).json({
        success: false,
        message: 'Le texte ne peut pas dépasser 5000 caractères.'
      });
    }

    if (!visibiliteValide(visibility)) {
      return res.status(400).json({
        success: false,
        message: 'Visibilité invalide.'
      });
    }

    if (mediaUrl !== null && !mediaUrlValide(mediaUrl)) {
      return res.status(400).json({
        success: false,
        message: 'Le lien du média doit être une URL HTTPS valide.'
      });
    }

    if (!content && !mediaUrl) {
      return res.status(400).json({
        success: false,
        message: 'Ajoute un texte ou un lien de média.'
      });
    }

    const result = await req.db.query(`
      INSERT INTO posts (user_id, content, media_url, visibility)
      VALUES ($1, $2, $3, $4)
      RETURNING id, user_id, content, media_url, visibility,
                created_at, updated_at
    `, [req.auth.sub, content, mediaUrl, visibility]);

    const post = result.rows[0];

    const author = await req.db.query(`
      SELECT username, first_name, last_name, profile_picture
      FROM users
      WHERE id = $1
    `, [req.auth.sub]);

    return res.status(201).json({
      success: true,
      message: 'Publication créée avec succès.',
      post: {
        ...post,
        ...(author.rows[0] || {})
      }
    });
  } catch (err) {
    next(err);
  }
});

// Modifier le texte et/ou la visibilité d'une publication personnelle.
router.patch('/:postId', databaseRequired, authenticate, async (req, res, next) => {
  const postId = req.params.postId;

  if (!identifiantValide(postId)) {
    return res.status(400).json({
      success: false,
      message: 'Identifiant de publication invalide.'
    });
  }

  try {
    const contentPresent = Object.prototype.hasOwnProperty.call(
      req.body || {}, 'content'
    );
    const visibilityPresent = Object.prototype.hasOwnProperty.call(
      req.body || {}, 'visibility'
    );

    if (!contentPresent && !visibilityPresent) {
      return res.status(400).json({
        success: false,
        message: 'Indique le texte ou la visibilité à modifier.'
      });
    }

    let content = null;
    let visibility = null;

    if (contentPresent) {
      if (typeof req.body?.content !== 'string') {
        return res.status(400).json({
          success: false,
          message: 'Le texte doit être une chaîne de caractères.'
        });
      }

      content = req.body?.content.trim();

      if (content.length > 5000) {
        return res.status(400).json({
          success: false,
          message: 'Le texte ne peut pas dépasser 5000 caractères.'
        });
      }
    }

    if (visibilityPresent) {
      visibility = req.body?.visibility;

      if (!visibiliteValide(visibility)) {
        return res.status(400).json({
          success: false,
          message: 'Visibilité invalide.'
        });
      }
    }

    const result = await req.db.query(`
      UPDATE posts
      SET content = COALESCE($3::text, content),
          visibility = COALESCE($4::varchar, visibility),
          updated_at = NOW()
      WHERE id = $1
        AND user_id = $2
        AND (
          COALESCE($3::text, content) <> ''
          OR media_url IS NOT NULL
        )
      RETURNING id, user_id, content, media_url, visibility,
                created_at, updated_at
    `, [postId, req.auth.sub, content, visibility]);

    if (!result.rowCount) {
      const existe = await req.db.query(
        'SELECT id FROM posts WHERE id = $1',
        [postId]
      );

      return res.status(existe.rowCount ? 403 : 404).json({
        success: false,
        message: existe.rowCount
          ? 'Tu ne peux modifier que tes propres publications.'
          : 'Publication introuvable.'
      });
    }

    return res.json({
      success: true,
      message: 'Publication modifiée avec succès.',
      post: result.rows[0]
    });
  } catch (err) {
    next(err);
  }
});

// Supprimer une publication personnelle.
router.delete('/:postId', databaseRequired, authenticate, async (req, res, next) => {
  const postId = req.params.postId;

  if (!identifiantValide(postId)) {
    return res.status(400).json({
      success: false,
      message: 'Identifiant de publication invalide.'
    });
  }

  try {
    const result = await req.db.query(`
      DELETE FROM posts
      WHERE id = $1 AND user_id = $2
      RETURNING id
    `, [postId, req.auth.sub]);

    if (!result.rowCount) {
      const existe = await req.db.query(
        'SELECT id FROM posts WHERE id = $1',
        [postId]
      );

      return res.status(existe.rowCount ? 403 : 404).json({
        success: false,
        message: existe.rowCount
          ? 'Tu ne peux supprimer que tes propres publications.'
          : 'Publication introuvable.'
      });
    }

    return res.json({
      success: true,
      message: 'Publication supprimée avec succès.',
      id: result.rows[0].id
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
