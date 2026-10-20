const express = require('express');
const jwt = require('jsonwebtoken');
const { getPool } = require('./db');

const router = express.Router();

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
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: 'Session invalide ou expiree.'
    });
  }
}

function databaseRequired(req, res, next) {
  const pool = getPool();

  if (!pool) {
    return res.status(503).json({
      success: false,
      message: 'Base de donnees non configuree.'
    });
  }

  req.db = pool;
  next();
}

// Consulter le fil d'actualite.
router.get('/', databaseRequired, authenticate, async (req, res, next) => {
  try {
    const result = await req.db.query(`
      SELECT
        p.id,
        p.user_id,
        p.content,
        p.media_url,
        p.visibility,
        p.created_at,
        u.username,
        u.first_name,
        u.last_name,
        u.profile_picture
      FROM posts p
      JOIN users u ON u.id = p.user_id
      WHERE p.visibility = 'public'
         OR p.user_id = $1
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

// Publier un texte.
router.post('/', databaseRequired, authenticate, async (req, res, next) => {
  try {
    const content = typeof req.body?.content === 'string'
      ? req.body.content.trim()
      : '';

    if (!content || content.length > 5000) {
      return res.status(400).json({
        success: false,
        message: 'La publication doit contenir entre 1 et 5000 caracteres.'
      });
    }

    const result = await req.db.query(`
      INSERT INTO posts (user_id, content, visibility)
      VALUES ($1, $2, 'public')
      RETURNING id, user_id, content, media_url, visibility, created_at
    `, [req.auth.sub, content]);

    const post = result.rows[0];

    const author = await req.db.query(`
      SELECT username, first_name, last_name, profile_picture
      FROM users
      WHERE id = $1
    `, [req.auth.sub]);

    return res.status(201).json({
      success: true,
      message: 'Publication creee avec succes.',
      post: {
        ...post,
        ...(author.rows[0] || {})
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
