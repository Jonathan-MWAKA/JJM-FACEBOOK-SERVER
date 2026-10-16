const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getPool } = require('./db');

const router = express.Router();

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    return null;
  }

  return secret;
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

function createToken(user) {
  const secret = getJwtSecret();

  if (!secret) {
    throw new Error('JWT_SECRET absent ou trop court.');
  }

  return jwt.sign(
    {
      sub: String(user.id),
      username: user.username
    },
    secret,
    {
      expiresIn: '7d',
      issuer: 'jjm-facebook'
    }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  const secret = getJwtSecret();

  if (!match || !secret) {
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

router.post('/register', databaseRequired, async (req, res, next) => {
  try {
    const secret = getJwtSecret();

    if (!secret) {
      return res.status(503).json({
        success: false,
        message: 'Configuration de securite incomplete.'
      });
    }

    let {
      username,
      first_name,
      last_name,
      email,
      phone,
      password
    } = req.body || {};

    username = typeof username === 'string'
      ? username.trim().toLowerCase()
      : '';

    first_name = typeof first_name === 'string'
      ? first_name.trim()
      : '';

    last_name = typeof last_name === 'string'
      ? last_name.trim()
      : '';

    email = typeof email === 'string'
      ? email.trim().toLowerCase() || null
      : null;

    phone = typeof phone === 'string'
      ? phone.trim() || null
      : null;

    if (
      !/^[a-z0-9_]{3,30}$/.test(username) ||
      first_name.length < 1 ||
      first_name.length > 80 ||
      last_name.length < 1 ||
      last_name.length > 80 ||
      typeof password !== 'string' ||
      password.length < 8 ||
      Buffer.byteLength(password, 'utf8') > 72
    ) {
      return res.status(400).json({
        success: false,
        message: 'Informations invalides. Verifiez le nom utilisateur, le nom, le prenom et le mot de passe (8 caracteres minimum).'
      });
    }

    if (!email && !phone) {
      return res.status(400).json({
        success: false,
        message: 'Un email ou un numero de telephone est requis.'
      });
    }

    if (
      email &&
      (
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      )
    ) {
      return res.status(400).json({
        success: false,
        message: 'Adresse email invalide.'
      });
    }

    if (phone && !/^\+?[0-9 ()-]{7,25}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'Numero de telephone invalide.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await req.db.query(
      `INSERT INTO users
       (username, first_name, last_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, first_name, last_name, email,
                 phone, bio, created_at`,
      [
        username,
        first_name,
        last_name,
        email,
        phone,
        passwordHash
      ]
    );

    const user = result.rows[0];
    const token = createToken(user);

    return res.status(201).json({
      success: true,
      message: 'Compte cree avec succes.',
      token,
      user
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'Ce nom utilisateur, email ou numero est deja utilise.'
      });
    }

    next(err);
  }
});

router.post('/login', databaseRequired, async (req, res, next) => {
  try {
    const secret = getJwtSecret();

    if (!secret) {
      return res.status(503).json({
        success: false,
        message: 'Configuration de securite incomplete.'
      });
    }

    const { identifier, password } = req.body || {};

    if (
      typeof identifier !== 'string' ||
      typeof password !== 'string' ||
      !identifier.trim() ||
      !password ||
      Buffer.byteLength(password, 'utf8') > 72
    ) {
      return res.status(400).json({
        success: false,
        message: 'Identifiant ou mot de passe invalide.'
      });
    }

    const value = identifier.trim().toLowerCase();

    const result = await req.db.query(
      `SELECT id, username, first_name, last_name, email,
              phone, bio, password_hash, created_at
       FROM users
       WHERE username = $1 OR email = $1 OR phone = $2
       LIMIT 1`,
      [value, identifier.trim()]
    );

    const user = result.rows[0];

    const valid = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: 'Identifiants incorrects.'
      });
    }

    const token = createToken(user);
    delete user.password_hash;

    return res.json({
      success: true,
      message: 'Connexion reussie.',
      token,
      user
    });
  } catch (err) {
    next(err);
  }
});

router.get('/me', databaseRequired, authenticate, async (req, res, next) => {
  try {
    const result = await req.db.query(
      `SELECT id, username, first_name, last_name,
              email, phone, bio, profile_picture,
              cover_picture, created_at
       FROM users
       WHERE id = $1`,
      [req.auth.sub]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur introuvable.'
      });
    }

    return res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
