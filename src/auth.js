const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getPool } = require('./db');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Trop de tentatives de connexion. Réessaie dans 15 minutes.'
  }
});

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

    const accountCode =
      'JJM-' + require('crypto').randomBytes(5).toString('hex').toUpperCase();

    const result = await req.db.query(
      `INSERT INTO users
       (account_code, username, first_name, last_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, account_code, username, first_name, last_name, email,
                 phone, bio, created_at`,
      [
        accountCode,
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
        message: 'Un conflit de donnees empeche la creation du compte. Reessayez.'
      });
    }

    next(err);
  }
});

router.post('/login', loginLimiter, databaseRequired, async (req, res, next) => {
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
    const accountCode = identifier.trim().toUpperCase();
    let result;

    if (/^JJM-[A-F0-9]{10}$/.test(accountCode)) {
      result = await req.db.query(
        `SELECT id, account_code, username, first_name, last_name,
                email, phone, bio, password_hash, created_at
         FROM users
         WHERE account_code = $1`,
        [accountCode]
      );
    } else {
      result = await req.db.query(
        `SELECT id, account_code, username, first_name, last_name,
                email, phone, bio, password_hash, created_at
         FROM users
         WHERE LOWER(username) = $1
            OR LOWER(email) = $1
            OR phone = $2`,
        [value, identifier.trim()]
      );
    }

    if (result.rows.length > 1) {
      return res.status(409).json({
        success: false,
        code: 'ACCOUNT_CODE_REQUIRED',
        message: 'Plusieurs comptes correspondent. Connectez-vous avec votre code de compte JJM.'
      });
    }

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


router.put('/me', databaseRequired, authenticate, async (req, res, next) => {
  try {
    let { first_name, last_name, username, bio } = req.body || {};

    first_name = typeof first_name === 'string' ? first_name.trim() : '';
    last_name = typeof last_name === 'string' ? last_name.trim() : '';
    username = typeof username === 'string'
      ? username.trim().toLowerCase()
      : '';
    bio = typeof bio === 'string' ? bio.trim() : '';

    if (
      first_name.length < 1 ||
      first_name.length > 80 ||
      last_name.length < 1 ||
      last_name.length > 80 ||
      !/^[a-z0-9_]{3,30}$/.test(username) ||
      bio.length > 500
    ) {
      return res.status(400).json({
        success: false,
        message: 'Vérifie le prénom, le nom, le nom utilisateur et la biographie (500 caractères maximum).'
      });
    }

    const result = await req.db.query(
      `UPDATE users
       SET first_name = $1,
           last_name = $2,
           username = $3,
           bio = $4,
           updated_at = NOW()
       WHERE id = $5
       RETURNING id, username, first_name, last_name,
                 email, phone, bio, profile_picture,
                 cover_picture, created_at`,
      [first_name, last_name, username, bio, req.auth.sub]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur introuvable.'
      });
    }

    return res.json({
      success: true,
      message: 'Profil mis à jour avec succès.',
      user: result.rows[0]
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'Ce nom utilisateur est déjà utilisé.'
      });
    }

    next(err);
  }
});


const crypto = require('crypto');

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});


router.post('/forgot-password', forgotPasswordLimiter, databaseRequired, async (req, res, next) => {
  const accountCode = typeof req.body?.account_code === 'string'
    ? req.body.account_code.trim().toUpperCase()
    : '';
  const email = typeof req.body?.email === 'string'
    ? req.body.email.trim().toLowerCase()
    : '';

  if (!/^JJM-[A-F0-9]{10}$/.test(accountCode) ||
      !email || email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      success: false,
      message: 'Code de compte ou adresse e-mail invalide.'
    });
  }

  try {
    const result = await req.db.query(
      `SELECT id, account_code, email
       FROM users
       WHERE account_code = $1 AND LOWER(email) = $2
       LIMIT 1`,
      [accountCode, email]
    );

    const message = 'Si le code de compte et l’adresse correspondent, un code sera envoyé par e-mail.';

    if (!result.rows.length) {
      return res.json({ success: true, message });
    }

    if (!process.env.RESEND_API_KEY) {
      console.error('RESEND_API_KEY absente de l’environnement serveur.');
      return res.status(503).json({
        success: false,
        message: 'Le service d’envoi d’e-mails est temporairement indisponible.'
      });
    }

    const user = result.rows[0];
    const code = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');

    await req.db.query(
      'DELETE FROM password_reset_codes WHERE user_id = $1',
      [user.id]
    );

    await req.db.query(
      `INSERT INTO password_reset_codes (user_id, code_hash, expires_at, attempts)
       VALUES ($1, $2, NOW() + INTERVAL '10 minutes', 0)`,
      [user.id, codeHash]
    );

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + process.env.RESEND_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: process.env.RESEND_FROM || 'JJM FACEBOOK <onboarding@resend.dev>',
        to: [user.email],
        subject: 'Code de réinitialisation — JJM FACEBOOK',
        text: 'Ton code est : ' + code +
          '\nIl expire dans 10 minutes. Si tu n’as pas demandé ce code, ignore cet e-mail.'
      })
    });

    if (!response.ok) {
      console.error('Échec de l’envoi du code par Resend :', response.status);
      await req.db.query(
        'DELETE FROM password_reset_codes WHERE user_id = $1',
        [user.id]
      );
      return res.status(503).json({
        success: false,
        message: 'Impossible d’envoyer le code pour le moment.'
      });
    }

    return res.json({ success: true, message });
  } catch (err) {
    next(err);
  }
});

const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

router.post('/reset-password', resetPasswordLimiter, databaseRequired, async (req, res, next) => {
  const accountCode = typeof req.body?.account_code === 'string'
    ? req.body.account_code.trim().toUpperCase()
    : '';
  const email = typeof req.body?.email === 'string'
    ? req.body.email.trim().toLowerCase()
    : '';
  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  const password = typeof req.body?.new_password === 'string' ? req.body.new_password : '';

  if (!/^JJM-[A-F0-9]{10}$/.test(accountCode) ||
      !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !/^[0-9]{6}$/.test(code)) {
    return res.status(400).json({
      success: false,
      message: 'Code de compte, adresse e-mail ou code de vérification invalide.'
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      success: false,
      message: 'Le mot de passe doit contenir entre 8 et 128 caractères.'
    });
  }

  const codeHash = crypto.createHash('sha256').update(code).digest('hex');
  const client = await req.db.connect();

  try {
    await client.query('BEGIN');

    const result = await client.query(
      `SELECT r.id AS reset_id, r.user_id, r.code_hash, r.expires_at, r.attempts
       FROM password_reset_codes r
       JOIN users u ON u.id = r.user_id
       WHERE u.account_code = $1 AND LOWER(u.email) = $2
       ORDER BY r.created_at DESC
       LIMIT 1
       FOR UPDATE OF r`,
      [accountCode, email]
    );

    if (!result.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        message: 'Code invalide ou expiré. Demande un nouveau code si nécessaire.'
      });
    }

    const reset = result.rows[0];

    if (new Date(reset.expires_at).getTime() <= Date.now() || reset.attempts >= 5) {
      await client.query(
        'DELETE FROM password_reset_codes WHERE id = $1',
        [reset.reset_id]
      );
      await client.query('COMMIT');
      return res.status(400).json({
        success: false,
        message: 'Code invalide ou expiré. Demande un nouveau code.'
      });
    }

    if (reset.code_hash !== codeHash) {
      await client.query(
        'UPDATE password_reset_codes SET attempts = attempts + 1 WHERE id = $1',
        [reset.reset_id]
      );
      await client.query('COMMIT');
      return res.status(400).json({
        success: false,
        message: 'Code invalide ou expiré.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await client.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [passwordHash, reset.user_id]
    );

    await client.query(
      'DELETE FROM password_reset_codes WHERE user_id = $1',
      [reset.user_id]
    );

    await client.query('COMMIT');

    return res.json({
      success: true,
      message: 'Mot de passe réinitialisé avec succès. Tu peux te connecter.'
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});


module.exports = router;
