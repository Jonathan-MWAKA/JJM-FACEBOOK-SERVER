require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const { getPool } = require('./db');
const { initializeDatabase } = require('./schema');
const authRoutes = require('./auth');
const postsRoutes = require('./posts');

const app = express();

app.disable('x-powered-by');

app.use(helmet());

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*'
}));

app.use(express.json({ limit: '1mb' }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

app.get('/', (req, res) => {
  res.json({
    application: 'JJM FACEBOOK',
    server: 'online',
    version: '1.0.0',
    message: 'Bienvenue sur JJM FACEBOOK'
  });
});

app.get('/api/health', async (req, res) => {
  const pool = getPool();

  let database = 'not_configured';

  if (pool) {
    try {
      await pool.query('SELECT 1');
      database = 'connected';
    } catch (err) {
      database = 'unavailable';
    }
  }

  res.status(database === 'unavailable' ? 503 : 200).json({
    success: database !== 'unavailable',
    server: 'JJM FACEBOOK',
    status: database === 'unavailable' ? 'degraded' : 'healthy',
    database,
    timestamp: new Date().toISOString()
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/posts', postsRoutes);

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route introuvable'
  });
});

app.use((err, req, res, next) => {
  console.error('Erreur serveur :', err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: 'Une erreur interne est survenue.'
  });
});

const port = Number(process.env.PORT) || 3000;

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`JJM FACEBOOK demarre sur le port ${port}`);

  initializeDatabase()
    .then((initialized) => {
      if (initialized) {
        console.log('Base de donnees initialisee.');
      } else {
        console.log(
          'Base de donnees en attente de configuration.'
        );
      }
    })
    .catch((err) => {
      console.error(
        'Initialisation PostgreSQL impossible :',
        err.message
      );
    });
});

function shutdown() {
  server.close(async () => {
    const pool = getPool();

    if (pool) {
      await pool.end().catch(() => {});
    }

    process.exit(0);
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
