const { getPool } = require('./db');

async function initializeDatabase() {
  const pool = getPool();

  if (!pool) {
    console.log(
      'PostgreSQL non configure : initialisation reportee.'
    );
    return false;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(30) NOT NULL UNIQUE,
      first_name VARCHAR(80) NOT NULL,
      last_name VARCHAR(80) NOT NULL,
      email VARCHAR(254) UNIQUE,
      phone VARCHAR(25) UNIQUE,
      password_hash TEXT NOT NULL,
      bio VARCHAR(500) NOT NULL DEFAULT '',
      profile_picture TEXT,
      cover_picture TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (email IS NOT NULL OR phone IS NOT NULL)
    );

    CREATE TABLE IF NOT EXISTS friendships (
      id BIGSERIAL PRIMARY KEY,
      requester_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      receiver_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (requester_id, receiver_id),
      CHECK (requester_id <> receiver_id)
    );

    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      content TEXT NOT NULL DEFAULT '',
      media_url TEXT,
      visibility VARCHAR(20) NOT NULL DEFAULT 'public'
        CHECK (visibility IN ('public', 'friends', 'private')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (content <> '' OR media_url IS NOT NULL)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES posts(id)
        ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (length(trim(content)) > 0)
    );

    CREATE TABLE IF NOT EXISTS reactions (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES posts(id)
        ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      reaction_type VARCHAR(20) NOT NULL DEFAULT 'like',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      receiver_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      content TEXT NOT NULL,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (sender_id <> receiver_id),
      CHECK (length(trim(content)) > 0)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      actor_id BIGINT REFERENCES users(id)
        ON DELETE SET NULL,
      type VARCHAR(40) NOT NULL,
      reference_id BIGINT,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reports (
      id BIGSERIAL PRIMARY KEY,
      reporter_id BIGINT NOT NULL REFERENCES users(id)
        ON DELETE CASCADE,
      target_type VARCHAR(20) NOT NULL,
      target_id BIGINT NOT NULL,
      reason TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_reset_codes (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_password_reset_user
      ON password_reset_codes(user_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_posts_created
      ON posts(created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_posts_user
      ON posts(user_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_comments_post
      ON comments(post_id, created_at);

    CREATE INDEX IF NOT EXISTS idx_messages_conversation
      ON messages(sender_id, receiver_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_notifications_user
      ON notifications(user_id, created_at DESC);
  `);

  console.log('Schema PostgreSQL initialise.');
  return true;
}

module.exports = { initializeDatabase };
