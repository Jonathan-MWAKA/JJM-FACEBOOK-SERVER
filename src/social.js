const express = require('express');
const jwt = require('jsonwebtoken');
const { getPool } = require('./db');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');


const router = express.Router();

function authentifier(req, res, next) {
    const entete = req.headers.authorization || '';
    const correspondance = entete.match(/^Bearer\s+(.+)$/i);

    if (!correspondance) {
        return res.status(401).json({
            success: false,
            message: 'Connexion requise.'
        });
    }

    const secret = process.env.JWT_SECRET;

    if (!secret || secret.length < 32) {
        return res.status(503).json({
            success: false,
            message: 'Configuration de sécurité indisponible.'
        });
    }

    try {
        const jeton = jwt.verify(correspondance[1], secret, {
            issuer: 'jjm-facebook'
        });

        if (!jeton.sub) {
            return res.status(401).json({
                success: false,
                message: 'Session invalide.'
            });
        }

        req.auth = jeton;
        req.userId = Number(jeton.sub);

        if (!Number.isSafeInteger(req.userId) || req.userId <= 0) {
            return res.status(401).json({
                success: false,
                message: 'Identifiant de session invalide.'
            });
        }

        next();
    } catch {
        return res.status(401).json({
            success: false,
            message: 'Session expirée ou invalide.'
        });
    }
}

function baseDeDonnees(req, res, next) {
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

router.use(authentifier, baseDeDonnees);

function erreurServeur(res, erreur) {
    console.error('Erreur JJM FACEBOOK SOCIAL:', erreur.message);

    return res.status(500).json({
        success: false,
        message: 'Une erreur est survenue. Réessaie plus tard.'
    });
}

async function notifier(db, utilisateur, acteur, type, reference) {
    if (Number(utilisateur) === Number(acteur)) return;

    await db.query(
        `INSERT INTO notifications (user_id, actor_id, type, reference_id)
         VALUES ($1, $2, $3, $4)`,
        [utilisateur, acteur, type, reference || null]
    );
}

/* RECHERCHE D'UTILISATEURS */
router.get('/search', async (req, res) => {
    try {
        const terme = String(req.query.q || '').trim().slice(0, 80);

        if (terme.length < 2) {
            return res.json({ success: true, users: [] });
        }

        const resultat = await req.db.query(
            `SELECT id, username, first_name, last_name,
                    bio, profile_picture
             FROM users
             WHERE id <> $1
               AND (
                 username ILIKE $2 OR
                 first_name ILIKE $2 OR
                 last_name ILIKE $2 OR
                 (first_name || ' ' || last_name) ILIKE $2
               )
             ORDER BY username
             LIMIT 30`,
            [req.userId, '%' + terme + '%']
        );

        res.json({ success: true, users: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* LISTE DES AMIS */
router.get('/friends', async (req, res) => {
    try {
        const resultat = await req.db.query(
            `SELECT u.id, u.username, u.first_name, u.last_name,
                    u.profile_picture, f.created_at AS friendship_date
             FROM friendships f
             JOIN users u ON u.id =
                CASE WHEN f.requester_id = $1
                     THEN f.receiver_id ELSE f.requester_id END
             WHERE (f.requester_id = $1 OR f.receiver_id = $1)
               AND f.status = 'accepted'
             ORDER BY u.username`,
            [req.userId]
        );

        res.json({ success: true, friends: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* DEMANDES D'AMIS REÇUES */
router.get('/friends/requests', async (req, res) => {
    try {
        const resultat = await req.db.query(
            `SELECT f.id AS request_id, f.created_at,
                    u.id, u.username, u.first_name, u.last_name,
                    u.profile_picture
             FROM friendships f
             JOIN users u ON u.id = f.requester_id
             WHERE f.receiver_id = $1 AND f.status = 'pending'
             ORDER BY f.created_at DESC`,
            [req.userId]
        );

        res.json({ success: true, requests: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* ENVOYER UNE DEMANDE D'AMI */
router.post('/friends/:userId', async (req, res) => {
    const cible = Number(req.params.userId);

    if (!Number.isSafeInteger(cible) || cible <= 0 ||
        cible === req.userId) {
        return res.status(400).json({
            success: false,
            message: 'Utilisateur invalide.'
        });
    }

    try {
        const existe = await req.db.query(
            'SELECT id FROM users WHERE id = $1',
            [cible]
        );

        if (!existe.rowCount) {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur introuvable.'
            });
        }

        const ancienne = await req.db.query(
            `SELECT id, status FROM friendships
             WHERE (requester_id = $1 AND receiver_id = $2)
                OR (requester_id = $2 AND receiver_id = $1)
             LIMIT 1`,
            [req.userId, cible]
        );

        if (ancienne.rowCount) {
            const relation = ancienne.rows[0];

            if (relation.status === 'accepted') {
                return res.json({
                    success: true,
                    message: 'Vous êtes déjà amis.'
                });
            }

            if (relation.status === 'pending') {
                return res.status(409).json({
                    success: false,
                    message: 'Une demande est déjà en attente.'
                });
            }

            await req.db.query(
                `DELETE FROM friendships
                 WHERE id = $1`,
                [relation.id]
            );
        }

        const ajout = await req.db.query(
            `INSERT INTO friendships
                (requester_id, receiver_id, status)
             VALUES ($1, $2, 'pending')
             RETURNING id`,
            [req.userId, cible]
        );

        await notifier(
            req.db, cible, req.userId,
            'friend_request', ajout.rows[0].id
        );

        res.status(201).json({
            success: true,
            message: 'Demande d’ami envoyée.'
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* ACCEPTER OU REFUSER UNE DEMANDE */
router.post('/friends/:userId/respond', async (req, res) => {
    const demandeur = Number(req.params.userId);
    const action = String(req.body.action || '').toLowerCase();

    if (!Number.isSafeInteger(demandeur) ||
        !['accept', 'reject'].includes(action)) {
        return res.status(400).json({
            success: false,
            message: 'Action invalide.'
        });
    }

    try {
        const resultat = await req.db.query(
            `UPDATE friendships
             SET status = $1
             WHERE requester_id = $2
               AND receiver_id = $3
               AND status = 'pending'
             RETURNING id`,
            [action === 'accept' ? 'accepted' : 'rejected',
             demandeur, req.userId]
        );

        if (!resultat.rowCount) {
            return res.status(404).json({
                success: false,
                message: 'Demande introuvable ou déjà traitée.'
            });
        }

        if (action === 'accept') {
            await notifier(
                req.db, demandeur, req.userId,
                'friend_accepted', resultat.rows[0].id
            );
        }

        res.json({
            success: true,
            message: action === 'accept'
                ? 'Demande acceptée.'
                : 'Demande refusée.'
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* RETIRER UN AMI */
router.delete('/friends/:userId', async (req, res) => {
    const cible = Number(req.params.userId);

    if (!Number.isSafeInteger(cible) || cible <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Identifiant invalide.'
        });
    }

    try {
        await req.db.query(
            `DELETE FROM friendships
             WHERE status = 'accepted'
               AND (
                 (requester_id = $1 AND receiver_id = $2)
                 OR
                 (requester_id = $2 AND receiver_id = $1)
               )`,
            [req.userId, cible]
        );

        res.json({ success: true, message: 'Relation mise à jour.' });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* AIMER / RETIRER SON J'AIME */
router.post('/posts/:postId/reaction', async (req, res) => {
    const postId = Number(req.params.postId);

    if (!Number.isSafeInteger(postId) || postId <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Publication invalide.'
        });
    }

    try {
        const post = await req.db.query(
            `SELECT p.id, p.user_id
             FROM posts p
             WHERE p.id = $1
               AND (
                 p.visibility = 'public'
                 OR p.user_id = $2
                 OR (
                   p.visibility = 'friends'
                   AND EXISTS (
                     SELECT 1
                     FROM friendships f
                     WHERE f.status = 'accepted'
                       AND (
                         (f.requester_id = p.user_id AND f.receiver_id = $2)
                         OR
                         (f.requester_id = $2 AND f.receiver_id = p.user_id)
                       )
                   )
                 )
               )`,
            [postId, req.userId]
        );

        if (!post.rowCount) {
            return res.status(404).json({
                success: false,
                message: 'Publication introuvable.'
            });
        }

        const existant = await req.db.query(
            `SELECT id FROM reactions
             WHERE post_id = $1 AND user_id = $2`,
            [postId, req.userId]
        );

        if (existant.rowCount) {
            await req.db.query(
                'DELETE FROM reactions WHERE id = $1',
                [existant.rows[0].id]
            );

            return res.json({
                success: true,
                liked: false,
                message: 'J’aime retiré.'
            });
        }

        await req.db.query(
            `INSERT INTO reactions (post_id, user_id, reaction_type)
             VALUES ($1, $2, 'like')`,
            [postId, req.userId]
        );

        await notifier(
            req.db, post.rows[0].user_id,
            req.userId, 'like', postId
        );

        res.json({ success: true, liked: true, message: 'J’aime ajouté.' });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* LIRE LES COMMENTAIRES */
router.get('/posts/:postId/comments', async (req, res) => {
    const postId = Number(req.params.postId);

    try {
        const resultat = await req.db.query(
            `SELECT c.id, c.post_id, c.content, c.created_at,
                    u.id AS user_id, u.username,
                    u.first_name, u.last_name, u.profile_picture
             FROM comments c
             JOIN users u ON u.id = c.user_id
             JOIN posts p ON p.id = c.post_id
             WHERE c.post_id = $1
               AND (
                 p.visibility = 'public'
                 OR p.user_id = $2
                 OR (
                   p.visibility = 'friends'
                   AND EXISTS (
                     SELECT 1
                     FROM friendships f
                     WHERE f.status = 'accepted'
                       AND (
                         (f.requester_id = p.user_id AND f.receiver_id = $2)
                         OR
                         (f.requester_id = $2 AND f.receiver_id = p.user_id)
                       )
                   )
                 )
               )
             ORDER BY c.created_at ASC
             LIMIT 200`,
            [postId, req.userId]
        );

        res.json({ success: true, comments: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* AJOUTER UN COMMENTAIRE */
router.post('/posts/:postId/comments', async (req, res) => {
    const postId = Number(req.params.postId);
    const contenu = String(req.body.content || '').trim();

    if (!Number.isSafeInteger(postId) || postId <= 0 ||
        !contenu || contenu.length > 2000) {
        return res.status(400).json({
            success: false,
            message: 'Commentaire invalide (1 à 2000 caractères).'
        });
    }

    try {
        const post = await req.db.query(
            `SELECT p.id, p.user_id
             FROM posts p
             WHERE p.id = $1
               AND (
                 p.visibility = 'public'
                 OR p.user_id = $2
                 OR (
                   p.visibility = 'friends'
                   AND EXISTS (
                     SELECT 1
                     FROM friendships f
                     WHERE f.status = 'accepted'
                       AND (
                         (f.requester_id = p.user_id AND f.receiver_id = $2)
                         OR
                         (f.requester_id = $2 AND f.receiver_id = p.user_id)
                       )
                   )
                 )
               )`,
            [postId, req.userId]
        );

        if (!post.rowCount) {
            return res.status(404).json({
                success: false,
                message: 'Publication introuvable.'
            });
        }

        const resultat = await req.db.query(
            `INSERT INTO comments (post_id, user_id, content)
             VALUES ($1, $2, $3)
             RETURNING id, post_id, user_id, content, created_at`,
            [postId, req.userId, contenu]
        );

        await notifier(
            req.db, post.rows[0].user_id,
            req.userId, 'comment', postId
        );

        res.status(201).json({
            success: true,
            comment: resultat.rows[0]
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* NOTIFICATIONS */
router.get('/notifications', async (req, res) => {
    try {
        const resultat = await req.db.query(
            `SELECT n.id, n.type, n.reference_id, n.read_at, n.created_at,
                    u.id AS actor_id, u.username,
                    u.first_name, u.last_name, u.profile_picture
             FROM notifications n
             LEFT JOIN users u ON u.id = n.actor_id
             WHERE n.user_id = $1
             ORDER BY n.created_at DESC
             LIMIT 100`,
            [req.userId]
        );

        res.json({ success: true, notifications: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});

router.post('/notifications/:id/read', async (req, res) => {
    try {
        await req.db.query(
            `UPDATE notifications SET read_at = NOW()
             WHERE id = $1 AND user_id = $2`,
            [Number(req.params.id), req.userId]
        );

        res.json({ success: true });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* CONVERSATION PRIVÉE : AMIS ACCEPTÉS UNIQUEMENT */
router.get('/messages/:userId', async (req, res) => {
    const cible = Number(req.params.userId);

    try {
        const ami = await req.db.query(
            `SELECT id FROM friendships
             WHERE status = 'accepted'
               AND (
                 (requester_id = $1 AND receiver_id = $2)
                 OR
                 (requester_id = $2 AND receiver_id = $1)
               )`,
            [req.userId, cible]
        );

        if (!ami.rowCount) {
            return res.status(403).json({
                success: false,
                message: 'Les messages sont réservés aux amis.'
            });
        }

        const resultat = await req.db.query(
            `SELECT id, sender_id, receiver_id, content, read_at, created_at
             FROM messages
             WHERE (sender_id = $1 AND receiver_id = $2)
                OR (sender_id = $2 AND receiver_id = $1)
             ORDER BY created_at ASC
             LIMIT 300`,
            [req.userId, cible]
        );

        await req.db.query(
            `UPDATE messages SET read_at = NOW()
             WHERE sender_id = $1 AND receiver_id = $2 AND read_at IS NULL`,
            [cible, req.userId]
        );

        res.json({ success: true, messages: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});

router.post('/messages/:userId', async (req, res) => {
    const cible = Number(req.params.userId);
    const contenu = String(req.body.content || '').trim();

    if (!Number.isSafeInteger(cible) || cible <= 0 ||
        cible === req.userId || !contenu || contenu.length > 4000) {
        return res.status(400).json({
            success: false,
            message: 'Message invalide.'
        });
    }

    try {
        const ami = await req.db.query(
            `SELECT id FROM friendships
             WHERE status = 'accepted'
               AND (
                 (requester_id = $1 AND receiver_id = $2)
                 OR
                 (requester_id = $2 AND receiver_id = $1)
               )`,
            [req.userId, cible]
        );

        if (!ami.rowCount) {
            return res.status(403).json({
                success: false,
                message: 'Vous devez être amis pour échanger des messages.'
            });
        }

        const resultat = await req.db.query(
            `INSERT INTO messages (sender_id, receiver_id, content)
             VALUES ($1, $2, $3)
             RETURNING id, sender_id, receiver_id, content, read_at, created_at`,
            [req.userId, cible, contenu]
        );

        await notifier(
            req.db, cible, req.userId,
            'message', resultat.rows[0].id
        );

        res.status(201).json({
            success: true,
            message: resultat.rows[0]
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* STORIES : EXPIRATION APRÈS 24 HEURES */
let storiesInitialisees = null;

async function assurerTableStories(db) {
    if (!storiesInitialisees) {
        storiesInitialisees = db.query(`
            CREATE TABLE IF NOT EXISTS stories (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                media_url TEXT NOT NULL,
                caption VARCHAR(500) DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS stories_created_idx
                ON stories (created_at DESC);
        `).catch(e => {
            storiesInitialisees = null;
            throw e;
        });
    }

    await storiesInitialisees;
}

router.get('/stories', async (req, res) => {
    try {
        await assurerTableStories(req.db);

        const resultat = await req.db.query(
            `SELECT s.id, s.user_id, s.media_url, s.caption, s.created_at,
                    u.username, u.first_name, u.last_name, u.profile_picture
             FROM stories s
             JOIN users u ON u.id = s.user_id
             WHERE s.created_at > NOW() - INTERVAL '24 hours'
             ORDER BY s.created_at DESC
             LIMIT 100`,
            []
        );

        res.json({ success: true, stories: resultat.rows });
    } catch (e) {
        erreurServeur(res, e);
    }
});


/* UPLOAD STORY : GALERIE ANDROID -> CLOUDINARY -> POSTGRESQL */
const recevoirMediaStory = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 25 * 1024 * 1024,
        files: 1,
        fields: 1,
        fieldSize: 500 * 4
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

function televerserVersCloudinary(fichier) {
    return new Promise((resolve, reject) => {
        const flux = cloudinary.uploader.upload_stream({
            resource_type: 'auto',
            folder: 'jjm-facebook/stories',
            transformation: undefined
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

router.post('/stories/upload', (req, res, next) => {
    recevoirMediaStory.single('media')(req, res, (erreur) => {
        if (erreur) {
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
                    message: 'Format accepté : JPEG, PNG, WEBP, GIF, MP4, WEBM ou MOV.'
                });
            }

            return res.status(400).json({
                success: false,
                message: 'Impossible de recevoir ce fichier.'
            });
        }

        next();
    });
}, async (req, res) => {
    if (!req.file) {
        return res.status(400).json({
            success: false,
            message: 'Sélectionne une photo ou une vidéo.'
        });
    }

    const caption = String(req.body.caption || '').trim();

    if (caption.length > 500) {
        return res.status(400).json({
            success: false,
            message: 'La légende ne doit pas dépasser 500 caractères.'
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

    try {
        const media = await televerserVersCloudinary(req.file);

        await assurerTableStories(req.db);

        const resultat = await req.db.query(
            `INSERT INTO stories (user_id, media_url, caption)
             VALUES ($1, $2, $3)
             RETURNING id, user_id, media_url, caption, created_at`,
            [req.userId, media.secure_url, caption]
        );

        return res.status(201).json({
            success: true,
            message: 'Story publiée avec succès.',
            story: {
                ...resultat.rows[0],
                media_type: media.resource_type
            }
        });
    } catch (e) {
        console.error('Erreur publication story Cloudinary:', e.message);

        return res.status(502).json({
            success: false,
            message: 'Le téléversement ou l’enregistrement de la story a échoué.'
        });
    }
});

router.post('/stories', async (req, res) => {
    const mediaUrl = String(req.body.media_url || '').trim();
    const caption = String(req.body.caption || '').trim();

    if (!/^https:\/\/\S+$/i.test(mediaUrl) || caption.length > 500) {
        return res.status(400).json({
            success: false,
            message: 'Il faut une URL HTTPS valide et une légende de 500 caractères maximum.'
        });
    }

    try {
        await assurerTableStories(req.db);

        const resultat = await req.db.query(
            `INSERT INTO stories (user_id, media_url, caption)
             VALUES ($1, $2, $3)
             RETURNING id, user_id, media_url, caption, created_at`,
            [req.userId, mediaUrl, caption]
        );

        res.status(201).json({
            success: true,
            story: resultat.rows[0]
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});


/* VUES DES STORIES : UNE VUE PAR UTILISATEUR ET PAR MEDIA */
let storyViewsInitialisees = null;

async function assurerTableVuesStories(db) {
    if (!storyViewsInitialisees) {
        storyViewsInitialisees = db.query(`
            CREATE TABLE IF NOT EXISTS story_views (
                id BIGSERIAL PRIMARY KEY,
                story_id BIGINT NOT NULL REFERENCES stories(id)
                    ON DELETE CASCADE,
                viewer_id BIGINT NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (story_id, viewer_id)
            );

            CREATE INDEX IF NOT EXISTS story_views_story_idx
                ON story_views (story_id, viewed_at DESC);
        `).catch(e => {
            storyViewsInitialisees = null;
            throw e;
        });
    }

    await storyViewsInitialisees;
}

/* ENREGISTRER UNE VUE */
router.post('/stories/:id/view', async (req, res) => {
    const storyId = Number(req.params.id);

    if (!Number.isSafeInteger(storyId) || storyId <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Identifiant de story invalide.'
        });
    }

    try {
        await assurerTableStories(req.db);
        await assurerTableVuesStories(req.db);

        const storyResult = await req.db.query(
            `SELECT id, user_id
             FROM stories
             WHERE id = $1
               AND created_at > NOW() - INTERVAL '24 hours'`,
            [storyId]
        );

        if (storyResult.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Story introuvable ou expirée.'
            });
        }

        const story = storyResult.rows[0];

        if (Number(story.user_id) === req.userId) {
            return res.json({
                success: true,
                recorded: false,
                message: 'La vue de l’auteur n’est pas comptabilisée.'
            });
        }

        const resultat = await req.db.query(
            `INSERT INTO story_views (story_id, viewer_id)
             VALUES ($1, $2)
             ON CONFLICT (story_id, viewer_id) DO NOTHING
             RETURNING id`,
            [storyId, req.userId]
        );

        const compteur = await req.db.query(
            `SELECT COUNT(*)::int AS views_count
             FROM story_views
             WHERE story_id = $1`,
            [storyId]
        );

        return res.json({
            success: true,
            recorded: resultat.rowCount > 0,
            views_count: compteur.rows[0].views_count
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});

/* LISTE DES SPECTATEURS : AUTEUR UNIQUEMENT */
router.get('/stories/:id/viewers', async (req, res) => {
    const storyId = Number(req.params.id);

    if (!Number.isSafeInteger(storyId) || storyId <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Identifiant de story invalide.'
        });
    }

    try {
        await assurerTableStories(req.db);
        await assurerTableVuesStories(req.db);

        const storyResult = await req.db.query(
            `SELECT id, user_id
             FROM stories
             WHERE id = $1
               AND created_at > NOW() - INTERVAL '24 hours'`,
            [storyId]
        );

        if (storyResult.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Story introuvable ou expirée.'
            });
        }

        if (Number(storyResult.rows[0].user_id) !== req.userId) {
            return res.status(403).json({
                success: false,
                message: 'Seul l’auteur peut consulter les spectateurs de cette story.'
            });
        }

        const resultat = await req.db.query(
            `SELECT v.viewer_id, v.viewed_at,
                    u.username, u.first_name, u.last_name,
                    u.profile_picture
             FROM story_views v
             JOIN users u ON u.id = v.viewer_id
             WHERE v.story_id = $1
             ORDER BY v.viewed_at DESC`,
            [storyId]
        );

        return res.json({
            success: true,
            story_id: storyId,
            views_count: resultat.rowCount,
            viewers: resultat.rows
        });
    } catch (e) {
        erreurServeur(res, e);
    }
});

module.exports = router;
