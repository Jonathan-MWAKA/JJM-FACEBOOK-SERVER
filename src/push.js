const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');

let firebaseApp = null;

function obtenirFirebase() {
    if (firebaseApp) return firebaseApp;

    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY
        ?.replace(/\\n/g, '\n');

    if (!projectId || !clientEmail || !privateKey) {
        return null;
    }

    firebaseApp = getApps().length
        ? getApps()[0]
        : initializeApp({
            credential: cert({
                projectId,
                clientEmail,
                privateKey
            })
        });

    return firebaseApp;
}

async function envoyerNotificationUtilisateur(db, userId, donnees = {}) {
    try {
        const app = obtenirFirebase();

        if (!app) {
            return { envoyees: 0, raison: 'firebase_non_configure' };
        }

        const resultat = await db.query(
            'SELECT token FROM fcm_tokens WHERE user_id = $1',
            [userId]
        );

        const tokens = [...new Set(
            resultat.rows.map(row => row.token).filter(Boolean)
        )];

        if (!tokens.length) {
            return { envoyees: 0, raison: 'aucun_jeton' };
        }

        const data = {};

        for (const [cle, valeur] of Object.entries(donnees)) {
            if (valeur !== null && valeur !== undefined) {
                data[cle] = String(valeur);
            }
        }

        const reponse = await getMessaging(app).sendEachForMulticast({
            tokens,
            data: {
                title: String(donnees.title || 'JJM FACEBOOK'),
                body: String(donnees.body || 'Tu as une nouvelle notification.'),
                ...data
            },
            android: {
                priority: 'high'
            }
        });

        const invalides = [];

        reponse.responses.forEach((r, index) => {
            if (
                !r.success &&
                (
                    r.error?.code === 'messaging/registration-token-not-registered' ||
                    r.error?.code === 'messaging/invalid-registration-token'
                )
            ) {
                invalides.push(tokens[index]);
            }
        });

        if (invalides.length) {
            await db.query(
                'DELETE FROM fcm_tokens WHERE token = ANY($1::text[])',
                [invalides]
            );
        }

        return {
            envoyees: reponse.successCount,
            echecs: reponse.failureCount
        };
    } catch (erreur) {
        console.error('Erreur notification Firebase :', erreur.message);
        return { envoyees: 0, raison: 'erreur_envoi' };
    }
}

module.exports = { envoyerNotificationUtilisateur };
