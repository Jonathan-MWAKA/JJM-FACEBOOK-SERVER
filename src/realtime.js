const jwt = require('jsonwebtoken');
const { getPool } = require('./db');

let ioInstance = null;
const appelsActifs = new Map();
const deconnexionsEnAttente = new Map();
const DELAI_GRACE_APPEL = 25000;

function identifiantValide(value) {
    const id = Number(value);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function envoyerErreur(socket, message) {
    socket.emit('call:error', { success: false, message });
}

async function sontAmis(idA, idB) {
    const pool = getPool();
    if (!pool) return false;

    const resultat = await pool.query(
        `SELECT 1
         FROM friendships
         WHERE status = 'accepted'
           AND (
             (requester_id = $1 AND receiver_id = $2)
             OR
             (requester_id = $2 AND receiver_id = $1)
           )
         LIMIT 1`,
        [idA, idB]
    );

    return resultat.rowCount > 0;
}

function initialiserSocketIO(io) {
    ioInstance = io;

    io.use((socket, next) => {
        const secret = process.env.JWT_SECRET;

        if (!secret || secret.length < 32) {
            return next(new Error('Authentification indisponible.'));
        }

        const token = socket.handshake.auth?.token;

        if (typeof token !== 'string' || !token) {
            return next(new Error('Authentification requise.'));
        }

        try {
            const jeton = jwt.verify(token, secret, {
                issuer: 'jjm-facebook'
            });

            const userId = Number(jeton.sub);

            if (!Number.isSafeInteger(userId) || userId <= 0) {
                return next(new Error('Session invalide.'));
            }

            socket.data.userId = userId;
            next();
        } catch {
            next(new Error('Session expirée ou invalide.'));
        }
    });

    io.on('connection', (socket) => {
        const userId = socket.data.userId;
        socket.join(`user:${userId}`);

        // Une reconnexion dans le délai de grâce annule la fin d'appel.
        const deconnexionPrecedente = deconnexionsEnAttente.get(userId);
        if (deconnexionPrecedente) {
            clearTimeout(deconnexionPrecedente);
            deconnexionsEnAttente.delete(userId);
            console.log(`Socket JJM reconnecté : utilisateur ${userId}`);
        }

        socket.emit('realtime:ready', {
            success: true,
            userId
        });

        console.log(`Socket JJM connecté : utilisateur ${userId}`);

        socket.on('call:request', async (data = {}, callback) => {
            const repondre = typeof callback === 'function'
                ? callback
                : () => {};

            try {
                const cible = identifiantValide(data.toUserId);
                const callId = typeof data.callId === 'string'
                    ? data.callId
                    : '';
                const type = data.type === 'video' ? 'video' : 'audio';

                if (!cible || cible === userId ||
                    !/^[a-zA-Z0-9_-]{8,100}$/.test(callId)) {
                    return repondre({
                        success: false,
                        message: 'Demande d’appel invalide.'
                    });
                }

                if (!await sontAmis(userId, cible)) {
                    return repondre({
                        success: false,
                        message: 'Vous devez être amis pour vous appeler.'
                    });
                }

                const salleCible = io.sockets.adapter.rooms.get(`user:${cible}`);

                if (!salleCible || salleCible.size === 0) {
                    return repondre({
                        success: false,
                        message: 'Cet utilisateur n’est pas connecté actuellement.'
                    });
                }


                if (appelsActifs.has(callId)) {
                    return repondre({
                        success: false,
                        message: 'Identifiant d’appel déjà utilisé.'
                    });
                }

                for (const appel of appelsActifs.values()) {
                    if (
                        appel.callerId === userId ||
                        appel.receiverId === userId ||
                        appel.callerId === cible ||
                        appel.receiverId === cible
                    ) {
                        return repondre({
                            success: false,
                            message: 'Un utilisateur est déjà en appel.'
                        });
                    }
                }

                appelsActifs.set(callId, {
                    callerId: userId,
                    receiverId: cible,
                    type
                });

                io.to(`user:${cible}`).emit('call:incoming', {
                    callId,
                    fromUserId: userId,
                    type
                });

                repondre({ success: true, callId });
            } catch (error) {
                console.error('Erreur call:request :', error.message);
                repondre({
                    success: false,
                    message: 'Impossible de lancer cet appel.'
                });
            }
        });

        const evenementsRelais = [
            'call:accept',
            'call:reject',
            'call:offer',
            'call:answer',
            'call:ice'
        ];

        for (const evenement of evenementsRelais) {
            socket.on(evenement, (data = {}) => {
                const callId = typeof data.callId === 'string'
                    ? data.callId
                    : '';
                const appel = appelsActifs.get(callId);

                if (!appel) {
                    return envoyerErreur(socket, 'Appel introuvable ou terminé.');
                }

                const estAppelant = appel.callerId === userId;
                const estDestinataire = appel.receiverId === userId;

                if (!estAppelant && !estDestinataire) {
                    return envoyerErreur(socket, 'Accès à cet appel refusé.');
                }

                const cible = estAppelant
                    ? appel.receiverId
                    : appel.callerId;

                if (
                    evenement === 'call:offer' &&
                    (!estAppelant || !data.sdp)
                ) return envoyerErreur(socket, 'Offre d’appel invalide.');

                if (
                    evenement === 'call:answer' &&
                    (!estDestinataire || !data.sdp)
                ) return envoyerErreur(socket, 'Réponse d’appel invalide.');

                if (
                    evenement === 'call:ice' &&
                    (!data.candidate ||
                     typeof data.candidate !== 'object')
                ) return envoyerErreur(socket, 'Candidat réseau invalide.');

                if (evenement === 'call:reject') {
                    appelsActifs.delete(callId);
                }

                io.to(`user:${cible}`).emit(evenement, {
                    callId,
                    fromUserId: userId,
                    ...(evenement === 'call:offer' ||
                       evenement === 'call:answer'
                        ? { sdp: data.sdp }
                        : {}),
                    ...(evenement === 'call:ice'
                        ? { candidate: data.candidate }
                        : {})
                });
            });
        }

        socket.on('call:end', (data = {}) => {
            const callId = typeof data.callId === 'string'
                ? data.callId
                : '';
            const appel = appelsActifs.get(callId);

            if (!appel) return;

            if (
                appel.callerId !== userId &&
                appel.receiverId !== userId
            ) {
                return envoyerErreur(socket, 'Accès à cet appel refusé.');
            }

            appelsActifs.delete(callId);

            const cible = appel.callerId === userId
                ? appel.receiverId
                : appel.callerId;

            io.to(`user:${cible}`).emit('call:end', {
                callId,
                fromUserId: userId
            });
        });

        socket.on('disconnect', (reason) => {
            const salleUtilisateur =
                io.sockets.adapter.rooms.get(`user:${userId}`);

            if (salleUtilisateur && salleUtilisateur.size > 0) {
                console.log(
                    `Socket déconnecté, autre connexion active : utilisateur ${userId}`
                );
                return;
            }

            const ancienDelai = deconnexionsEnAttente.get(userId);
            if (ancienDelai) {
                clearTimeout(ancienDelai);
            }

            const temporisateur = setTimeout(() => {
                if (deconnexionsEnAttente.get(userId) !== temporisateur) {
                    return;
                }

                deconnexionsEnAttente.delete(userId);

                const salle = io.sockets.adapter.rooms.get(`user:${userId}`);
                if (salle && salle.size > 0) return;

                for (const [callId, appel] of appelsActifs.entries()) {
                    if (
                        appel.callerId === userId ||
                        appel.receiverId === userId
                    ) {
                        appelsActifs.delete(callId);

                        const cible = appel.callerId === userId
                            ? appel.receiverId
                            : appel.callerId;

                        io.to(`user:${cible}`).emit('call:end', {
                            callId,
                            fromUserId: userId,
                            reason: 'disconnected'
                        });
                    }
                }

                console.log(
                    `Appels terminés après délai de grâce : utilisateur ${userId}`
                );
            }, DELAI_GRACE_APPEL);

            deconnexionsEnAttente.set(userId, temporisateur);

            console.log(
                `Socket déconnecté : utilisateur ${userId} (${reason}). `
                + `Délai : ${DELAI_GRACE_APPEL / 1000}s.`
            );
        });
    });

    return io;
}

function notifierUtilisateur(userId, evenement, donnees) {
    if (!ioInstance) return false;

    ioInstance.to(`user:${Number(userId)}`).emit(evenement, donnees);
    return true;
}

module.exports = {
    initialiserSocketIO,
    notifierUtilisateur
};
