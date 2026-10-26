const jwt = require('jsonwebtoken');

let ioInstance = null;

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

        socket.emit('realtime:ready', {
            success: true,
            userId
        });

        console.log(`Socket JJM connecté : utilisateur ${userId}`);

        socket.on('disconnect', (reason) => {
            console.log(
                `Socket JJM déconnecté : utilisateur ${userId} (${reason})`
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
