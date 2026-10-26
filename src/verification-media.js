const TYPES_MEDIA = Object.freeze({
    'image/jpeg': 'image',
    'image/png': 'image',
    'image/webp': 'image',
    'image/gif': 'image',
    'video/mp4': 'video',
    'video/webm': 'video',
    'video/quicktime': 'video'
});

const TYPES_PHOTO = new Set([
    'image/jpeg',
    'image/png',
    'image/webp'
]);

async function verifierMedia(buffer, mimeDeclare, categorie) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
        return {
            valide: false,
            raison: 'Fichier vide ou invalide.'
        };
    }

    const estPhotoProfil = categorie === 'profil';
    const estStory = categorie === 'story';
    const estPublication = categorie === 'publication';

    if (!estPhotoProfil && !estStory && !estPublication) {
        return {
            valide: false,
            raison: 'Catégorie de média invalide.'
        };
    }

    const mimeAutorises = estPhotoProfil
        ? TYPES_PHOTO
        : new Set(Object.keys(TYPES_MEDIA));

    if (!mimeAutorises.has(mimeDeclare)) {
        return {
            valide: false,
            raison: 'Format déclaré non autorisé.'
        };
    }

    try {
        const { fileTypeFromBuffer } = await import('file-type');
        const detecte = await fileTypeFromBuffer(buffer);

        if (!detecte) {
            return {
                valide: false,
                raison: 'Type réel du fichier non reconnu.'
            };
        }

        if (detecte.mime !== mimeDeclare) {
            return {
                valide: false,
                raison: 'Le contenu ne correspond pas au format déclaré.'
            };
        }

        if (estPhotoProfil && TYPES_MEDIA[detecte.mime] !== 'image') {
            return {
                valide: false,
                raison: 'Une image est requise.'
            };
        }

        return {
            valide: true,
            mime: detecte.mime
        };
    } catch (erreur) {
        console.error(
            'Erreur de vérification du média :',
            erreur.message
        );

        return {
            valide: false,
            raison: 'Impossible de vérifier le fichier.'
        };
    }
}

module.exports = { verifierMedia };
