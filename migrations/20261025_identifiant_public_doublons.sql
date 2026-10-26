BEGIN;

-- Ajouter la colonne sans modifier les comptes existants.
ALTER TABLE users
ADD COLUMN IF NOT EXISTS account_code VARCHAR(20);

-- Attribuer un identifiant public aux comptes existants.
UPDATE users
SET account_code =
    'JJM-' || UPPER(
        SUBSTRING(
            MD5(RANDOM()::TEXT || CLOCK_TIMESTAMP()::TEXT || id::TEXT),
            1,
            10
        )
    )
WHERE account_code IS NULL;

-- Vérifier qu'aucun identifiant public n'est dupliqué.
DO $$
BEGIN
    IF EXISTS (
        SELECT account_code
        FROM users
        GROUP BY account_code
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'Migration annulée : identifiants publics dupliqués.';
    END IF;
END $$;

-- Garantir que chaque compte possède un identifiant public.
ALTER TABLE users
ALTER COLUMN account_code SET NOT NULL;

-- Ajouter une contrainte unique si elle n'existe pas déjà.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.users'::regclass
          AND conname = 'users_account_code_key'
    ) THEN
        ALTER TABLE users
        ADD CONSTRAINT users_account_code_key
        UNIQUE (account_code);
    END IF;
END $$;

-- Autoriser les doublons de pseudo, d'e-mail et de téléphone.
ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_username_key;

ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_email_key;

ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_phone_key;

COMMIT;
