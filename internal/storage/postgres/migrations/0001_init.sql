-- Accounts and their security state.
CREATE TABLE users (
    id                    BIGSERIAL PRIMARY KEY,
    -- Stored already normalised to lower case by the application layer.
    username              TEXT        NOT NULL,
    password_hash         TEXT        NOT NULL,
    -- AES-256-GCM ciphertext of the base32 TOTP secret, empty when no
    -- enrollment exists.
    totp_secret           TEXT        NOT NULL DEFAULT '',
    totp_enabled          BOOLEAN     NOT NULL DEFAULT FALSE,
    totp_confirmed_at     TIMESTAMPTZ,
    failed_login_attempts INTEGER     NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_username_key UNIQUE (username),
    CONSTRAINT users_username_length CHECK (char_length(username) BETWEEN 3 AND 32),
    CONSTRAINT users_failed_attempts_non_negative CHECK (failed_login_attempts >= 0),
    -- A confirmed enrollment must keep its secret around.
    CONSTRAINT users_totp_secret_present CHECK (NOT totp_enabled OR totp_secret <> '')
);

-- Login sessions. Only the SHA-256 hash of the token is persisted.
CREATE TABLE sessions (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash          TEXT        NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    -- Sliding deadline, pushed forward on every authenticated command.
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    -- Hard ceiling fixed at login time.
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    client_info         TEXT        NOT NULL DEFAULT '',

    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_live_idx ON sessions (idle_expires_at) WHERE revoked_at IS NULL;
