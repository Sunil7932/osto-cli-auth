-- Append-only audit trail. Counters on the users row get reset, this does not,
-- so a lockout can still be explained after the fact.
CREATE TABLE auth_events (
    id         BIGSERIAL PRIMARY KEY,
    -- NULL when the attempt named an account that does not exist.
    user_id    BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    username   TEXT        NOT NULL DEFAULT '',
    event_type TEXT        NOT NULL,
    detail     TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX auth_events_user_id_created_at_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_username_created_at_idx ON auth_events (username, created_at DESC);
