-- WebAuthn / passkeys.
--
-- Each row is one registered authenticator credential. `passkey_json` is the
-- serde-serialized webauthn-rs `Passkey` (it carries the public key, the
-- signature counter, and the transports); we never store a private key — the
-- private half never leaves the user's device. `credential_id` is the base64url
-- of the credential's id, kept as its own column so registration can pass the
-- existing ids as `exclude_credentials` and login can look a credential up.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id  TEXT NOT NULL UNIQUE,
    passkey_json   TEXT NOT NULL,
    nickname       TEXT,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials(user_id);

-- Stable per-user handle (a UUID) used as the WebAuthn user id. Required for
-- discoverable (usernameless / passwordless) login, where the assertion carries
-- this handle and we resolve it back to a local user. Minted on first passkey
-- registration; NULL for users who have never enrolled one.
ALTER TABLE users ADD COLUMN webauthn_user_handle TEXT;
