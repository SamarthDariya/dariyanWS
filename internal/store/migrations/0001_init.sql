-- Accounts and credentials: the only state dariyanWS owns (DESIGN.md decision 1).
--
-- Nothing service-specific may be added here. A table for queues or functions in this schema is the
-- central-registry design creeping back in through the side door.

CREATE TABLE accounts (
    -- CHAR(12) rather than a bigint: account ids are zero-padded identifiers that appear in ARNs and
    -- in storage key prefixes, never numbers that get arithmetic done to them. Storing them as an
    -- integer invites a round trip through int64 that silently drops the leading zeros.
    account_id    CHAR(12)    PRIMARY KEY,
    name          TEXT        NOT NULL,
    state         TEXT        NOT NULL,
    created_at_ms BIGINT      NOT NULL,

    CONSTRAINT accounts_id_digits CHECK (account_id ~ '^[0-9]{12}$')
);

CREATE TABLE access_keys (
    access_key_id TEXT        PRIMARY KEY,
    account_id    CHAR(12)    NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    principal_arn TEXT        NOT NULL,

    -- The secret, encrypted at rest (DESIGN.md decision 10).
    --
    -- NOT a hash. Verifying a signature means recomputing the HMAC, which needs the actual secret
    -- back — a one-way hash cannot do it. That is a password store, and this is a signing store.
    -- AES-256-GCM under a master key held by the front door; the nonce is per-row and never reused.
    secret_ciphertext BYTEA   NOT NULL,
    secret_nonce      BYTEA   NOT NULL,
    -- Which master key encrypted it, so the master key can be rotated with an overlap window.
    master_key_id     TEXT    NOT NULL,

    state         TEXT        NOT NULL,
    created_at_ms BIGINT      NOT NULL
);

-- Every lookup of a key is either by its id (the signing path, already the primary key) or by
-- account (the console listing). Nothing scans this table.
CREATE INDEX access_keys_by_account ON access_keys (account_id, created_at_ms DESC);

-- Idempotency for mutating control-plane calls.
--
-- Scoped by (operation, client_token) rather than client_token alone: a client that reuses one token
-- across two different operations means two different intents, and collapsing them would silently
-- return a CreateAccount result to a CreateAccessKey call.
CREATE TABLE idempotency (
    operation     TEXT        NOT NULL,
    client_token  TEXT        NOT NULL,
    -- The identifier the first call returned, replayed verbatim on a retry.
    result_id     TEXT        NOT NULL,
    created_at_ms BIGINT      NOT NULL,

    PRIMARY KEY (operation, client_token)
);

-- Retries arrive within seconds; tokens are not kept forever. A sweeper deletes rows past the
-- window, and this index is what makes that cheap.
CREATE INDEX idempotency_by_age ON idempotency (created_at_ms);
