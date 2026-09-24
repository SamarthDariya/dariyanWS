-- Console sessions (DESIGN.md decision 12).
--
-- Server-side rather than a self-contained signed token, for one reason: logout has to work.
-- A stateless session cannot be revoked before it expires, and "sign out" that leaves a working
-- credential in the browser for another twelve hours is a lie told to the person clicking it.
-- The cost is a database read on every console request, which is why it gets the same cache
-- treatment everything else on the hot path got.

CREATE TABLE sessions (
    -- The SHA-256 of the session token, never the token.
    --
    -- Hashed, unlike an access key secret, and the contrast is the point. Decision 10 could not
    -- hash a signing secret because verifying a signature means recomputing an HMAC and needing
    -- the secret back. A session token is checked by equality, so the server never needs the
    -- original — which makes a hash both possible and correct, and a stolen database dump
    -- useless for impersonation.
    token_sha256  BYTEA    PRIMARY KEY,

    account_id    CHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    principal_arn TEXT     NOT NULL,

    -- Echoed back at sign-in and required in a header on every mutating request. SameSite is the
    -- primary CSRF defence; this is the belt to its braces, and it is stored so that a stolen
    -- cookie alone is not enough to write.
    csrf_token    TEXT     NOT NULL,

    created_at_ms BIGINT   NOT NULL,
    expires_at_ms BIGINT   NOT NULL
);

-- Sweeping expired sessions, and showing a person their active ones later.
CREATE INDEX sessions_by_account ON sessions (account_id, expires_at_ms DESC);
CREATE INDEX sessions_by_expiry ON sessions (expires_at_ms);
