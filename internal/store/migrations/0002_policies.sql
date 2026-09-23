-- Policies and their attachments (DESIGN.md decision 6: policy is defined and evaluated here).
--
-- Identity policies only. No groups, no role indirection, no resource policies — see the M3.1
-- commit for why. An attachment therefore binds a policy directly to a principal ARN.

CREATE TABLE policies (
    -- arn:dariya:iam:<region>:<account>:policy/<name>
    --
    -- Derived from the name rather than random, so a policy is addressable from a config file
    -- someone wrote by hand, and so the uniqueness constraint below is the same constraint as
    -- "one policy per name per account" rather than a second one that can disagree with it.
    policy_arn    TEXT     PRIMARY KEY,

    account_id    CHAR(12) NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    name          TEXT     NOT NULL,

    -- The document as protojson.
    --
    -- JSONB rather than a BYTEA of the binary encoding: this is the table someone reads during an
    -- incident at 3am, from psql, asking "what was this principal allowed to do?". Binary proto
    -- would be smaller and faster and completely opaque at exactly that moment. The cost is that
    -- protojson must round-trip faithfully, which the tests assert.
    document      JSONB    NOT NULL,

    created_at_ms BIGINT   NOT NULL,

    CONSTRAINT policies_name_unique UNIQUE (account_id, name)
);

CREATE TABLE policy_attachments (
    policy_arn     TEXT NOT NULL REFERENCES policies(policy_arn) ON DELETE CASCADE,
    principal_arn  TEXT NOT NULL,
    attached_at_ms BIGINT NOT NULL,

    PRIMARY KEY (policy_arn, principal_arn)
);

-- The hot-path query is "every policy attached to this principal", once per authorisation. It
-- must never be a scan.
CREATE INDEX policy_attachments_by_principal ON policy_attachments (principal_arn);
