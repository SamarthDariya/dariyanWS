-- nache's own database (DESIGN.md decision 1): not a schema in dariyanws, a separate database, so
-- a query joining a cluster to an access key cannot be written at all.

CREATE TABLE IF NOT EXISTS clusters (
    -- From the verified capability that created the row, and from nowhere else (decision 13i).
    account_id  text        NOT NULL,
    name        text        NOT NULL,

    -- creating | active | deleting. A deleted cluster has no row.
    state       text        NOT NULL,

    -- What the reconciler last saw, as the proto's CacheNode list. Describe reads this rather
    -- than asking chala, so a Describe does not depend on the compute service being up.
    nodes       jsonb       NOT NULL DEFAULT '[]',

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (account_id, name),
    CHECK (state IN ('creating', 'active', 'deleting'))
);
