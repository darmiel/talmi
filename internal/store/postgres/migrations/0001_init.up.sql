CREATE TABLE leases
(
    id                     TEXT PRIMARY KEY,
    principal_id           TEXT        NOT NULL,
    issuer                 TEXT        NOT NULL,
    policy_names           TEXT[]      NOT NULL DEFAULT '{}',
    policy_revision        TEXT        NOT NULL DEFAULT '',
    created_at             TIMESTAMPTZ NOT NULL,
    revocation_secret_hash TEXT        NOT NULL DEFAULT ''
);

-- lookup by revocation secret; partial so empty hashes aren't indexed
CREATE INDEX idx_leases_revocation_hash
    ON leases (revocation_secret_hash)
    WHERE revocation_secret_hash <> '';

CREATE TABLE lease_artifacts
(
    lease_id      TEXT        NOT NULL REFERENCES leases (id) ON DELETE CASCADE,
    idx           INT         NOT NULL,
    provider      TEXT        NOT NULL,
    realm         TEXT        NOT NULL,
    covers        JSONB       NOT NULL,
    fingerprint   TEXT        NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ NOT NULL,
    revocable     BOOLEAN     NOT NULL DEFAULT false,
    revoked       BOOLEAN     NOT NULL DEFAULT false,
    revocation_id TEXT        NOT NULL DEFAULT '',
    metadata      JSONB       NOT NULL DEFAULT '{}',
    PRIMARY KEY (lease_id, idx)
);

-- supports ListActive / DeleteExpired scans over live artifacts
CREATE INDEX idx_artifacts_active
    ON lease_artifacts (expires_at)
    WHERE revoked = false;