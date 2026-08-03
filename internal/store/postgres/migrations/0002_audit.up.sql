CREATE TABLE audit_log
(
    seq            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correlation_id TEXT        NOT NULL,
    time           TIMESTAMPTZ NOT NULL,
    action         TEXT        NOT NULL,
    principal_id   TEXT        NOT NULL DEFAULT '',
    success        BOOLEAN     NOT NULL,
    revision       TEXT        NOT NULL DEFAULT '',
    entry          JSONB       NOT NULL
);

CREATE INDEX idx_audit_time ON audit_log (time DESC);
CREATE INDEX idx_audit_correlation ON audit_log (correlation_id);
CREATE INDEX idx_audit_principal ON audit_log (principal_id);

CREATE TABLE audit_artifacts
(
    artifact_id    TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,          -- the lease.issue entry's id (= lease id)
    provider       TEXT NOT NULL,
    fingerprint    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_artifacts_correlation ON audit_artifacts (correlation_id);
CREATE INDEX idx_audit_artifacts_fingerprint ON audit_artifacts (fingerprint) WHERE fingerprint <> '';