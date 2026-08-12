CREATE TABLE audit_log
(
    seq        BIGINT GENERATED ALWAYS AS IDENTITY,
    id         TEXT PRIMARY KEY,
    time       TIMESTAMPTZ NOT NULL,
    action     TEXT        NOT NULL,
    outcome    TEXT        NOT NULL,
    actor_id   TEXT        NOT NULL DEFAULT '',
    request_id TEXT        NOT NULL DEFAULT '',
    session_id TEXT        NOT NULL DEFAULT '',
    revision   TEXT        NOT NULL DEFAULT '',
    error      TEXT        NOT NULL DEFAULT '',
    entry      JSONB       NOT NULL
);

CREATE INDEX idx_audit_time ON audit_log (time DESC);
CREATE INDEX idx_audit_request ON audit_log (request_id);
CREATE INDEX idx_audit_session ON audit_log (session_id);
CREATE INDEX idx_audit_actor ON audit_log (actor_id);
CREATE INDEX idx_audit_action ON audit_log (action);

CREATE TABLE audit_artifacts
(
    artifact_id TEXT PRIMARY KEY,
    entry_id    TEXT NOT NULL REFERENCES audit_log (id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_artifacts_entry ON audit_artifacts (entry_id);
CREATE INDEX idx_audit_artifacts_fingerprint ON audit_artifacts (fingerprint) WHERE fingerprint <> '';