package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*Auditor)(nil)

type Auditor struct {
	pool *pgxpool.Pool
}

func OpenAuditor(ctx context.Context, dsn string) (*Auditor, error) {
	pool, err := Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &Auditor{
		pool: pool,
	}, nil
}

func (a *Auditor) Close() error {
	a.pool.Close()
	return nil
}

func (a *Auditor) Log(ctx context.Context, entry core.AuditEntry) error {
	principalID := ""
	if entry.Principal != nil {
		principalID = entry.Principal.ID
	}

	artifacts := entry.Artifacts
	stored := entry
	stored.Artifacts = nil // we store artifacts separately.

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit tx: %w", err)
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		_ = tx.Rollback(ctx)
	}(tx, ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (correlation_id, time, action, principal_id, success, revision, entry)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		stored.ID, stored.Time, stored.Action, principalID,
		stored.Success, stored.Revision, stored,
	); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}

	for _, art := range artifacts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_artifacts (artifact_id, correlation_id, provider, fingerprint)
			VALUES ($1, $2, $3, $4)`,
			art.ArtifactID, stored.ID, art.Provider, art.Fingerprint,
		); err != nil {
			return fmt.Errorf("writing audit artifact %q: %w", art.ArtifactID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit tx: %w", err)
	}

	return nil
}

func (a *Auditor) Query(ctx context.Context, f core.AuditFilter) ([]core.AuditEntry, error) {
	var (
		conds []string
		args  []any
	)
	add := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if f.CorrelationID != "" {
		add("correlation_id", f.CorrelationID)
	}
	if f.Action != "" {
		add("action", f.Action)
	}
	if f.PrincipalID != "" {
		add("principal_id", f.PrincipalID)
	}
	if f.Success != nil {
		add("success", *f.Success)
	}
	if f.Fingerprint != "" {
		args = append(args, f.Fingerprint)
		conds = append(conds, fmt.Sprintf(
			"correlation_id IN (SELECT correlation_id FROM audit_artifacts WHERE fingerprint = $%d)", len(args)))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		conds = append(conds, fmt.Sprintf("time >= $%d", len(args)))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until)
		conds = append(conds, fmt.Sprintf("time <= $%d", len(args)))
	}

	query := "SELECT entry FROM audit_log"
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY time DESC"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := a.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit entries: %w", err)
	}
	defer rows.Close()

	var entries []core.AuditEntry
	for rows.Next() {
		var entry core.AuditEntry
		if err := rows.Scan(&entry); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		entries = append(entries, entry)
	}

	// re-attach the entries :)
	if len(entries) > 0 {
		ids := make([]string, len(entries))
		for i, e := range entries {
			ids[i] = e.ID
		}

		rows, err := a.pool.Query(ctx, `
			SELECT correlation_id, artifact_id, provider, fingerprint
			FROM audit_artifacts WHERE correlation_id = ANY($1)`, ids)
		if err != nil {
			return nil, fmt.Errorf("loading audit artifacts: %w", err)
		}
		defer rows.Close()

		byCorr := make(map[string][]core.ArtifactAudit)
		for rows.Next() {
			var corrID string
			var art core.ArtifactAudit
			if err := rows.Scan(&corrID, &art.ArtifactID, &art.Provider, &art.Fingerprint); err != nil {
				return nil, fmt.Errorf("scanning audit artifact: %w", err)
			}
			byCorr[corrID] = append(byCorr[corrID], art)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterating audit artifacts: %w", err)
		}
		for i := range entries {
			entries[i].Artifacts = byCorr[entries[i].ID]
		}
	}

	return entries, nil
}
