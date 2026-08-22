package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*Auditor)(nil)

type Auditor struct {
	pool *pgxpool.Pool
}

func OpenAuditor(ctx context.Context, dsn string, connectTimeout time.Duration) (*Auditor, error) {
	pool, err := Connect(ctx, dsn, connectTimeout)
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

func (a *Auditor) Log(ctx context.Context, event core.Event) error {
	actorID := ""
	if event.Actor != nil {
		actorID = event.Actor.ID
	}

	artifacts := event.Artifacts
	stored := event
	stored.Artifacts = nil // we store artifacts separately.

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit tx: %w", err)
	}

	defer func(tx pgx.Tx, ctx context.Context) {
		_ = tx.Rollback(ctx)
	}(tx, ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (id, time, action, outcome, actor_id, request_id, session_id, node_id, revision, error, entry)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		stored.ID, stored.Time, stored.Action, stored.Outcome, actorID,
		stored.RequestID, stored.SessionID, stored.NodeID, stored.Revision, stored.Error, stored,
	); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}

	for _, art := range artifacts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_artifacts (artifact_id, entry_id, provider, fingerprint)
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

func (a *Auditor) Query(ctx context.Context, f core.AuditFilter) ([]core.Event, error) {
	// can we make this better :(
	conds, args := auditWhere(f)

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

	var events []core.Event
	for rows.Next() {
		var event core.Event
		if err := rows.Scan(&event); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit entries: %w", err)
	}

	// re-attach artifacts by entry id
	if len(events) > 0 {
		ids := make([]string, len(events))
		for i, e := range events {
			ids[i] = e.ID
		}

		artRows, err := a.pool.Query(ctx, `
			SELECT entry_id, artifact_id, provider, fingerprint
			FROM audit_artifacts WHERE entry_id = ANY($1)`, ids)
		if err != nil {
			return nil, fmt.Errorf("loading audit artifacts: %w", err)
		}
		defer artRows.Close()

		byEntry := make(map[string][]core.ArtifactAudit)
		for artRows.Next() {
			var entryID string
			var art core.ArtifactAudit
			if err := artRows.Scan(&entryID, &art.ArtifactID, &art.Provider, &art.Fingerprint); err != nil {
				return nil, fmt.Errorf("scanning audit artifact: %w", err)
			}
			byEntry[entryID] = append(byEntry[entryID], art)
		}
		if err := artRows.Err(); err != nil {
			return nil, fmt.Errorf("iterating audit artifacts: %w", err)
		}
		for i := range events {
			events[i].Artifacts = byEntry[events[i].ID]
		}
	}

	return events, nil
}

func (a *Auditor) Prune(ctx context.Context, before time.Time) (int, error) {
	tag, err := a.pool.Exec(ctx, `DELETE FROM audit_log WHERE time < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("pruning audit entries: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func auditWhere(f core.AuditFilter) (conds []string, args []any) {
	add := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if f.ID != "" {
		add("id", f.ID)
	}
	if f.Action != "" {
		add("action", f.Action)
	}
	if f.Outcome != "" {
		add("outcome", f.Outcome)
	}
	if f.ActorID != "" {
		add("actor_id", f.ActorID)
	}
	if f.RequestID != "" {
		add("request_id", f.RequestID)
	}
	if f.SessionID != "" {
		add("session_id", f.SessionID)
	}
	if f.NodeID != "" {
		add("node_id", f.NodeID)
	}
	if f.Fingerprint != "" {
		args = append(args, f.Fingerprint)
		conds = append(conds, fmt.Sprintf(
			"id IN (SELECT entry_id FROM audit_artifacts WHERE fingerprint = $%d)", len(args),
		))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		conds = append(conds, fmt.Sprintf("time >= $%d", len(args)))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until)
		conds = append(conds, fmt.Sprintf("time <= $%d", len(args)))
	}
	return conds, args
}
