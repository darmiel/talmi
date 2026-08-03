package postgres

import (
	"context"
	"fmt"
	"strings"

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
	_, err := a.pool.Exec(ctx, `
		INSERT INTO audit_log
			(correlation_id, time, action, principal_id, success, revision, entry)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.ID, entry.Time, entry.Action, principalID,
		entry.Success, entry.Revision, entry,
	)
	if err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
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

	return entries, nil
}
