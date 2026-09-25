package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// executor is the subset of *sql.DB and *sql.Tx the repositories need. Taking
// it from the context is what allows a repository call to silently join an
// ongoing transaction.
type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type txContextKey struct{}

// TxManager implements the unit of work port.
type TxManager struct {
	db *sql.DB
}

func NewTxManager(db *sql.DB) *TxManager {
	return &TxManager{db: db}
}

// WithinTx runs fn inside a transaction, committing on success and rolling back
// on error or panic. Nested calls reuse the outermost transaction.
func (m *TxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txContextKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(context.WithValue(ctx, txContextKey{}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true
	return nil
}

// repository is embedded by the concrete repositories to share the executor
// lookup.
type repository struct {
	db *sql.DB
}

func (r repository) exec(ctx context.Context) executor {
	if tx, ok := ctx.Value(txContextKey{}).(*sql.Tx); ok {
		return tx
	}
	return r.db
}
