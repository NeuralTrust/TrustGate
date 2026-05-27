package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// WithTx runs fn inside a database transaction obtained from the connection
// pool. The transaction is committed when fn returns nil; otherwise it is
// rolled back. A panic inside fn is propagated after a best-effort rollback
// so the caller's defer chain stays intact.
//
// Repositories use WithTx to compose multiple writes into a single atomic
// unit:
//
//	err := database.WithTx(ctx, conn, func(tx pgx.Tx) error {
//	    if _, err := tx.Exec(ctx, "INSERT ..."); err != nil { return err }
//	    return tx.QueryRow(ctx, "...").Scan(&id)
//	})
func WithTx(ctx context.Context, conn *Connection, fn func(pgx.Tx) error) (err error) {
	if conn == nil || conn.Pool == nil {
		return errors.New("database: nil connection")
	}

	tx, err := conn.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				err = fmt.Errorf("%w (rollback failed: %v)", err, rbErr)
			}
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	if commitErr := tx.Commit(ctx); commitErr != nil {
		err = fmt.Errorf("commit tx: %w", commitErr)
		return err
	}
	return nil
}
