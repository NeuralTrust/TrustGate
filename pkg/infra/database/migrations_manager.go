package database

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration is a versioned schema change. ID must start with a Unix timestamp prefix.
type Migration struct {
	ID   string
	Name string
	Up   func(ctx context.Context, tx pgx.Tx) error
	Down func(ctx context.Context, tx pgx.Tx) error
}

var (
	migrationsRegistry = make(map[string]Migration)
	migrationsOrder    = make([]string, 0)
)

func extractTimestampPrefix(id string) int64 {
	parts := strings.SplitN(id, "_", 2)
	timestamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	return timestamp
}

func RegisterMigration(m Migration) {
	if _, exists := migrationsRegistry[m.ID]; exists {
		panic(fmt.Sprintf("migration with ID %s already registered", m.ID))
	}
	migrationsRegistry[m.ID] = m

	insertPos := len(migrationsOrder)
	newTimestamp := extractTimestampPrefix(m.ID)
	for i, existingID := range migrationsOrder {
		existingTimestamp := extractTimestampPrefix(existingID)
		if newTimestamp < existingTimestamp {
			insertPos = i
			break
		}
	}
	if insertPos == len(migrationsOrder) {
		migrationsOrder = append(migrationsOrder, m.ID)
	} else {
		migrationsOrder = append(migrationsOrder[:insertPos+1], migrationsOrder[insertPos:]...)
		migrationsOrder[insertPos] = m.ID
	}
}

// MigrationsManager applies registered migrations against a pgx pool.
type MigrationsManager struct {
	pool *pgxpool.Pool
}

func NewMigrationsManager(pool *pgxpool.Pool) *MigrationsManager {
	return &MigrationsManager{pool: pool}
}

func (m *MigrationsManager) ensureMigrationsTable(ctx context.Context) error {
	const createTableSQL = `
		CREATE TABLE IF NOT EXISTS public.migration_version (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`
	_, err := m.pool.Exec(ctx, createTableSQL)
	return err
}

func (m *MigrationsManager) getAppliedMigrations(ctx context.Context) (map[string]struct{}, error) {
	const query = `SELECT id FROM public.migration_version`
	rows, err := m.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		applied[id] = struct{}{}
	}
	return applied, rows.Err()
}

func (m *MigrationsManager) ApplyPending(ctx context.Context) error {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("load applied migrations: %w", err)
	}

	for _, id := range migrationsOrder {
		if _, ok := applied[id]; ok {
			continue
		}
		mig := migrationsRegistry[id]
		if mig.Up == nil {
			return fmt.Errorf("migration %s has no Up function", id)
		}

		err := func() error {
			tx, err := m.pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()

			if err := mig.Up(ctx, tx); err != nil {
				return err
			}
			const insertQuery = `
				INSERT INTO public.migration_version (id, name, applied_at)
				VALUES ($1, $2, $3)`
			if _, err := tx.Exec(ctx, insertQuery, mig.ID, mig.Name, time.Now()); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if err != nil {
			return fmt.Errorf("apply migration %s (%s): %w", mig.ID, mig.Name, err)
		}
	}
	return nil
}

func RegisteredIDs() []string {
	out := make([]string, len(migrationsOrder))
	copy(out, migrationsOrder)
	return out
}
