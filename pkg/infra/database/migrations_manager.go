package database

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

type Migration struct {
	ID   string
	Name string
	Up   func(db *gorm.DB) error
	Down func(db *gorm.DB) error
}

var (
	migrationsRegistry = make(map[string]Migration)
	migrationsOrder    = make([]string, 0)
)

// extractTimestampPrefix extracts the timestamp prefix from migration ID
// Expected format: "20240001_migration_name" -> returns 20240001 as int64
func extractTimestampPrefix(id string) int64 {
	parts := strings.Split(id, "_")
	if len(parts) == 0 {
		return 0
	}

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

	// Insert migration ID in chronological order based on timestamp prefix
	insertPos := len(migrationsOrder)
	newTimestamp := extractTimestampPrefix(m.ID)

	// Find the correct position to insert (maintain chronological order)
	for i, existingID := range migrationsOrder {
		existingTimestamp := extractTimestampPrefix(existingID)
		if newTimestamp < existingTimestamp {
			insertPos = i
			break
		}
	}

	// Insert at the correct position
	if insertPos == len(migrationsOrder) {
		migrationsOrder = append(migrationsOrder, m.ID)
	} else {
		migrationsOrder = append(migrationsOrder[:insertPos+1], migrationsOrder[insertPos:]...)
		migrationsOrder[insertPos] = m.ID
	}
}

type MigrationsManager struct {
	db *gorm.DB
}

func NewMigrationsManager(db *gorm.DB) *MigrationsManager {
	return &MigrationsManager{db: db}
}

func (m *MigrationsManager) ensureMigrationsTable() error {
	const createTableSQL = `
CREATE TABLE IF NOT EXISTS migration_version (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`
	return m.db.Exec(createTableSQL).Error
}

func (m *MigrationsManager) getAppliedMigrations() (map[string]struct{}, error) {
	type row struct{ ID string }
	var rows []row
	if err := m.db.Raw("SELECT id FROM migration_version").Scan(&rows).Error; err != nil {
		return nil, err
	}
	applied := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		applied[r.ID] = struct{}{}
	}
	return applied, nil
}

func (m *MigrationsManager) ApplyPending() error {
	if err := m.ensureMigrationsTable(); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	applied, err := m.getAppliedMigrations()
	if err != nil {
		return fmt.Errorf("load applied migrations: %w", err)
	}

	// No need to sort here anymore - migrations are already in chronological order from registration

	for _, id := range migrationsOrder {
		if _, ok := applied[id]; ok {
			continue
		}
		mig := migrationsRegistry[id]
		if mig.Up == nil {
			return fmt.Errorf("migration %s has no Up function", id)
		}
		// Execute the migration and the version insert in a single transaction to ensure atomicity
		err := m.db.Transaction(func(tx *gorm.DB) error {
			if err := mig.Up(tx); err != nil {
				return err
			}
			return tx.Exec("INSERT INTO migration_version (id, name, applied_at) VALUES (?, ?, ?)", mig.ID, mig.Name, time.Now()).Error
		})
		if err != nil {
			return fmt.Errorf("apply migration %s (%s): %w", mig.ID, mig.Name, err)
		}
	}
	return nil
}
