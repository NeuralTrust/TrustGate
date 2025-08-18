package database

import (
	"fmt"
	"sort"
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

func RegisterMigration(m Migration) {
	if _, exists := migrationsRegistry[m.ID]; exists {
		panic(fmt.Sprintf("migration with ID %s already registered", m.ID))
	}
	migrationsRegistry[m.ID] = m
	migrationsOrder = append(migrationsOrder, m.ID)
}

type MigrationsManager struct {
	db *gorm.DB
}

func NewMigrationsManager(db *gorm.DB) *MigrationsManager {
	return &MigrationsManager{db: db}
}

func (m *MigrationsManager) ensureMigrationsTable() error {
	const createTableSQL = `
CREATE TABLE IF NOT EXISTS public.migration_version (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`
	return m.db.Exec(createTableSQL).Error
}

func (m *MigrationsManager) getAppliedMigrations() (map[string]struct{}, error) {
	type row struct{ ID string }
	var rows []row
	if err := m.db.Raw("SELECT id FROM public.migration_version").Scan(&rows).Error; err != nil {
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

	sort.Slice(migrationsOrder, func(i, j int) bool { return migrationsOrder[i] < migrationsOrder[j] })

	for _, id := range migrationsOrder {
		if _, ok := applied[id]; ok {
			continue
		}
		mig := migrationsRegistry[id]
		if mig.Up == nil {
			return fmt.Errorf("migration %s has no Up function", id)
		}
		if err := mig.Up(m.db); err != nil {
			return fmt.Errorf("apply migration %s (%s): %w", mig.ID, mig.Name, err)
		}
		if err := m.db.Exec("INSERT INTO public.migration_version (id, name, applied_at) VALUES (?, ?, ?)", mig.ID, mig.Name, time.Now()).Error; err != nil {
			return fmt.Errorf("record migration %s: %w", mig.ID, err)
		}
	}
	return nil
}
