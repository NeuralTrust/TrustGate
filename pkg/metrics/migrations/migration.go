// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package migrations holds the ordered schema history for the sensible store.
// Each change lives in its own migration_<id>_<name>.go file that self-registers
// via register in an init; All returns the full set ordered by ID.
package migrations

import "sort"

// VersionTableName is the bookkeeping table that records which migrations have
// been applied so a runner can skip them on the next start.
const VersionTableName = "migration_versions"

// VersionTableDDL creates VersionTableName. It is idempotent so a runner can
// execute it on every start before consulting the applied set.
const VersionTableDDL = `CREATE TABLE IF NOT EXISTS migration_versions (
    id         TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

// Migration is a driver-free unit of schema change: forward and rollback SQL
// kept as strings so the module stays dependency-light. The pgx-based runner
// that executes these lives in the consuming write path, not here.
type Migration struct {
	ID      string
	Name    string
	UpSQL   string
	DownSQL string
}

var registry []Migration

// register adds a migration to the set. A duplicate ID is a build-time
// programmer error, so it panics rather than silently shadowing.
func register(m Migration) {
	for _, existing := range registry {
		if existing.ID == m.ID {
			panic("migrations: duplicate migration ID " + m.ID)
		}
	}
	registry = append(registry, m)
}

// All returns every registered migration ordered by ID as a fresh slice, so
// callers cannot mutate the shared registry. Every statement is idempotent.
func All() []Migration {
	out := make([]Migration, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
