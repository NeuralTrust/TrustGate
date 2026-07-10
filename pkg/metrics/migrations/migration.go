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

package migrations

import "sort"

const VersionTableName = "migration_versions"

const VersionTableDDL = `CREATE TABLE IF NOT EXISTS migration_versions (
    id         TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

type Migration struct {
	ID      string
	Name    string
	UpSQL   string
	DownSQL string
}

var registry []Migration

func register(m Migration) {
	for _, existing := range registry {
		if existing.ID == m.ID {
			panic("migrations: duplicate migration ID " + m.ID)
		}
	}
	registry = append(registry, m)
}

func All() []Migration {
	out := make([]Migration, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
