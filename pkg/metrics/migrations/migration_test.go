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

import (
	"sort"
	"strings"
	"testing"
)

func TestAllRegisteredMigrationsAreOrderedAndUnique(t *testing.T) {
	migs := All()
	if len(migs) == 0 {
		t.Fatal("expected at least one registered migration")
	}
	seen := make(map[string]bool, len(migs))
	ids := make([]string, 0, len(migs))
	for i, m := range migs {
		if m.ID == "" {
			t.Errorf("migration %d has empty ID", i)
		}
		if m.Name == "" {
			t.Errorf("migration %q has empty name", m.ID)
		}
		if strings.TrimSpace(m.UpSQL) == "" {
			t.Errorf("migration %q has empty UpSQL", m.ID)
		}
		if seen[m.ID] {
			t.Errorf("duplicate migration ID %q", m.ID)
		}
		seen[m.ID] = true
		ids = append(ids, m.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("migrations are not ordered by ID: %v", ids)
	}
}

func TestAllReturnsIndependentSlices(t *testing.T) {
	first := All()
	first[0].UpSQL = "mutated"
	if All()[0].UpSQL == "mutated" {
		t.Error("All must return a fresh slice, not shared mutable state")
	}
}

func TestRegisterPanicsOnDuplicateID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected register to panic on duplicate ID")
		}
	}()
	register(Migration{ID: "0001", Name: "dup", UpSQL: "SELECT 1;"})
}

func TestVersionTableDDLTargetsVersionTable(t *testing.T) {
	if !strings.Contains(VersionTableDDL, VersionTableName) {
		t.Errorf("version DDL does not reference %q", VersionTableName)
	}
}
