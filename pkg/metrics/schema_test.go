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

package metrics

import (
	"strings"
	"testing"
)

func TestMigrationsOrderedUniqueAndTargetTable(t *testing.T) {
	migs := Migrations()
	if len(migs) == 0 {
		t.Fatal("expected at least one migration")
	}
	seen := make(map[string]bool, len(migs))
	for i, m := range migs {
		if m.ID == "" {
			t.Errorf("migration %d has empty ID", i)
		}
		if seen[m.ID] {
			t.Errorf("duplicate migration ID %q", m.ID)
		}
		seen[m.ID] = true
		if strings.TrimSpace(m.UpSQL) == "" {
			t.Errorf("migration %q has empty UpSQL", m.ID)
		}
	}
	if !strings.Contains(migs[0].UpSQL, TableName) {
		t.Errorf("first migration UpSQL does not reference table %q", TableName)
	}
}

func TestMigrationsReturnsIndependentSlices(t *testing.T) {
	first := Migrations()
	first[0].UpSQL = "mutated"
	if Migrations()[0].UpSQL == "mutated" {
		t.Error("Migrations() must return a fresh slice, not shared mutable state")
	}
}

func TestInsertColumnsSubsetOfReadColumns(t *testing.T) {
	read := make(map[string]bool)
	for _, c := range ReadColumns() {
		read[c] = true
	}
	for _, c := range InsertColumns() {
		if !read[c] {
			t.Errorf("insert column %q missing from read allow-list", c)
		}
	}
}

func TestReadColumnsIncludeCreatedAt(t *testing.T) {
	for _, c := range ReadColumns() {
		if c == ColumnCreatedAt {
			return
		}
	}
	t.Errorf("read columns must include %q", ColumnCreatedAt)
}

func TestInsertColumnsExcludeDefaultedCreatedAt(t *testing.T) {
	for _, c := range InsertColumns() {
		if c == ColumnCreatedAt {
			t.Errorf("insert columns must not include database-defaulted %q", ColumnCreatedAt)
		}
	}
}
