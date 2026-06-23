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
	"strings"
	"testing"
)

func TestRoleRegistryCascadeSwitchesRegistryFkToCascade(t *testing.T) {
	t.Parallel()

	for _, fragment := range []string{
		"ALTER TABLE role_registry DROP CONSTRAINT IF EXISTS role_registry_registry_id_fkey",
		"FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE CASCADE",
	} {
		if !strings.Contains(roleRegistryCascadeUpDDL, fragment) {
			t.Fatalf("up DDL missing %q", fragment)
		}
	}
	if !strings.Contains(roleRegistryCascadeDownDDL, "ON DELETE RESTRICT") {
		t.Fatal("down DDL must restore ON DELETE RESTRICT")
	}
}
