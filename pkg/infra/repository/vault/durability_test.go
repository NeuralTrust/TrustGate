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

package vault

import (
	"strings"
	"testing"
)

// The vault's Redis holds durable OAuth state; the startup check must flag a
// cache-tuned instance (eviction on, persistence off) and stay quiet on a safe
// one — and on managed offerings where the settings are unreadable.
func TestVolatilityProblems(t *testing.T) {
	t.Parallel()

	if got := volatilityProblems("noeviction", "aof_enabled:1", "", true); len(got) != 0 {
		t.Fatalf("safe config flagged: %v", got)
	}
	// Memorystore's default: volatile-lru only evicts keys with a TTL, which
	// the vault's keys never carry — not a problem.
	if got := volatilityProblems("volatile-lru", "aof_enabled:1", "", true); len(got) != 0 {
		t.Fatalf("volatile-lru flagged despite TTL-less vault keys: %v", got)
	}
	// Managed Redis (CONFIG blocked, INFO unreadable): nothing to report.
	if got := volatilityProblems("", "", "", false); len(got) != 0 {
		t.Fatalf("unreadable config must stay quiet, got %v", got)
	}

	got := volatilityProblems("allkeys-lru", "aof_enabled:0", "", true)
	if len(got) != 2 {
		t.Fatalf("problems = %v, want eviction + no-persistence", got)
	}
	if !strings.Contains(got[0], "allkeys-lru") || !strings.Contains(got[1], "restart wipes") {
		t.Fatalf("problems = %v", got)
	}

	// RDB snapshots alone count as persistence.
	if got := volatilityProblems("noeviction", "aof_enabled:0", "3600 1 300 100", true); len(got) != 0 {
		t.Fatalf("RDB-only persistence flagged: %v", got)
	}
}
