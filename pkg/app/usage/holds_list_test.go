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

package usage

import (
	"context"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

type plainChecker struct{}

func (plainChecker) Exhausted(string) (domain.Reason, bool) { return domain.ReasonNone, false }

func TestEnforcementHoldsAListOnlyOnceOneIsComplete(t *testing.T) {
	t.Parallel()
	e := NewEnforcement()
	e.ApplySnapshot(domain.Snapshot{Exhausted: []domain.TenantState{exhausted(t, "a", 3)}})
	if e.HoldsList() {
		t.Fatal("a list with no as_of version counted as a list from Usage System")
	}
	e.ApplySnapshot(domain.Snapshot{AsOfVersion: 4})
	if !e.HoldsList() {
		t.Fatal("a complete list did not count")
	}
}

func TestStoreHoldsAListOnlyAfterAUsageSyncSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, cached := range [][]domain.TenantState{nil, {state(t, "a", true, 5)}} {
		store := NewStore(&memoryCache{stored: cached}, nil, time.Second)
		store.RestoreUntilReady(ctx, RestoreOptions{Interval: time.Millisecond, MaxBackoff: time.Millisecond})
		if !store.Ready() {
			t.Fatal("store not ready after the restore")
		}
		if store.HoldsList() {
			t.Fatalf("a store restored from the cache (%d states) counted as holding a list from Usage System", len(cached))
		}
		_ = store.ApplySnapshot(ctx, nil, 6)
		if !store.HoldsList() {
			t.Fatal("a UsageSync snapshot did not count")
		}
	}
}

func TestHoldsListIsFalseForACheckerThatCannotTell(t *testing.T) {
	t.Parallel()
	if HoldsList(plainChecker{}) || HoldsList(nil) {
		t.Fatal("a checker without HoldsList counted as holding a list")
	}
}
