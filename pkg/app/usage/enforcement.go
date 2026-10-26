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
	"maps"
	"sync"
	"sync/atomic"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

//go:generate mockery --name=ExhaustionChecker --dir=. --output=./mocks --filename=exhaustion_checker_mock.go --case=underscore --with-expecter

// ExhaustionChecker tells the request path whether a tenant must be blocked.
type ExhaustionChecker interface {
	// Exhausted reports whether tenantID is exhausted and why.
	Exhausted(tenantID string) (domain.Reason, bool)
}

// ListHolder is implemented by the exhaustion checkers that can tell whether
// they hold a usage list from Usage System.
type ListHolder interface {
	HoldsList() bool
}

// HoldsList reports whether checker holds a usage list from Usage System. A
// checker that cannot tell holds none.
func HoldsList(checker ExhaustionChecker) bool {
	holder, ok := checker.(ListHolder)
	return ok && holder.HoldsList()
}

// Enforcement is the data plane's copy of the exhausted tenants, fed by the
// control plane's usage snapshots and changes. Reads load an immutable map
// without locking; each update that changes something publishes a new copy.
type Enforcement struct {
	writeMu  sync.Mutex
	tenants  atomic.Pointer[map[string]domain.TenantState]
	received atomic.Bool
	complete atomic.Bool
}

var _ ExhaustionChecker = (*Enforcement)(nil)

// NewEnforcement builds an empty Enforcement that has received no list yet.
func NewEnforcement() *Enforcement {
	e := &Enforcement{}
	empty := make(map[string]domain.TenantState)
	e.tenants.Store(&empty)
	return e
}

// ApplySnapshot merges a usage snapshot following domain.Snapshot.Changes.
// The healthy records it keeps are what stop a control plane replica that is
// behind from blocking a tenant again.
func (e *Enforcement) ApplySnapshot(snapshot domain.Snapshot) {
	e.writeMu.Lock()
	current := *e.tenants.Load()
	if changes := snapshot.Changes(current); len(changes) > 0 {
		next := make(map[string]domain.TenantState, len(current)+len(changes))
		maps.Copy(next, current)
		for _, state := range changes {
			next[state.TenantID] = state
		}
		e.tenants.Store(&next)
	}
	e.writeMu.Unlock()
	e.received.Store(true)
	if snapshot.AsOfVersion > 0 {
		e.complete.Store(true)
	}
}

// HoldsList reports whether a complete usage list has been applied: one with
// an as_of version, built from Usage System and not only from a cache.
func (e *Enforcement) HoldsList() bool { return e.complete.Load() }

// ApplyChanges merges individual tenant states following
// TenantState.Supersedes. Only a full list counts as received: changes alone
// say nothing about the tenants they do not mention.
func (e *Enforcement) ApplyChanges(states []domain.TenantState) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	held := *e.tenants.Load()
	var next map[string]domain.TenantState
	for _, state := range states {
		if current, ok := held[state.TenantID]; ok && !state.Supersedes(current) {
			continue
		}
		if next == nil {
			next = make(map[string]domain.TenantState, len(held)+len(states))
			maps.Copy(next, held)
			held = next
		}
		next[state.TenantID] = state
	}
	if next != nil {
		e.tenants.Store(&next)
	}
}

// Received reports whether at least one snapshot has been applied.
func (e *Enforcement) Received() bool { return e.received.Load() }

// Exhausted reports whether tenantID is exhausted and why. An unknown tenant
// is healthy.
func (e *Enforcement) Exhausted(tenantID string) (domain.Reason, bool) {
	state, ok := (*e.tenants.Load())[tenantID]
	if !ok || !state.Exhausted() {
		return domain.ReasonNone, false
	}
	return state.Reason, true
}
