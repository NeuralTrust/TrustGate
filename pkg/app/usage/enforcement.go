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

// Enforcement is the data plane's copy of the exhausted tenants, fed by the
// control plane's usage snapshots. Reads load an immutable map without
// locking; each snapshot that changes something publishes a new copy.
type Enforcement struct {
	writeMu  sync.Mutex
	tenants  atomic.Pointer[map[string]enforcedState]
	received atomic.Bool
}

type enforcedState struct {
	exhausted bool
	reason    domain.Reason
	version   int64
}

var _ ExhaustionChecker = (*Enforcement)(nil)

// NewEnforcement builds an empty Enforcement that has received no list yet.
func NewEnforcement() *Enforcement {
	e := &Enforcement{}
	empty := make(map[string]enforcedState)
	e.tenants.Store(&empty)
	return e
}

// ApplySnapshot merges a usage snapshot. A listed tenant is applied when its
// version is newer than the one held. A held exhausted tenant missing from the
// list becomes healthy at the snapshot's AsOfVersion, unless the data plane
// holds a newer version; keeping that healthy record is what stops a control
// plane replica that is behind from blocking the tenant again.
func (e *Enforcement) ApplySnapshot(snapshot domain.Snapshot) {
	listed := make(map[string]struct{}, len(snapshot.Exhausted))
	e.writeMu.Lock()
	current := *e.tenants.Load()
	var next map[string]enforcedState
	held := func(tenantID string) (enforcedState, bool) {
		if next != nil {
			state, ok := next[tenantID]
			return state, ok
		}
		state, ok := current[tenantID]
		return state, ok
	}
	set := func(tenantID string, state enforcedState) {
		if next == nil {
			next = make(map[string]enforcedState, len(current)+len(snapshot.Exhausted))
			for id, held := range current {
				next[id] = held
			}
		}
		next[tenantID] = state
	}
	for _, state := range snapshot.Exhausted {
		listed[state.TenantID] = struct{}{}
		if prev, ok := held(state.TenantID); ok && prev.version >= state.Version {
			continue
		}
		set(state.TenantID, enforcedState{exhausted: true, reason: state.Reason, version: state.Version})
	}
	for tenantID, held := range current {
		if _, ok := listed[tenantID]; ok || !held.exhausted || held.version > snapshot.AsOfVersion {
			continue
		}
		set(tenantID, enforcedState{version: snapshot.AsOfVersion})
	}
	if next != nil {
		e.tenants.Store(&next)
	}
	e.writeMu.Unlock()
	e.received.Store(true)
}

// Received reports whether at least one snapshot has been applied.
func (e *Enforcement) Received() bool { return e.received.Load() }

// Exhausted reports whether tenantID is exhausted and why. An unknown tenant
// is healthy.
func (e *Enforcement) Exhausted(tenantID string) (domain.Reason, bool) {
	state, ok := (*e.tenants.Load())[tenantID]
	if !ok || !state.exhausted {
		return domain.ReasonNone, false
	}
	return state.reason, true
}
