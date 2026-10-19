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
// control plane's usage snapshots.
type Enforcement struct {
	mu       sync.RWMutex
	tenants  map[string]enforcedState
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
	return &Enforcement{tenants: make(map[string]enforcedState)}
}

// ApplySnapshot merges a usage snapshot. A listed tenant is applied when its
// version is newer than the one held. A held exhausted tenant missing from the
// list becomes healthy at the snapshot's AsOfVersion, unless the data plane
// holds a newer version; keeping that healthy record is what stops a control
// plane replica that is behind from blocking the tenant again.
func (e *Enforcement) ApplySnapshot(snapshot domain.Snapshot) {
	listed := make(map[string]struct{}, len(snapshot.Exhausted))
	e.mu.Lock()
	for _, state := range snapshot.Exhausted {
		listed[state.TenantID] = struct{}{}
		if current, ok := e.tenants[state.TenantID]; ok && current.version >= state.Version {
			continue
		}
		e.tenants[state.TenantID] = enforcedState{exhausted: true, reason: state.Reason, version: state.Version}
	}
	for tenantID, current := range e.tenants {
		if _, ok := listed[tenantID]; ok || !current.exhausted || current.version > snapshot.AsOfVersion {
			continue
		}
		e.tenants[tenantID] = enforcedState{version: snapshot.AsOfVersion}
	}
	e.mu.Unlock()
	e.received.Store(true)
}

// Received reports whether at least one snapshot has been applied.
func (e *Enforcement) Received() bool { return e.received.Load() }

// Exhausted reports whether tenantID is exhausted and why. An unknown tenant
// is healthy.
func (e *Enforcement) Exhausted(tenantID string) (domain.Reason, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	state, ok := e.tenants[tenantID]
	if !ok || !state.exhausted {
		return domain.ReasonNone, false
	}
	return state.reason, true
}
