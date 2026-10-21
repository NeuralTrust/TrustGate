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

// Package usage holds the per-tenant usage states Usage System decides and the
// gateway enforces: an exhausted tenant has its requests blocked.
package usage

import (
	"context"
	"errors"
	"sort"
)

// Status is whether a tenant may be served.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusExhausted Status = "exhausted"
)

// Reason explains an exhausted status.
type Reason string

const (
	ReasonNone             Reason = ""
	ReasonFreeLimitReached Reason = "free_limit_reached"
	ReasonWalletEmpty      Reason = "wallet_empty"
)

// ErrInvalidState is returned for a state that cannot be applied.
var ErrInvalidState = errors.New("usage: invalid state")

// TenantState is the usage state of one tenant. Version comes from Usage
// System's global sequence and never decreases, so every holder keeps the
// highest version it has seen and drops anything older.
type TenantState struct {
	TenantID string
	Status   Status
	Reason   Reason
	Version  int64
}

// NewTenantState validates and builds a TenantState.
func NewTenantState(tenantID string, status Status, reason Reason, version int64) (TenantState, error) {
	if tenantID == "" {
		return TenantState{}, errors.Join(ErrInvalidState, errors.New("tenant id is required"))
	}
	if version <= 0 {
		return TenantState{}, errors.Join(ErrInvalidState, errors.New("version must be positive"))
	}
	switch status {
	case StatusHealthy:
		reason = ReasonNone
	case StatusExhausted:
		if reason != ReasonFreeLimitReached && reason != ReasonWalletEmpty {
			return TenantState{}, errors.Join(ErrInvalidState, errors.New("exhausted state needs a reason"))
		}
	default:
		return TenantState{}, errors.Join(ErrInvalidState, errors.New("unknown status"))
	}
	return TenantState{TenantID: tenantID, Status: status, Reason: reason, Version: version}, nil
}

// Exhausted reports whether the tenant's requests must be blocked.
func (s TenantState) Exhausted() bool { return s.Status == StatusExhausted }

// Snapshot lists the exhausted tenants. A tenant missing from Exhausted is
// healthy unless the reader already holds a newer version for it than
// AsOfVersion.
type Snapshot struct {
	Exhausted   []TenantState
	AsOfVersion int64
}

// Changes returns the states that applying the snapshot to held would write,
// without touching held. A listed tenant is written when its version is newer
// than the held one. A held exhausted tenant missing from the list becomes
// healthy at AsOfVersion, unless held is newer: keeping that healthy record is
// what stops a list that is behind from blocking the tenant again.
func (s Snapshot) Changes(held map[string]TenantState) []TenantState {
	listed := make(map[string]TenantState, len(s.Exhausted))
	for _, state := range s.Exhausted {
		if prev, ok := listed[state.TenantID]; ok && prev.Version >= state.Version {
			continue
		}
		listed[state.TenantID] = state
	}
	var changes []TenantState
	for tenantID, state := range listed {
		if current, ok := held[tenantID]; ok && current.Version >= state.Version {
			continue
		}
		changes = append(changes, state)
	}
	for tenantID, current := range held {
		if _, ok := listed[tenantID]; ok || !current.Exhausted() || current.Version > s.AsOfVersion {
			continue
		}
		changes = append(changes, TenantState{TenantID: tenantID, Status: StatusHealthy, Reason: ReasonNone, Version: s.AsOfVersion})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].TenantID < changes[j].TenantID })
	return changes
}

//go:generate mockery --name=StateCache --dir=. --output=./mocks --filename=state_cache_mock.go --case=underscore --with-expecter

// StateCache persists the last known state of every tenant so a control plane
// that starts while Usage System is unreachable can still serve it.
type StateCache interface {
	// SaveAll stores each state unless the cache already holds the same or a
	// newer version for its tenant.
	SaveAll(ctx context.Context, states []TenantState) error
	// LoadAll returns every cached state.
	LoadAll(ctx context.Context) ([]TenantState, error)
}
