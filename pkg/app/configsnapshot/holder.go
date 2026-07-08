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

package configsnapshot

import "sync/atomic"

type snapshotState struct {
	raw     []byte
	version string
}

// ScopedSnapshot is a compiled snapshot for a single partition scope.
type ScopedSnapshot struct {
	Raw     []byte
	Version string
}

// Holder stores the current compiled snapshot(s) for the gRPC server to serve.
// It always holds the whole, unpartitioned snapshot (scope "") and, when
// partitioned compilation is active, a per-scope map. Reads are lock-free.
type Holder struct {
	current atomic.Pointer[snapshotState]
	scoped  atomic.Pointer[map[string]snapshotState]
}

func NewHolder() *Holder {
	return &Holder{}
}

// Set replaces the whole, unpartitioned snapshot and leaves the per-scope map
// untouched.
func (h *Holder) Set(raw []byte, version string) {
	h.current.Store(&snapshotState{raw: raw, version: version})
}

// SetPartitioned atomically replaces the whole snapshot and the entire per-scope
// map, so scopes that no longer exist stop being served (fail-closed) on the next
// dispatch.
func (h *Holder) SetPartitioned(raw []byte, version string, scoped map[string]ScopedSnapshot) {
	next := make(map[string]snapshotState, len(scoped))
	for scope, snap := range scoped {
		next[scope] = snapshotState{raw: snap.Raw, version: snap.Version}
	}
	h.current.Store(&snapshotState{raw: raw, version: version})
	h.scoped.Store(&next)
}

func (h *Holder) Snapshot() (raw []byte, version string, ok bool) {
	state := h.current.Load()
	if state == nil {
		return nil, "", false
	}
	return state.raw, state.version, true
}

// SnapshotFor returns the compiled snapshot for a partition scope. An empty scope
// returns the whole, unpartitioned snapshot. A non-empty scope returns only that
// scope's snapshot and never falls back to the whole snapshot: an unknown scope
// yields ok=false so the transport denies it rather than leaking global config.
func (h *Holder) SnapshotFor(scope string) (raw []byte, version string, ok bool) {
	if scope == "" {
		return h.Snapshot()
	}
	m := h.scoped.Load()
	if m == nil {
		return nil, "", false
	}
	state, present := (*m)[scope]
	if !present {
		return nil, "", false
	}
	return state.raw, state.version, true
}

func (h *Holder) Version() string {
	state := h.current.Load()
	if state == nil {
		return ""
	}
	return state.version
}
