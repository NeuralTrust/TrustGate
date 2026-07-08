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

type ScopedSnapshot struct {
	Raw     []byte
	Version string
}

type Holder struct {
	current atomic.Pointer[snapshotState]
	scoped  atomic.Pointer[map[string]snapshotState]
}

func NewHolder() *Holder {
	return &Holder{}
}

func (h *Holder) Set(raw []byte, version string) {
	h.current.Store(&snapshotState{raw: raw, version: version})
}

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
