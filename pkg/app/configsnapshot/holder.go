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

import (
	"sync"
	"sync/atomic"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
)

type snapshotState struct {
	raw     []byte
	version string
}

// ScopedSnapshot is the encoded snapshot of one scope: Raw followed by
// Catalog. A compile shares one Catalog slice across every scope, so the
// catalog is held once per compile rather than once per scope. A snapshot
// restored from the last-good store carries its full bytes in Raw and no
// Catalog. Neither slice may be appended to or modified once built.
type ScopedSnapshot struct {
	Raw     []byte
	Catalog []byte
	Version string
}

// Len returns the size of the bytes served for the scope.
func (s ScopedSnapshot) Len() int {
	return len(s.Raw) + len(s.Catalog)
}

// Parts returns the non-empty segments whose concatenation is the scope's
// encoded snapshot.
func (s ScopedSnapshot) Parts() [][]byte {
	if len(s.Catalog) == 0 {
		return [][]byte{s.Raw}
	}
	return [][]byte{s.Raw, s.Catalog}
}

// Bytes returns the concatenated encoded snapshot in a new slice when the
// snapshot has a separate catalog, and Raw itself otherwise.
func (s ScopedSnapshot) Bytes() []byte {
	if len(s.Catalog) == 0 {
		return s.Raw
	}
	out := make([]byte, 0, s.Len())
	out = append(out, s.Raw...)
	return append(out, s.Catalog...)
}

type Holder struct {
	current atomic.Pointer[snapshotState]
	scoped  atomic.Pointer[map[string]ScopedSnapshot]

	layeredMu sync.RWMutex
	layered   *Layered
	// previous keeps the fragments of the publish before the current one, so a
	// data plane that read the previous manifest can still fetch its fragments
	// while it pulls.
	previous map[[32]byte][]byte
}

func NewHolder() *Holder {
	return &Holder{}
}

func (h *Holder) Set(raw []byte, version string) {
	h.current.Store(&snapshotState{raw: raw, version: version})
}

func (h *Holder) SetPartitioned(raw []byte, version string, scoped map[string]ScopedSnapshot) {
	next := make(map[string]ScopedSnapshot, len(scoped))
	for scope, snap := range scoped {
		next[scope] = snap
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

// SnapshotFor returns the concatenated snapshot served to scope. It copies a
// scoped snapshot that has a separate catalog, so serving paths use
// SnapshotPartsFor instead.
func (h *Holder) SnapshotFor(scope string) (raw []byte, version string, ok bool) {
	if scope == "" {
		return h.Snapshot()
	}
	snap, ok := h.scopedFor(scope)
	if !ok {
		return nil, "", false
	}
	return snap.Bytes(), snap.Version, true
}

// SnapshotPartsFor returns the segments whose concatenation is the snapshot
// served to scope, without copying them.
func (h *Holder) SnapshotPartsFor(scope string) (parts [][]byte, version string, ok bool) {
	if scope == "" {
		raw, version, ok := h.Snapshot()
		if !ok {
			return nil, "", false
		}
		return [][]byte{raw}, version, true
	}
	snap, ok := h.scopedFor(scope)
	if !ok {
		return nil, "", false
	}
	return snap.Parts(), snap.Version, true
}

func (h *Holder) scopedFor(scope string) (ScopedSnapshot, bool) {
	m := h.scoped.Load()
	if m == nil {
		return ScopedSnapshot{}, false
	}
	snap, ok := (*m)[scope]
	return snap, ok
}

func (h *Holder) Version() string {
	state := h.current.Load()
	if state == nil {
		return ""
	}
	return state.version
}

// SetLayered publishes the manifests and fragments of a layered snapshot. The
// fragments of the publish it replaces stay readable for one more publish.
func (h *Holder) SetLayered(layered Layered) {
	h.layeredMu.Lock()
	defer h.layeredMu.Unlock()
	if h.layered != nil {
		h.previous = h.layered.Fragments
	}
	h.layered = &layered
}

// ClearLayered withdraws the layered snapshot, for a publish that has none: a
// data plane then falls back to the single-blob snapshot.
func (h *Holder) ClearLayered() {
	h.layeredMu.Lock()
	defer h.layeredMu.Unlock()
	h.layered, h.previous = nil, nil
}

// ManifestFor returns the layered manifest served to scope; an empty scope is
// the global snapshot. ok is false when no layered snapshot is published.
func (h *Holder) ManifestFor(scope string) (configsyncport.Manifest, bool) {
	h.layeredMu.RLock()
	defer h.layeredMu.RUnlock()
	if h.layered == nil {
		return configsyncport.Manifest{}, false
	}
	if scope == "" {
		return h.layered.Global, true
	}
	manifest, ok := h.layered.Scoped[scope]
	return manifest, ok
}

// Fragment returns the bytes of the fragment with digest, from the current
// publish or the one before it.
func (h *Holder) Fragment(digest [32]byte) ([]byte, bool) {
	h.layeredMu.RLock()
	defer h.layeredMu.RUnlock()
	if h.layered != nil {
		if raw, ok := h.layered.Fragments[digest]; ok {
			return raw, true
		}
	}
	raw, ok := h.previous[digest]
	return raw, ok
}
