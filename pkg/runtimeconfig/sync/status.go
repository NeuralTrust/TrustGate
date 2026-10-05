// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configsync

import (
	"sync"
	"time"
)

// SnapshotState says where the snapshot a pod is serving came from.
type SnapshotState string

const (
	// SnapshotNone means no snapshot is loaded; the pod is not ready.
	SnapshotNone SnapshotState = "none"
	// SnapshotLKG means the snapshot was restored from the last-known-good file
	// and no converge has confirmed or refreshed it since.
	SnapshotLKG SnapshotState = "lkg"
	// SnapshotLive means a successful converge applied or confirmed the snapshot.
	SnapshotLive SnapshotState = "live"
)

// SnapshotInfo is a point-in-time view of the served snapshot.
type SnapshotInfo struct {
	State   SnapshotState
	Version string
	// AppliedAt is when the snapshot was applied: for lkg, when the last-known-good
	// file was written; for live, when the converge applied or confirmed it.
	AppliedAt time.Time
}

// SnapshotStatus tracks the source of the served snapshot so /readyz and the
// gauges can tell a live snapshot from a stale restored one. It never affects
// convergence; the worker only reports into it. Safe for concurrent use.
type SnapshotStatus struct {
	mu    sync.RWMutex
	clock func() time.Time
	info  SnapshotInfo
}

// NewSnapshotStatus builds a tracker in the none state. A nil clock uses time.Now.
func NewSnapshotStatus(clock func() time.Time) *SnapshotStatus {
	if clock == nil {
		clock = time.Now
	}
	return &SnapshotStatus{clock: clock, info: SnapshotInfo{State: SnapshotNone}}
}

// MarkLKG records a snapshot restored from the last-known-good file, whose
// content is age old (zero when the file age is unknown).
func (s *SnapshotStatus) MarkLKG(version string, age time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if age < 0 {
		age = 0
	}
	s.info = SnapshotInfo{State: SnapshotLKG, Version: version, AppliedAt: s.clock().Add(-age)}
}

// MarkLive records a snapshot applied by a successful converge.
func (s *SnapshotStatus) MarkLive(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info = SnapshotInfo{State: SnapshotLive, Version: version, AppliedAt: s.clock()}
}

// ConfirmLive promotes a restored snapshot to live when the control plane
// answered a converge with not-modified, proving the restored version is the
// current one. It is a no-op in any other state.
func (s *SnapshotStatus) ConfirmLive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.info.State != SnapshotLKG {
		return
	}
	s.info = SnapshotInfo{State: SnapshotLive, Version: s.info.Version, AppliedAt: s.clock()}
}

// Info returns the current state.
func (s *SnapshotStatus) Info() SnapshotInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.info
}

// Age returns how long ago the snapshot was applied; false when none is loaded.
func (s *SnapshotStatus) Age() (time.Duration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.info.State == SnapshotNone {
		return 0, false
	}
	age := s.clock().Sub(s.info.AppliedAt)
	if age < 0 {
		age = 0
	}
	return age, true
}
