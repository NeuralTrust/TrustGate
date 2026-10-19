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

package adapters

import (
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

// SessionRevocations reads default-IdP revocation markers from the config
// snapshot this data plane is serving.
//
// The rows travel in snapshot field 15. A data plane built before that field
// ignores it (proto3 skips unknown fields) and keeps serving; the revocation
// applies once that plane runs a build that reads the field. Shipping the
// field does not block a deploy of older data planes. A missing snapshot or
// a missing row is not a revocation.
type SessionRevocations struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

var _ appoauth.SnapshotRevocations = SessionRevocations{}

// NewSessionRevocations adapts the data plane's snapshot store.
func NewSessionRevocations(store configsync.ConfigStore[*readmodel.Snapshot]) SessionRevocations {
	return SessionRevocations{store: store}
}

// RevokedAt is the snapshot's marker for this subject, or false when the
// snapshot is not loaded or has no row.
func (s SessionRevocations) RevokedAt(gatewayID, org, subject string) (time.Time, bool) {
	if s.store == nil {
		return time.Time{}, false
	}
	snap, ok := snapshotFrom(s.store)
	if !ok {
		return time.Time{}, false
	}
	return snap.SessionRevokedAt(gatewayID, org, subject)
}
