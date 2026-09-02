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
	"crypto/rsa"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/golang-jwt/jwt/v5"
)

// PlaygroundKeySource exposes the RS256 playground-token verification keys
// carried by the live config-sync snapshot, so a data plane trusts whatever
// keys its control plane currently publishes — rotation needs no restart.
// Parsed keys are cached per snapshot version.
type PlaygroundKeySource struct {
	store configsync.ConfigStore[*readmodel.Snapshot]

	mu      sync.Mutex
	version string
	keys    map[string]*rsa.PublicKey
}

func NewPlaygroundKeySource(store configsync.ConfigStore[*readmodel.Snapshot]) *PlaygroundKeySource {
	return &PlaygroundKeySource{store: store}
}

func (s *PlaygroundKeySource) PlaygroundTokenKeys() map[string]*rsa.PublicKey {
	if s == nil || s.store == nil {
		return nil
	}
	snap, ok := snapshotFrom(s.store)
	if !ok {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Version() != "" && snap.Version() == s.version {
		return s.keys
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, entry := range snap.PlaygroundTokenKeys() {
		// A key that does not parse is skipped rather than poisoning the set:
		// the control plane validates keys at boot, so this only guards against
		// a corrupted snapshot entry.
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(entry.PEM))
		if err != nil {
			continue
		}
		keys[entry.KID] = key
	}
	s.version = snap.Version()
	s.keys = keys
	return keys
}
