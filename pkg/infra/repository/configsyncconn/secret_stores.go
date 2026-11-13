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

package configsyncconn

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// storedSecretStore is how a reported secret store is kept in the
// secret_stores column.
type storedSecretStore struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	AllowedPaths []string `json:"allowed_paths,omitempty"`
	// AllowedDestinations is omitted when absent; a store never declares an
	// empty one.
	AllowedDestinations []string        `json:"allowed_destinations,omitempty"`
	Gateways            []ids.GatewayID `json:"gateways,omitempty"`
	State               string          `json:"state"`
	ErrorClass          string          `json:"error_class,omitempty"`
	CheckedAt           *time.Time      `json:"checked_at,omitempty"`
}

// encodeSecretStores returns the column value: NULL when the data plane
// reported none.
func encodeSecretStores(in []secretstore.Status) ([]byte, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]storedSecretStore, 0, len(in))
	for _, s := range in {
		st := storedSecretStore{
			Name: s.Name, Type: string(s.Type), AllowedPaths: s.AllowedPaths, Gateways: s.Gateways,
			State: string(s.State), ErrorClass: string(s.ErrorClass), AllowedDestinations: s.AllowedDestinations,
		}
		if !s.CheckedAt.IsZero() {
			t := s.CheckedAt.UTC()
			st.CheckedAt = &t
		}
		out = append(out, st)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("configsyncconn: encode secret stores: %w", err)
	}
	return raw, nil
}

// decodeSecretStores reads the column back. A value that does not decode is
// treated as no report: it only ever comes from a heartbeat.
func decodeSecretStores(raw []byte) []secretstore.Status {
	if len(raw) == 0 {
		return nil
	}
	var stored []storedSecretStore
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil
	}
	out := make([]secretstore.Status, 0, len(stored))
	for _, s := range stored {
		st := secretstore.Status{
			Name: s.Name, Type: secretstore.Type(s.Type), AllowedPaths: s.AllowedPaths, Gateways: s.Gateways,
			State: secretstore.State(s.State), ErrorClass: secretstore.Class(s.ErrorClass), AllowedDestinations: s.AllowedDestinations,
		}
		if s.CheckedAt != nil {
			st.CheckedAt = *s.CheckedAt
		}
		out = append(out, st)
	}
	return out
}
