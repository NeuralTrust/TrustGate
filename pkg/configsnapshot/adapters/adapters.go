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
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/configsync"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

func snapshotFrom(store configsync.ConfigStore[*readmodel.Snapshot]) (*readmodel.Snapshot, bool) {
	v, ok := store.Load()
	if !ok || v == nil || v.Snapshot == nil {
		return nil, false
	}
	return v.Snapshot, true
}

func cloneJSON[T any](src *T) (*T, error) {
	blob, err := json.Marshal(src)
	if err != nil {
		return nil, fmt.Errorf("adapters: clone marshal: %w", err)
	}
	dst := new(T)
	if err := json.Unmarshal(blob, dst); err != nil {
		return nil, fmt.Errorf("adapters: clone unmarshal: %w", err)
	}
	return dst, nil
}

func cloneAuth(src *authdomain.Auth) (*authdomain.Auth, error) {
	dst, err := cloneJSON(src)
	if err != nil {
		return nil, err
	}
	dst.KeyHash = src.KeyHash
	dst.RawKey = src.RawKey
	return dst, nil
}

func cloneSlice[T any](src []*T) ([]*T, error) {
	out := make([]*T, 0, len(src))
	for _, item := range src {
		clone, err := cloneJSON(item)
		if err != nil {
			return nil, err
		}
		out = append(out, clone)
	}
	return out, nil
}
