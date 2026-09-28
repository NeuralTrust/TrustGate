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
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

// storeGrantReader serves MCP Store access grants and per-principal policies
// from the config snapshot — the data plane's read side. Both are edited on the
// control plane only.
type storeGrantReader struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

// NewStoreGrantReader wires the snapshot-backed grant reader.
func NewStoreGrantReader(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Reader {
	return &storeGrantReader{store: store}
}

// NewStorePolicyReader wires the snapshot-backed policy reader.
func NewStorePolicyReader(store configsync.ConfigStore[*readmodel.Snapshot]) domain.PolicyReader {
	return &storeGrantReader{store: store}
}

// ListPoliciesByGateway returns the gateway's policies; an unloaded snapshot
// yields none, which falls back to the gateway default mode.
func (r *storeGrantReader) ListPoliciesByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*domain.Policy, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, nil
	}
	return cloneSlice(snap.StorePoliciesByGateway(gatewayID))
}

// ListByGateway returns the gateway's grants; an unloaded snapshot yields none,
// which fails closed (nobody granted) rather than erroring the request.
func (r *storeGrantReader) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*domain.Grant, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, nil
	}
	return cloneSlice(snap.StoreGrantsByGateway(gatewayID))
}
