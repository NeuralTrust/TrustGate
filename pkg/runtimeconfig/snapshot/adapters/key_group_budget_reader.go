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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

// keyGroupBudgetReader serves the group budgets from the config snapshot, the
// read side of a data plane with no database. Budgets are edited on the
// control plane only.
type keyGroupBudgetReader struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

// NewKeyGroupBudgetReader wires the snapshot-backed budget reader.
func NewKeyGroupBudgetReader(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Reader {
	return &keyGroupBudgetReader{store: store}
}

// ListByGateway returns the gateway's budgets. An unloaded snapshot yields
// none: before its first snapshot a plane serves no store request either.
func (r *keyGroupBudgetReader) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*domain.Budget, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, nil
	}
	return cloneSlice(snap.KeyGroupBudgetsByGateway(gatewayID))
}
