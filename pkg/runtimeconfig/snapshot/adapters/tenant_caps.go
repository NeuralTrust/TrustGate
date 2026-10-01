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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

// TenantCapsSource reads a tenant's plan caps out of the current snapshot. A
// snapshot compiled before caps were stored per tenant has none, which reads as
// not found so the caller can fall back to the gateway's own stamp.
type TenantCapsSource struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewTenantCapsSource(store configsync.ConfigStore[*readmodel.Snapshot]) *TenantCapsSource {
	return &TenantCapsSource{store: store}
}

func (s *TenantCapsSource) FindTenantCaps(_ context.Context, tenantID string) (*ratelimitdomain.TenantCaps, error) {
	snap, ok := snapshotFrom(s.store)
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	c, ok := snap.TenantCapsByTenantID(tenantID)
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	clone := *c
	return &clone, nil
}
