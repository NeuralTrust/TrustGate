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

package adapters_test

import (
	"context"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantCapsSourceReadsTheSnapshotAndReturnsACopy(t *testing.T) {
	t.Parallel()
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: readmodel.Build(readmodel.Data{
		TenantCaps: []ratelimitdomain.TenantCaps{{TenantID: "acme", Tier: "standard", BurstPerMin: 300, QuotaPerMonth: 100000, MaxInstances: 5}},
	})})
	src := adapters.NewTenantCapsSource(store)

	got, err := src.FindTenantCaps(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 300, got.BurstPerMin)
	got.BurstPerMin = 1
	again, _ := src.FindTenantCaps(context.Background(), "acme")
	assert.Equal(t, 300, again.BurstPerMin, "the snapshot's row must not be mutable through the result")

	_, err = src.FindTenantCaps(context.Background(), "globex")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound, "a tenant the snapshot has no row for reads as not found")
}

func TestTenantCapsSourceBeforeTheFirstSnapshotIsNotFound(t *testing.T) {
	t.Parallel()
	_, err := adapters.NewTenantCapsSource(emptyStore()).FindTenantCaps(context.Background(), "acme")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}
