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

package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func stampedGatewayEntitlements(tier string, burst, quota, maxInst int) gatewaydomain.Entitlements {
	return gatewaydomain.Entitlements{
		Tier:          tier,
		BurstPerMin:   &burst,
		QuotaPerMonth: &quota,
		MaxInstances:  &maxInst,
	}
}

func tenantGateway(id ids.GatewayID, tenant string, e gatewaydomain.Entitlements) *gatewaydomain.Gateway {
	gw := &gatewaydomain.Gateway{ID: id, Entitlements: e}
	if tenant != "" {
		gw.Metadata = map[string]string{gatewaydomain.MetadataTenantIDKey: tenant}
	}
	return gw
}

// capsStub answers from a fixed map, like the snapshot or the cache would.
type capsStub struct {
	rows map[string]domain.TenantCaps
	err  error
}

func (c capsStub) FindTenantCaps(_ context.Context, tenantID string) (*domain.TenantCaps, error) {
	if c.err != nil {
		return nil, c.err
	}
	row, ok := c.rows[tenantID]
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	return &row, nil
}

func TestResolvePrefersTheContextGateway(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	gw := tenantGateway(id, "acme", stampedGatewayEntitlements("standard", 300, 100_000, 5))
	ctx := appgateway.WithGateway(context.Background(), gw)

	got, err := NewGatewayTierLoader(finder, nil).Resolve(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.Subject)
	assert.Equal(t, domain.Limits{BurstPerMin: 300, QuotaPerMonth: 100_000, MaxInstances: 5}, got.Limits)
	finder.AssertNotCalled(t, "FindByID")
}

func TestResolveFallsBackToTheFinder(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	finder.EXPECT().FindByID(context.Background(), id).
		Return(tenantGateway(id, "acme", stampedGatewayEntitlements("enterprise", 1_000, 0, 5)), nil).Once()

	got, err := NewGatewayTierLoader(finder, nil).Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, domain.Limits{BurstPerMin: 1_000, QuotaPerMonth: 0, MaxInstances: 5}, got.Limits)
}

func TestResolveUsesTheTenantCapsAndCountsUnderTheTenant(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	gw := tenantGateway(id, "acme", stampedGatewayEntitlements("free", 60, 10_000, 5))
	caps := capsStub{rows: map[string]domain.TenantCaps{
		"acme": {TenantID: "acme", Tier: "standard", BurstPerMin: 300, QuotaPerMonth: 100_000, MaxInstances: 5},
	}}

	got, err := NewGatewayTierLoader(finder, caps).Resolve(appgateway.WithGateway(context.Background(), gw), id)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.Subject)
	assert.Equal(t, 300, got.Limits.BurstPerMin, "the tenant's caps beat the gateway stamp")
}

// Until the control plane has published a row, the stamp is the number, but the
// counter is already the tenant's.
func TestResolveWithoutATenantRowUsesTheStampUnderTheTenant(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	gw := tenantGateway(id, "acme", stampedGatewayEntitlements("standard", 300, 100_000, 5))

	got, err := NewGatewayTierLoader(finder, capsStub{}).Resolve(appgateway.WithGateway(context.Background(), gw), id)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.Subject)
	assert.Equal(t, 300, got.Limits.BurstPerMin)
}

func TestResolveGatewayWithoutATenantIsUnmeteredEvenWhenStamped(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	gw := tenantGateway(id, "", stampedGatewayEntitlements("standard", 300, 100_000, 5))

	_, err := NewGatewayTierLoader(finder, nil).Resolve(appgateway.WithGateway(context.Background(), gw), id)
	assert.ErrorIs(t, err, ErrUnmetered, "there is nobody to bill: OSS installs have no tenant")
}

func TestResolveTenantWithNeitherRowNorStampIsUnmetered(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	gw := tenantGateway(id, "acme", gatewaydomain.Entitlements{Tier: "standard"})

	_, err := NewGatewayTierLoader(finder, capsStub{}).Resolve(appgateway.WithGateway(context.Background(), gw), id)
	assert.ErrorIs(t, err, ErrUnmetered)
}

func TestResolveCapsSourceFailurePropagates(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	gw := tenantGateway(id, "acme", stampedGatewayEntitlements("standard", 300, 100_000, 5))
	boom := errors.New("db down")

	_, err := NewGatewayTierLoader(finder, capsStub{err: boom}).Resolve(appgateway.WithGateway(context.Background(), gw), id)
	assert.ErrorIs(t, err, boom, "the meter fails open on it; it must not read as unmetered or as a stamp")
	assert.NotErrorIs(t, err, ErrUnmetered)
}

func TestResolveFinderErrorPropagates(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()
	finder.EXPECT().FindByID(context.Background(), id).Return(nil, gatewaydomain.ErrNotFound).Once()

	_, err := NewGatewayTierLoader(finder, nil).Resolve(context.Background(), id)
	assert.ErrorIs(t, err, gatewaydomain.ErrNotFound)
}

func TestResolveNilContextGatewayIsNotFound(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	id := ids.New[ids.GatewayKind]()

	_, err := NewGatewayTierLoader(finder, nil).Resolve(appgateway.WithGateway(context.Background(), nil), id)
	assert.ErrorIs(t, err, gatewaydomain.ErrNotFound)
	finder.AssertNotCalled(t, "FindByID")
}

// The point of the cache: resolving a gateway is one lookup, however many
// requests, and never a query for the tenant's row.
func TestResolveWithCapsCacheMakesOnlyTheGatewayLookup(t *testing.T) {
	id := ids.New[ids.GatewayKind]()
	finder := gatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(
		tenantGateway(id, "tenant-1", stampedGatewayEntitlements("free", 60, 10_000, 5)), nil)

	lister := &fakeLister{rows: []domain.TenantCaps{capsRow("tenant-1", 300)}}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	require.NoError(t, c.Load(context.Background()))
	loads := lister.calls

	loader := NewGatewayTierLoader(finder, c)
	for i := 0; i < 5; i++ {
		got, err := loader.Resolve(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, 300, got.Limits.BurstPerMin, "the tenant's caps beat the gateway stamp")
	}
	assert.Equal(t, loads, lister.calls, "resolving must not query the caps table")
}

func TestResolveWithCapsCacheNeverLoadedFallsBackToTheGatewayStamp(t *testing.T) {
	id := ids.New[ids.GatewayKind]()
	finder := gatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(
		tenantGateway(id, "tenant-1", stampedGatewayEntitlements("standard", 300, 100_000, 5)), nil)

	c := NewTenantCapsCache(&fakeLister{err: errors.New("down")}, time.Hour, discardLogger())
	require.Error(t, c.Load(context.Background()))

	got, err := NewGatewayTierLoader(finder, c).Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", got.Subject, "still counted under the tenant")
	assert.Equal(t, domain.Limits{BurstPerMin: 300, QuotaPerMonth: 100_000, MaxInstances: 5}, got.Limits)
}

// A cold cache with an unstamped gateway is not metered, as an OSS gateway is not:
// the cache being cold must not invent a plan.
func TestResolveWithColdCacheAndUnstampedGatewayIsUnmetered(t *testing.T) {
	id := ids.New[ids.GatewayKind]()
	finder := gatewaymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(tenantGateway(id, "tenant-1", gatewaydomain.Entitlements{}), nil)

	c := NewTenantCapsCache(&fakeLister{}, time.Hour, discardLogger())
	_, err := NewGatewayTierLoader(finder, c).Resolve(context.Background(), id)
	assert.ErrorIs(t, err, ErrUnmetered)
}
