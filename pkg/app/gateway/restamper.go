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

package gateway

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// RestampResult reports what a tenant-wide re-stamp touched.
//
// OverCap is advisory, never a refusal: the stamp is applied regardless, so the
// caller can warn an operator that the tenant now sits above the plan it just
// moved to.
type RestampResult struct {
	Stamped      int
	MaxInstances int
	OverCap      bool
}

//go:generate mockery --name=EntitlementsRestamper --dir=. --output=./mocks --filename=gateway_entitlements_restamper_mock.go --case=underscore --with-expecter
type EntitlementsRestamper interface {
	RestampTenant(ctx context.Context, tenantID string, e domain.Entitlements) (RestampResult, error)
}

var _ EntitlementsRestamper = (*restamper)(nil)

type restamper struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	signaler    configsyncport.SnapshotSignaler
	logger      *slog.Logger
}

func NewEntitlementsRestamper(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	signaler configsyncport.SnapshotSignaler,
	logger *slog.Logger,
) EntitlementsRestamper {
	return &restamper{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		publisher:   publisher,
		signaler:    signaler,
		logger:      logger,
	}
}

// RestampTenant applies e to every gateway of the tenant.
//
// Only entitlements move: slug, metadata, telemetry and the rest are untouched,
// because a plan change knows the plan and nothing else about each gateway.
// Blindly rewriting the rest is how a cached value from the control plane silently
// reverts a field somebody edited in the runtime.
//
// A downgrade is applied even when the tenant is already above the new instance
// cap. Refusing would leave every gateway of the tenant on the old plan — trace
// retention included — with no way out but deleting gateways first. The cap still
// binds on create, which is where it prevents growth.
func (r *restamper) RestampTenant(
	ctx context.Context,
	tenantID string,
	e domain.Entitlements,
) (RestampResult, error) {
	normalized, err := domain.RequireStampedEntitlements(e)
	if err != nil {
		return RestampResult{}, err
	}

	touched, err := r.repo.RestampEntitlementsByTenantID(ctx, tenantID, normalized)
	if err != nil {
		r.logger.Error("failed to restamp tenant entitlements",
			slog.String("tenant_id", tenantID), slog.Any("error", err))
		return RestampResult{}, err
	}

	// Per gateway, mirroring the single-gateway update: the local entry is dropped
	// under both keys it is stored beneath, and every other replica is told to do
	// the same.
	for _, g := range touched {
		r.memoryCache.Delete(gatewayIDCacheKey(g.ID))
		if g.Slug != "" {
			r.memoryCache.Delete(gatewaySlugCacheKey(g.Slug))
		}
		invalidation.GatewayData(ctx, r.publisher, r.logger, g.ID)
	}
	// One signal for the whole batch — the snapshot is rebuilt wholesale, so N
	// signals would be N rebuilds of the same thing.
	if r.signaler != nil && len(touched) > 0 {
		r.signaler.Signal(ctx)
	}

	result := RestampResult{Stamped: len(touched)}
	if limits, ok := normalized.ResolveLimits(); ok && limits.HasInstanceCap() {
		result.MaxInstances = limits.MaxInstances
		result.OverCap = len(touched) > limits.MaxInstances
	}
	return result, nil
}
