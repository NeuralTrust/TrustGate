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

package gateway_test

import (
	"context"
	"testing"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/mock"
)

func intPtr(v int) *int { return &v }

func stamp(tier string, maxInstances, retentionDays int) domain.Entitlements {
	return domain.Entitlements{
		Tier:          tier,
		BurstPerMin:   intPtr(300),
		QuotaPerMonth: intPtr(100_000),
		MaxInstances:  intPtr(maxInstances),
		RetentionDays: intPtr(retentionDays),
	}
}

func touched(n int) []domain.RestampedGateway {
	out := make([]domain.RestampedGateway, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, domain.RestampedGateway{ID: ids.New[ids.GatewayKind](), Slug: "gw"})
	}
	return out
}

func TestRestampTenantReportsWhatItStamped(t *testing.T) {
	repo := mocks.NewRepository(t)
	repo.EXPECT().
		RestampEntitlementsByTenantID(mock.Anything, "acme", mock.MatchedBy(func(e domain.Entitlements) bool {
			return e.Tier == "standard" && e.RetentionDays != nil && *e.RetentionDays == 30
		})).
		Return(touched(3), nil).Once()

	r := appgateway.NewEntitlementsRestamper(repo, newCacheManager(), nil, nil, newTestLogger())
	got, err := r.RestampTenant(context.Background(), "acme", stamp("standard", 5, 30))
	if err != nil {
		t.Fatalf("RestampTenant: %v", err)
	}
	if got.Stamped != 3 {
		t.Fatalf("stamped = %d, want 3", got.Stamped)
	}
	if got.OverCap {
		t.Fatal("3 gateways under a cap of 5 must not report over_cap")
	}
}

// A downgrade must reach every gateway even when the tenant is already above the
// new cap. Refusing would strand them all on the old plan, retention included.
func TestRestampTenantAppliesDowngradeOverCapAndReportsIt(t *testing.T) {
	repo := mocks.NewRepository(t)
	repo.EXPECT().
		RestampEntitlementsByTenantID(mock.Anything, "acme", mock.Anything).
		Return(touched(4), nil).Once()

	r := appgateway.NewEntitlementsRestamper(repo, newCacheManager(), nil, nil, newTestLogger())
	got, err := r.RestampTenant(context.Background(), "acme", stamp("free", 1, 7))
	if err != nil {
		t.Fatalf("a downgrade over cap must not be refused: %v", err)
	}
	if got.Stamped != 4 {
		t.Fatalf("stamped = %d, want 4 (all gateways, cap notwithstanding)", got.Stamped)
	}
	if !got.OverCap || got.MaxInstances != 1 {
		t.Fatalf("over_cap = %v max_instances = %d, want true and 1", got.OverCap, got.MaxInstances)
	}
}

// An unstamped payload never reaches the database: the same contract the
// per-gateway PUT enforces.
func TestRestampTenantRejectsPartialStamp(t *testing.T) {
	repo := mocks.NewRepository(t)

	r := appgateway.NewEntitlementsRestamper(repo, newCacheManager(), nil, nil, newTestLogger())
	if _, err := r.RestampTenant(context.Background(), "acme",
		domain.Entitlements{Tier: "free", BurstPerMin: intPtr(60)}); err == nil {
		t.Fatal("a partial stamp must be rejected before any write")
	}
}

func TestRestampTenantEmptyTenantStampsNothing(t *testing.T) {
	repo := mocks.NewRepository(t)
	repo.EXPECT().
		RestampEntitlementsByTenantID(mock.Anything, "ghost", mock.Anything).
		Return(nil, nil).Once()

	r := appgateway.NewEntitlementsRestamper(repo, newCacheManager(), nil, nil, newTestLogger())
	got, err := r.RestampTenant(context.Background(), "ghost", stamp("free", 1, 7))
	if err != nil {
		t.Fatalf("RestampTenant: %v", err)
	}
	if got.Stamped != 0 || got.OverCap {
		t.Fatalf("got %+v, want nothing stamped and no overage", got)
	}
}
