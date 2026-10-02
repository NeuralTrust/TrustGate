//go:build functional

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
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
)

func ip(v int) *int { return &v }

func plan(tier string, burst, quota, inst int) domain.Entitlements {
	return domain.Entitlements{Tier: tier, BurstPerMin: ip(burst), QuotaPerMonth: ip(quota), MaxInstances: ip(inst)}
}

// The restamp writes the tenant's row in the same transaction as the gateways,
// and writes it for a tenant that has no gateway at all.
func TestRepository_Restamp_UpsertsTheTenantRow(t *testing.T) {
	r, conn := setupRepo(t)
	ctx := context.Background()
	_, _ = conn.Pool.Exec(ctx, "TRUNCATE TABLE tenant_entitlements")
	t.Cleanup(func() { _, _ = conn.Pool.Exec(context.Background(), "TRUNCATE TABLE tenant_entitlements") })

	touched, err := r.RestampEntitlementsByTenantID(ctx, "ghost", plan("standard", 300, 100000, 5))
	if err != nil {
		t.Fatalf("restamp: %v", err)
	}
	if len(touched) != 0 {
		t.Fatalf("touched = %d, want 0", len(touched))
	}
	got, err := r.GetTenantCaps(ctx, "ghost")
	if err != nil {
		t.Fatalf("GetTenantCaps: %v", err)
	}
	if got.Tier != "standard" || got.BurstPerMin != 300 || got.QuotaPerMonth != 100000 || got.MaxInstances != 5 {
		t.Fatalf("row = %+v", got)
	}

	// A second restamp replaces it.
	if _, err := r.RestampEntitlementsByTenantID(ctx, "ghost", plan("enterprise", 1000, 0, 0)); err != nil {
		t.Fatalf("restamp 2: %v", err)
	}
	got, _ = r.GetTenantCaps(ctx, "ghost")
	if got.Tier != "enterprise" || got.BurstPerMin != 1000 || got.QuotaPerMonth != 0 {
		t.Fatalf("row after second restamp = %+v", got)
	}
}

// A stamped create fills the gap and never overwrites a row a restamp keeps current.
func TestRepository_StampedCreate_SeedsOnlyWhenAbsent(t *testing.T) {
	r, conn := setupRepo(t)
	ctx := context.Background()
	_, _ = conn.Pool.Exec(ctx, "TRUNCATE TABLE tenant_entitlements")
	t.Cleanup(func() { _, _ = conn.Pool.Exec(context.Background(), "TRUNCATE TABLE tenant_entitlements") })

	if _, err := r.GetTenantCaps(ctx, "acme"); !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("a tenant without a row = %v, want ErrNotFound", err)
	}

	first, _ := domain.New("acme-one")
	first.Metadata = domain.WithTenantID(nil, "acme")
	first.Entitlements = plan("free", 60, 10000, 5)
	if err := r.Save(ctx, first); err != nil {
		t.Fatalf("save first: %v", err)
	}
	got, err := r.GetTenantCaps(ctx, "acme")
	if err != nil || got.BurstPerMin != 60 {
		t.Fatalf("seeded row = %+v, %v", got, err)
	}

	// The tenant moves to standard through a restamp. A later create carrying a
	// stale free stamp must not push it back.
	if _, err := r.RestampEntitlementsByTenantID(ctx, "acme", plan("standard", 300, 100000, 5)); err != nil {
		t.Fatalf("restamp: %v", err)
	}
	stale, _ := domain.New("acme-two")
	stale.Metadata = domain.WithTenantID(nil, "acme")
	stale.Entitlements = plan("free", 60, 10000, 5)
	if err := r.SaveWithTenantCap(ctx, stale, "acme", 5); err != nil {
		t.Fatalf("save stale: %v", err)
	}
	got, _ = r.GetTenantCaps(ctx, "acme")
	if got.Tier != "standard" || got.BurstPerMin != 300 {
		t.Fatalf("a stale create overwrote the row: %+v", got)
	}

	// Unstamped and tenantless creates write nothing.
	plain, _ := domain.New("plain")
	if err := r.Save(ctx, plain); err != nil {
		t.Fatalf("save plain: %v", err)
	}
	loose, _ := domain.New("loose")
	loose.Entitlements = plan("free", 60, 10000, 5)
	if err := r.Save(ctx, loose); err != nil {
		t.Fatalf("save loose: %v", err)
	}
	list, err := r.ListTenantCaps(ctx)
	if err != nil || len(list) != 1 || list[0].TenantID != "acme" {
		t.Fatalf("list = %+v, %v; want exactly acme", list, err)
	}
}
