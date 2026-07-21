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
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	metricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func expectNoSiblingGateways(repo *repomocks.Repository, tenantID string) {
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == tenantID
		})).
		Return([]*domain.Gateway{}, 0, nil).
		Once()
}

func entitlementInt(v int) *int { return &v }

func stampedEntitlements(tier string) domain.Entitlements {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "standard":
		return domain.Entitlements{
			Tier:          "standard",
			BurstPerMin:   entitlementInt(300),
			QuotaPerMonth: entitlementInt(100_000),
			MaxInstances:  entitlementInt(5),
		}
	case "enterprise":
		return domain.Entitlements{
			Tier:          "enterprise",
			BurstPerMin:   entitlementInt(1_000),
			QuotaPerMonth: entitlementInt(0),
			MaxInstances:  entitlementInt(5),
		}
	default:
		return domain.Entitlements{
			Tier:          "free",
			BurstPerMin:   entitlementInt(60),
			QuotaPerMonth: entitlementInt(10_000),
			MaxInstances:  entitlementInt(5),
		}
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	tel := &telemetry.Telemetry{ExtraParams: map[string]string{"env": "prod"}}
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Slug == "prod" &&
				g.Status == "active" &&
				g.Telemetry == tel
		}), "acme", 0).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:      "prod",
		TenantID:  "acme",
		Telemetry: tel,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Slug != "prod" || g.Status != "active" {
		t.Fatalf("Create returned unexpected gateway: %+v", g)
	}
	if !g.SessionConfig.IsEnabled() {
		t.Fatal("expected default session config to be enabled when none is provided")
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + g.ID.String())
	if !ok {
		t.Fatal("created gateway was not pre-warmed in the cache")
	}
	if cached.(*domain.Gateway).ID != g.ID {
		t.Fatal("cached gateway ID mismatch")
	}
}

func TestCreator_Create_PreservesExplicitSessionConfig(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	disabled := false
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(nil).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod",
		TenantID:      "acme",
		SessionConfig: &domain.SessionConfig{Enabled: &disabled},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.SessionConfig.IsEnabled() {
		t.Fatal("explicit enabled=false must be preserved")
	}
}

func TestCreator_Create_GeneratesSlugWhenEmpty(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return domain.IsValidSlug(g.Slug)
		}), "acme", 0).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if !domain.IsValidSlug(g.Slug) {
		t.Fatalf("expected auto-generated valid slug, got %q", g.Slug)
	}
}

func TestCreator_Create_RetriesOnGeneratedSlugCollision(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(domain.ErrAlreadyExists).Once()
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(nil).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "", TenantID: "acme"})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if !domain.IsValidSlug(g.Slug) {
		t.Fatalf("expected valid slug after retry, got %q", g.Slug)
	}
}

func TestCreator_Create_DoesNotRetryOnProvidedSlugCollision(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(domain.ErrAlreadyExists).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "prod", TenantID: "acme"})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for client-provided slug, got %v", err)
	}
}

func TestCreator_Create_RejectsUnknownExporter(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	factory := metricsmocks.NewExporterFactory(t)
	factory.EXPECT().
		Validate(mock.MatchedBy(func(cfg telemetry.ExporterConfig) bool { return cfg.Name == "datadog" })).
		Return(errors.New("unknown exporter")).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), factory, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
		Telemetry: &telemetry.Telemetry{
			Exporters: []telemetry.ExporterConfig{
				{Name: "datadog", Settings: map[string]interface{}{}},
			},
		},
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}

func TestCreator_Create_RejectsDuplicateExporter(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	factory := metricsmocks.NewExporterFactory(t)
	factory.EXPECT().Validate(mock.Anything).Return(nil).Maybe()

	creator := appgateway.NewCreator(repo, newCacheManager(), factory, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
		Telemetry: &telemetry.Telemetry{
			Exporters: []telemetry.ExporterConfig{
				{Name: "kafka", Settings: map[string]interface{}{"topic": "a"}},
				{Name: "kafka", Settings: map[string]interface{}{"topic": "b"}},
			},
		},
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation for duplicate exporter, got %v", err)
	}
}

func TestCreator_Create_StripsClientProvidedTenantID(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme" && g.Metadata["env"] == "prod"
		}), "acme", 0).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
		Metadata: map[string]string{domain.MetadataTenantIDKey: "attacker-team", "env": "prod"},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.TenantID() != "acme" {
		t.Fatalf("tenant_id from input was not stamped: got %q, want acme", g.TenantID())
	}
}

func TestCreator_Create_StampsTenantIDFromContext(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme" && g.Metadata["env"] == "prod"
		}), "acme", 0).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
		Metadata: map[string]string{domain.MetadataTenantIDKey: "attacker-team", "env": "prod"},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.TenantID() != "acme" {
		t.Fatalf("tenant_id from context was not stamped: got %q, want acme", g.TenantID())
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).
		Return(domain.ErrAlreadyExists).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	if !errors.Is(err, commonerrors.ErrAlreadyExists) {
		t.Fatalf("expected wrapped commonerrors.ErrAlreadyExists, got %v", err)
	}
}

func TestCreator_Create_RejectsSecondGatewayOnFreeTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 5).Return(ratelimit.ErrInstanceLimit).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	entitlements := stampedEntitlements("free")
	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod-2",
		TenantID:      "acme",
		PlatformAdmin: true,
		Entitlements:  &entitlements,
	})
	if !errors.Is(err, ratelimit.ErrInstanceLimit) {
		t.Fatalf("expected ErrInstanceLimit, got %v", err)
	}
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("expected wrapped commonerrors.ErrConflict, got %v", err)
	}
}

func TestCreator_Create_AllowsSecondGatewayOnStandardTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 5).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	entitlements := stampedEntitlements("standard")
	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod-2",
		TenantID:      "acme",
		PlatformAdmin: true,
		Entitlements:  &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", g.Entitlements.Tier)
	}
}

func TestCreator_Create_AllowsEnterpriseTierAtInstanceCap(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 5).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	entitlements := stampedEntitlements("enterprise")
	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod-51",
		TenantID:      "acme",
		PlatformAdmin: true,
		Entitlements:  &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestCreator_Create_RejectsEmptyTenant(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "prod"})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation for empty tenant_id, got %v", err)
	}
}

func TestCreator_Create_AllowsFirstGatewayOnFreeTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestCreator_Create_PropagatesSaveWithTenantCapError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(errors.New("db down")).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		TenantID: "acme",
	})
	if err == nil || err.Error() != "db down" {
		t.Fatalf("expected repo error to propagate, got %v", err)
	}
}

func TestCreator_Create_RateLimitDisabled_PassesUnlimitedCap(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	// With rate limiting off the cap is unlimited (0) even for a tenant on the free tier.
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod-2",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestCreator_Create_RejectsClientEntitlementsWhenTenantSet(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	entitlements := stampedEntitlements("enterprise")
	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:         "prod",
		TenantID:     "acme",
		Entitlements: &entitlements,
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation rejecting tenant entitlements, got %v", err)
	}
}

func TestCreator_Create_AcceptsClientEntitlementsWhenPlatformAdmin(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 5).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	entitlements := stampedEntitlements("standard")
	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod",
		TenantID:      "acme",
		PlatformAdmin: true,
		Entitlements:  &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Entitlements.Tier != "standard" {
		t.Fatalf("platform admin entitlements must be honored: got %q, want standard", g.Entitlements.Tier)
	}
}

func TestCreator_Create_InheritsSiblingStandardTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	sibling := &domain.Gateway{Entitlements: stampedEntitlements("standard")}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == "acme"
		})).
		Return([]*domain.Gateway{sibling}, 1, nil).
		Once()
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "standard"
		}), "acme", 5).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod-2",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", g.Entitlements.Tier)
	}
}

func TestCreator_Create_RejectsThirdGatewayOnInheritedStandardCap(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	siblings := []*domain.Gateway{
		{Entitlements: stampedEntitlements("standard")},
		{Entitlements: stampedEntitlements("standard")},
	}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == "acme"
		})).
		Return(siblings, 2, nil).
		Once()
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 5).Return(ratelimit.ErrInstanceLimit).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod-3",
		TenantID: "acme",
	})
	if !errors.Is(err, ratelimit.ErrInstanceLimit) {
		t.Fatalf("expected ErrInstanceLimit, got %v", err)
	}
}

func TestCreator_Create_PlatformAdminStampsTenantAndEntitlements(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	// Platform stamps standard explicitly, so sibling inheritance is skipped.
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme" && g.Entitlements.Tier == "standard"
		}), "acme", 5).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	entitlements := stampedEntitlements("standard")
	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod",
		TenantID:      "acme",
		PlatformAdmin: true,
		Entitlements:  &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.TenantID() != "acme" {
		t.Fatalf("TenantID = %q, want acme", g.TenantID())
	}
	if g.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", g.Entitlements.Tier)
	}
}

func TestCreator_Create_InheritsHighestSiblingTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	siblings := []*domain.Gateway{
		{Entitlements: stampedEntitlements("free")},
		{Entitlements: stampedEntitlements("enterprise")},
		{Entitlements: stampedEntitlements("standard")},
	}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == "acme"
		})).
		Return(siblings, 3, nil).
		Once()
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "enterprise"
		}), "acme", 5).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod-n",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Entitlements.Tier != "enterprise" {
		t.Fatalf("Entitlements.Tier = %q, want enterprise", g.Entitlements.Tier)
	}
}
