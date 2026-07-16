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

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	tel := &telemetry.Telemetry{ExtraParams: map[string]string{"env": "prod"}}
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Slug == "prod" &&
				g.Status == "active" &&
				g.Telemetry == tel
		}), "", 0).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true, false)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:      "prod",
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
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).Return(nil).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true, false)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod",
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
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return domain.IsValidSlug(g.Slug)
		}), "", 0).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true, false)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug: "",
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
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).Return(domain.ErrAlreadyExists).Once()
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).Return(nil).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true, false)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: ""})
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
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).Return(domain.ErrAlreadyExists).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "prod"})
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

	creator := appgateway.NewCreator(repo, newCacheManager(), factory, newTestLogger(), nil, true, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug: "prod",
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

	creator := appgateway.NewCreator(repo, newCacheManager(), factory, newTestLogger(), nil, true, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug: "prod",
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
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "" && g.Metadata["env"] == "prod"
		}), "", 0).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod",
		Metadata: map[string]string{domain.MetadataTenantIDKey: "attacker-team", "env": "prod"},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.TenantID() != "" {
		t.Fatalf("client-provided tenant_id was not stripped: %q", g.TenantID())
	}
}

func TestCreator_Create_StampsTenantIDFromContext(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme" && g.Metadata["env"] == "prod"
		}), "acme", 1).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

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
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).
		Return(domain.ErrAlreadyExists).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger(), nil, true, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug: "prod",
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
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 1).Return(ratelimit.ErrInstanceLimit).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod-2",
		TenantID: "acme",
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
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 2).Return(nil).Once()

	// entitlementsMutable=true so the tenant-scoped tier is honored for the cap.
	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, true)

	entitlements := domain.Entitlements{Tier: "standard"}
	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:         "prod-2",
		TenantID:     "acme",
		Entitlements: &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", g.Entitlements.Tier)
	}
}

func TestCreator_Create_AllowsUnlimitedInstancesOnEnterpriseTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 0).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, true)

	entitlements := domain.Entitlements{Tier: "enterprise"}
	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:         "prod-51",
		TenantID:     "acme",
		Entitlements: &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestCreator_Create_SkipsInstanceLimitWhenTenantEmpty(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "prod"})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestCreator_Create_AllowsFirstGatewayOnFreeTier(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 1).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

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
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 1).Return(errors.New("db down")).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

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

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, false, false)

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:     "prod-2",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestCreator_Create_IgnoresClientEntitlementsWhenTenantSet(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	expectNoSiblingGateways(repo, "acme")
	// Tenant-scoped caller cannot upgrade its own tier; cap stays at the free-tier 1.
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 1).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

	entitlements := domain.Entitlements{Tier: "enterprise"}
	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:         "prod",
		TenantID:     "acme",
		Entitlements: &entitlements,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Entitlements.Tier != domain.TierFree {
		t.Fatalf("tenant-set entitlements must be ignored: got %q, want free", g.Entitlements.Tier)
	}
}

func TestCreator_Create_AcceptsClientEntitlementsWhenPlatformAdmin(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "", 0).Return(nil).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

	entitlements := domain.Entitlements{Tier: "standard"}
	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Slug:          "prod",
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
	sibling := &domain.Gateway{Entitlements: domain.Entitlements{Tier: "standard"}}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == "acme"
		})).
		Return([]*domain.Gateway{sibling}, 1, nil).
		Once()
	repo.EXPECT().
		SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "standard"
		}), "acme", 2).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

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
		{Entitlements: domain.Entitlements{Tier: "standard"}},
		{Entitlements: domain.Entitlements{Tier: "standard"}},
	}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.TenantID == "acme"
		})).
		Return(siblings, 2, nil).
		Once()
	repo.EXPECT().SaveWithTenantCap(mock.Anything, mock.Anything, "acme", 2).Return(ratelimit.ErrInstanceLimit).Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

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
		}), "acme", 2).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

	entitlements := domain.Entitlements{Tier: "standard"}
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
		{Entitlements: domain.Entitlements{Tier: "free"}},
		{Entitlements: domain.Entitlements{Tier: "enterprise"}},
		{Entitlements: domain.Entitlements{Tier: "standard"}},
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
		}), "acme", 0).
		Return(nil).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), nil, newTestLogger(), nil, true, false)

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
