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

package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T { return &v }

func existingAuth(gwID ids.GatewayID) *domain.Auth {
	a, _ := domain.NewAuth(gwID, "current", domain.TypeAPIKey, true, validConfig())
	return a
}

func oauth2Config(clientSecret string) domain.Config {
	return domain.Config{
		OAuth2: &domain.OAuth2Config{
			Issuer:       "https://issuer.example.com",
			Audiences:    []string{"gateway"},
			JWKSURL:      "https://issuer.example.com/jwks",
			ClientID:     "client-123",
			ClientSecret: clientSecret,
		},
	}
}

func existingOAuth2Auth(gwID ids.GatewayID) *domain.Auth {
	a, _ := domain.NewAuth(gwID, "oauth-cred", domain.TypeOAuth2, true, oauth2Config("real-secret"))
	return a
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingAuth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.ID == existing.ID && a.Name == "renamed"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
		Type:      ptr(domain.TypeAPIKey),
		Enabled:   ptr(true),
		Config:    ptr(validConfig()),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("expected renamed, got %s", got.Name)
	}
}

func TestUpdater_Update_Partial_PreservesTypeAndConfig(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).Return(nil, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.Name == "renamed" && a.Type == domain.TypeOAuth2 &&
				a.Config.OAuth2 != nil && a.Config.OAuth2.ClientSecret == "real-secret"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Type != domain.TypeOAuth2 {
		t.Fatalf("Type = %q, want preserved oauth2", got.Type)
	}
	if got.Config.OAuth2 == nil || got.Config.OAuth2.ClientSecret != "real-secret" {
		t.Fatalf("oauth2 config not preserved: %+v", got.Config.OAuth2)
	}
}

func TestUpdater_Update_PreservesSecretWhenMasked(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).Return(nil, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.Config.OAuth2 != nil && a.Config.OAuth2.ClientSecret == "real-secret"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Config:    ptr(oauth2Config("***")),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Config.OAuth2 == nil || got.Config.OAuth2.ClientSecret != "real-secret" {
		t.Fatalf("masked secret not resolved to stored value: %+v", got.Config.OAuth2)
	}
}

func TestUpdater_Update_GatewayMismatch(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingAuth(ids.New[ids.GatewayKind]())
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      ptr("renamed"),
		Type:      ptr(domain.TypeAPIKey),
		Config:    ptr(validConfig()),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:     id,
		Name:   ptr("x"),
		Type:   ptr(domain.TypeAPIKey),
		Config: ptr(validConfig()),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func oidcConfig() domain.Config {
	return domain.Config{OIDC: &domain.OIDCConfig{
		Issuer:    "https://idp.example.com",
		Audiences: []string{"api://gateway"},
		JWKSURL:   "https://idp.example.com/jwks",
	}}
}

func TestUpdater_Update_RejectsTypeChangeBreakingMCPConsumer(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return([]*consumerdomain.Consumer{{
		ID:          ids.New[ids.ConsumerKind](),
		Slug:        "mcp-cons",
		Type:        consumerdomain.TypeMCP,
		RoutingMode: consumerdomain.RoutingModeRoleBased,
	}}, nil).Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeOIDC),
		Config:    ptr(oidcConfig()),
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (oidc breaks the MCP consumer referencing this auth)", err)
	}
}

func TestUpdater_Update_AllowsTypeChangeWithoutReferences(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		return a.Type == domain.TypeOIDC
	})).Return(nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return(nil, nil).Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeOIDC),
		Config:    ptr(oidcConfig()),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsDisablingAuthOfRoleBasedConsumer(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return([]*consumerdomain.Consumer{{
		ID:          ids.New[ids.ConsumerKind](),
		Slug:        "role-cons",
		Type:        consumerdomain.TypeLLM,
		RoutingMode: consumerdomain.RoutingModeRoleBased,
	}}, nil).Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (disabling the only auth of a role_based consumer)", err)
	}
}

func TestUpdater_Update_RejectsDisablingOnlyMCPAuth(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return([]*consumerdomain.Consumer{{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Slug:        "mcp-inline",
		Type:        consumerdomain.TypeMCP,
		RoutingMode: consumerdomain.RoutingModeInline,
		AuthIDs:     []ids.AuthID{existing.ID},
	}}, nil).Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (disabling the only usable auth of an MCP consumer)", err)
	}
}

func TestUpdater_Update_AllowsDisablingMCPAuthWithUsableSibling(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	sibling := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*domain.Auth{existing, sibling}, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		return a.ID == existing.ID && !a.Enabled
	})).Return(nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return([]*consumerdomain.Consumer{{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Slug:        "mcp-inline",
		Type:        consumerdomain.TypeMCP,
		RoutingMode: consumerdomain.RoutingModeInline,
		AuthIDs:     []ids.AuthID{existing.ID, sibling.ID},
	}}, nil).Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	}); err != nil {
		t.Fatalf("expected disabling one of two usable MCP auths to be allowed, got %v", err)
	}
}
