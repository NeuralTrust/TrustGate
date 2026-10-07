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
	"slices"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
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

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
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

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
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

func existingOAuth2AuthWithLoginScopes(t *testing.T, gwID ids.GatewayID) *domain.Auth {
	t.Helper()
	cfg := oauth2Config("real-secret")
	cfg.OAuth2.LoginScopes = []string{"api://gw/mcp.access", "offline_access"}
	a, err := domain.NewAuth(gwID, "oauth-cred", domain.TypeOAuth2, true, cfg)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	return a
}

func TestUpdater_Update_StatusToggle_KeepsLoginScopes(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2AuthWithLoginScopes(t, gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	var persisted []string
	repo.EXPECT().Update(mock.Anything, mock.Anything).
		Run(func(_ context.Context, a *domain.Auth) { persisted = slices.Clone(a.Config.OAuth2.LoginScopes) }).
		Return(nil).
		Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return(nil, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil, nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if want := []string{"api://gw/mcp.access", "offline_access"}; !slices.Equal(persisted, want) {
		t.Fatalf("persisted LoginScopes = %q, want %q", persisted, want)
	}
}

func TestUpdater_Update_ConfigWithoutLoginScopes_ClearsThem(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2AuthWithLoginScopes(t, gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).Return(nil, nil).Once()
	persisted := []string{"sentinel"}
	repo.EXPECT().Update(mock.Anything, mock.Anything).
		Run(func(_ context.Context, a *domain.Auth) { persisted = slices.Clone(a.Config.OAuth2.LoginScopes) }).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:     existing.ID,
		Config: ptr(oauth2Config("***")),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if len(persisted) != 0 {
		t.Fatalf("persisted LoginScopes = %q, want none", persisted)
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

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
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

func TestUpdater_Update_StatusToggleWithMaskedEchoKeepsBothSecrets(t *testing.T) {
	t.Parallel()
	const (
		loginSecret    = "real-login-secret"
		exchangeSecret = "real-exchange-secret"
	)
	withSecrets := func(login, exchange string) domain.Config {
		cfg := oauth2Config(login)
		cfg.OAuth2.ExchangeClientID = "exchange-456"
		cfg.OAuth2.ExchangeClientSecret = exchange
		return cfg
	}
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing, err := domain.NewAuth(gwID, "oauth-cred", domain.TypeOAuth2, false, withSecrets(loginSecret, exchangeSecret))
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).Return(nil, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			o := a.Config.OAuth2
			return a.Enabled && o != nil && o.ClientSecret == loginSecret && o.ExchangeClientSecret == exchangeSecret
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(true),
		Config:  ptr(withSecrets(secret.Mask(loginSecret), secret.Mask(exchangeSecret))),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_GatewayMismatch(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingAuth(ids.New[ids.GatewayKind]())
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
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
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:     id,
		Name:   ptr("x"),
		Type:   ptr(domain.TypeAPIKey),
		Config: ptr(validConfig()),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func oidcConfig() domain.Config {
	return domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer:    "https://idp.example.com",
		Audiences: []string{"api://gateway"},
		JWKSURL:   "https://idp.example.com/jwks",
	}}
}

// Setting the deprecated alias on an auth an MCP consumer references no longer
// breaks that consumer: the alias canonicalizes to oauth2, which is the type
// MCP takes. Before unification the same request was a 409, so this pins the
// behaviour change rather than leaving it to the type guard.
func TestUpdater_Update_AliasedTypeKeepsMCPConsumerValid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return([]*consumerdomain.Consumer{{
		ID:   ids.New[ids.ConsumerKind](),
		Slug: "mcp-cons",
		Type: consumerdomain.TypeMCP,
	}}, nil).Maybe()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).Return(nil, nil).Once()

	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		return a.Type == domain.TypeOAuth2
	})).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil, nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeOIDC),
		Config:    ptr(oidcConfig()),
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Sending the deprecated alias for an auth that is already oauth2 is accepted
// and stores the canonical type. It is no longer a type change at all, so the
// reference guard does not run — that path is covered by
// TestUpdater_Update_AliasedTypeKeepsMCPConsumerValid.
func TestUpdater_Update_AliasedTypeIsCanonicalizedOnWrite(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		// Canonicalized on the way in: no row is ever written under the alias.
		return a.Type == domain.TypeOAuth2
	})).Return(nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, existing.ID).Return(nil, nil).Maybe()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).Return(nil, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil, nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeOIDC),
		Config:    ptr(oidcConfig()),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
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
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Slug:      "mcp-inline",
		Type:      consumerdomain.TypeMCP,
		AuthIDs:   []ids.AuthID{existing.ID},
	}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil, nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (disabling the only usable auth of an MCP consumer)", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
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
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Slug:      "mcp-inline",
		Type:      consumerdomain.TypeMCP,
		AuthIDs:   []ids.AuthID{existing.ID, sibling.ID},
	}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil, nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	}); err != nil {
		t.Fatalf("expected disabling one of two usable MCP auths to be allowed, got %v", err)
	}
}

func TestUpdater_Update_RefusesAnOwnedKey(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing, err := domain.NewAPIKeyAuth(gwID, "personal-alice", true, nil)
	if err != nil {
		t.Fatalf("NewAPIKeyAuth: %v", err)
	}
	existing.OwnerID = "alice"
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil, nil)
	_, err = updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
		Enabled:   ptr(false),
	})
	if !errors.Is(err, domain.ErrOwnedKey) {
		t.Fatalf("err = %v, want ErrOwnedKey", err)
	}
	if existing.Name != "personal-alice" || !existing.Enabled {
		t.Fatalf("owned key was modified: %+v", existing)
	}
}

func TestUpdater_Update_ReadsTheInjectedClock(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	clock := time.Date(2031, time.January, 1, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		expiresAt time.Time
		wantErr   error
	}{
		"expiry after the injected now":  {expiresAt: clock.Add(time.Hour)},
		"expiry before the injected now": {expiresAt: clock.Add(-time.Hour), wantErr: domain.ErrExpiryInThePast},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			existing, err := domain.NewAPIKeyAuth(gwID, "client-key", true, nil)
			if err != nil {
				t.Fatalf("NewAPIKeyAuth: %v", err)
			}
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			if tc.wantErr == nil {
				repo.EXPECT().Update(mock.Anything, existing).Return(nil).Once()
				publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()
			}
			updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil,
				func() time.Time { return clock })

			updated, err := updater.Update(context.Background(), appauth.UpdateInput{
				ID: existing.ID, GatewayID: gwID, Expiry: &appauth.ExpiryChange{At: &tc.expiresAt},
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Update() = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && !updated.UpdatedAt.Equal(clock) {
				t.Fatalf("UpdatedAt = %v, want the injected clock %v", updated.UpdatedAt, clock)
			}
		})
	}
}
