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

package registry_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

type authLookupStub map[ids.AuthID]*authdomain.Auth

func (s authLookupStub) FindByID(_ context.Context, id ids.AuthID) (*authdomain.Auth, error) {
	if a, ok := s[id]; ok {
		return a, nil
	}
	return nil, authdomain.ErrNotFound
}

func entraIdentity(gatewayID ids.GatewayID, enabled bool, secret string) *authdomain.Auth {
	return &authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gatewayID,
		Type:      authdomain.TypeOAuth2,
		Enabled:   enabled,
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: "https://login.microsoftonline.com/tid/v2.0", ClientID: "gw-app", ClientSecret: secret,
		}},
	}
}

func sessionModeIdentity(gatewayID ids.GatewayID) *authdomain.Auth {
	a := entraIdentity(gatewayID, true, "s3cret")
	a.Config.OAuth2.SessionMode = true
	return a
}

func sessionModeExchangeOnlyIdentity(gatewayID ids.GatewayID) *authdomain.Auth {
	a := entraIdentity(gatewayID, true, "")
	a.Config.OAuth2.SessionMode = true
	a.Config.OAuth2.ClientID = ""
	a.Config.OAuth2.ExchangeClientID = "exchange-app"
	a.Config.OAuth2.ExchangeClientSecret = "exchange-s3cret"
	return a
}

func tokenExchangeTarget(identityID string) *domain.MCPTarget {
	return &domain.MCPTarget{
		URL: "https://agentcore.example.com/mcp",
		Auth: &domain.MCPAuth{
			Mode: domain.MCPAuthModeExchange, Pattern: domain.ExchangeTokenExchange,
			Audience: "https://up.example.com", IdentityID: identityID,
		},
	}
}

func oboTarget(identityID string) *domain.MCPTarget {
	return &domain.MCPTarget{
		URL: "https://agentcore.example.com/mcp",
		Auth: &domain.MCPAuth{
			Mode: domain.MCPAuthModeExchange, Pattern: domain.ExchangeOBO,
			Scope: "api://up/.default", IdentityID: identityID,
		},
	}
}

func TestCreator_Create_ExchangeIdentity(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	ready := entraIdentity(gwID, true, "s3cret")
	disabled := entraIdentity(gwID, false, "s3cret")
	noSecret := entraIdentity(gwID, true, "")
	otherGateway := entraIdentity(ids.New[ids.GatewayKind](), true, "s3cret")
	sessionMode := sessionModeIdentity(gwID)
	passThrough := entraIdentity(gwID, true, "s3cret")
	sessionModeNoLogin := sessionModeExchangeOnlyIdentity(gwID)
	mtls := &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gwID, Type: authdomain.TypeMTLS, Enabled: true}
	lookup := authLookupStub{
		ready.ID: ready, disabled.ID: disabled, noSecret.ID: noSecret, otherGateway.ID: otherGateway, mtls.ID: mtls,
		sessionMode.ID: sessionMode, passThrough.ID: passThrough, sessionModeNoLogin.ID: sessionModeNoLogin,
	}

	tests := []struct {
		name     string
		identity string
		target   func(string) *domain.MCPTarget
		lookup   appregistry.AuthLookup
		wantErr  bool
		wantMsg  []string
	}{
		{name: "enabled oauth2 identity with credentials", identity: ready.ID.String(), lookup: lookup},
		{name: "unknown identity", identity: ids.New[ids.AuthKind]().String(), lookup: lookup, wantErr: true},
		{name: "identity of another gateway", identity: otherGateway.ID.String(), lookup: lookup, wantErr: true},
		{name: "disabled identity", identity: disabled.ID.String(), lookup: lookup, wantErr: true},
		{name: "identity without client secret", identity: noSecret.ID.String(), lookup: lookup, wantErr: true},
		{name: "non oauth2 identity", identity: mtls.ID.String(), lookup: lookup, wantErr: true},
		{name: "no lookup wired", identity: ready.ID.String(), wantErr: true},
		{name: "upper-case spelling of a usable identity", identity: strings.ToUpper(ready.ID.String()), lookup: lookup},
		{
			name: "session-mode login identity", identity: sessionMode.ID.String(), lookup: lookup, wantErr: true,
			wantMsg: []string{sessionMode.ID.String(), "turn session mode off"},
		},
		{
			name: "session-mode login identity for token exchange", identity: sessionMode.ID.String(),
			target: tokenExchangeTarget, lookup: lookup, wantErr: true,
			wantMsg: []string{"turn session mode off"},
		},
		{name: "pass-through login identity", identity: passThrough.ID.String(), lookup: lookup},
		{name: "session-mode identity without a login client", identity: sessionModeNoLogin.ID.String(), lookup: lookup},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			var opts []appregistry.Option
			if tc.lookup != nil {
				opts = append(opts, appregistry.WithAuthLookup(tc.lookup))
			}
			if !tc.wantErr {
				repo.EXPECT().Save(mock.Anything, mock.MatchedBy(func(r *domain.Registry) bool {
					return r.MCPTarget.Auth.IdentityID == strings.ToLower(tc.identity)
				})).Return(nil).Once()
			}
			creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, nil, opts...)
			target := oboTarget
			if tc.target != nil {
				target = tc.target
			}

			_, err := creator.Create(context.Background(), appregistry.CreateInput{
				GatewayID: gwID, Name: "agentcore", Type: domain.TypeMCP, MCPTarget: target(tc.identity),
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Create() = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, domain.ErrInvalidMCPTarget) {
				t.Fatalf("Create() = %v, want ErrInvalidMCPTarget", err)
			}
			for _, part := range tc.wantMsg {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("Create() = %v, want the message to contain %q", err, part)
				}
			}
		})
	}
}

func TestUpdater_Update_ExchangeIdentity(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	ready := entraIdentity(gwID, true, "s3cret")
	gone := ids.New[ids.AuthKind]().String()

	stored := func() *domain.Registry {
		r, err := domain.NewMCPRegistry(gwID, "agentcore", "", oboTarget(gone))
		if err != nil {
			t.Fatalf("NewMCPRegistry: %v", err)
		}
		return r
	}

	t.Run("accepts an echoed stored auth whose identity is gone", func(t *testing.T) {
		t.Parallel()
		existing := stored()
		repo := repomocks.NewRepository(t)
		repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
		repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()
		publisher := cachemocks.NewEventPublisher(t)
		publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Maybe()
		updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
			appregistry.WithAuthLookup(authLookupStub{ready.ID: ready}))

		name := "renamed"
		_, err := updater.Update(context.Background(), appregistry.UpdateInput{ID: existing.ID, Name: &name, MCPTarget: oboTarget(gone)})
		if err != nil {
			t.Fatalf("Update() = %v, want nil", err)
		}
	})

	t.Run("refuses re-pinning to an identity that is unknown", func(t *testing.T) {
		t.Parallel()
		existing := stored()
		repo := repomocks.NewRepository(t)
		repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
		updater := appregistry.NewUpdater(repo, newCacheManager(), nil, newTestLogger(), nil, nil,
			appregistry.WithAuthLookup(authLookupStub{ready.ID: ready}))

		_, err := updater.Update(context.Background(), appregistry.UpdateInput{
			ID: existing.ID, MCPTarget: oboTarget(ids.New[ids.AuthKind]().String()),
		})
		if !errors.Is(err, domain.ErrInvalidMCPTarget) {
			t.Fatalf("Update() = %v, want ErrInvalidMCPTarget", err)
		}
	})

	t.Run("accepts an echoed pin whose identity turned session mode on", func(t *testing.T) {
		t.Parallel()
		sessionMode := sessionModeIdentity(gwID)
		existing, err := domain.NewMCPRegistry(gwID, "agentcore", "", oboTarget(sessionMode.ID.String()))
		if err != nil {
			t.Fatalf("NewMCPRegistry: %v", err)
		}
		repo := repomocks.NewRepository(t)
		repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
		repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()
		publisher := cachemocks.NewEventPublisher(t)
		publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Maybe()
		updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
			appregistry.WithAuthLookup(authLookupStub{sessionMode.ID: sessionMode}))

		name := "renamed"
		_, err = updater.Update(context.Background(), appregistry.UpdateInput{
			ID: existing.ID, Name: &name, MCPTarget: oboTarget(strings.ToUpper(sessionMode.ID.String())),
		})
		if err != nil {
			t.Fatalf("Update() = %v, want nil", err)
		}
	})

	t.Run("refuses re-pinning to a session-mode identity", func(t *testing.T) {
		t.Parallel()
		existing, err := domain.NewMCPRegistry(gwID, "agentcore", "", oboTarget(ready.ID.String()))
		if err != nil {
			t.Fatalf("NewMCPRegistry: %v", err)
		}
		sessionMode := sessionModeIdentity(gwID)
		repo := repomocks.NewRepository(t)
		repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
		updater := appregistry.NewUpdater(repo, newCacheManager(), nil, newTestLogger(), nil, nil,
			appregistry.WithAuthLookup(authLookupStub{ready.ID: ready, sessionMode.ID: sessionMode}))

		_, err = updater.Update(context.Background(), appregistry.UpdateInput{
			ID: existing.ID, MCPTarget: oboTarget(sessionMode.ID.String()),
		})
		if !errors.Is(err, domain.ErrInvalidMCPTarget) {
			t.Fatalf("Update() = %v, want ErrInvalidMCPTarget", err)
		}
	})

	t.Run("keeps unrelated edits possible when the stored identity is gone", func(t *testing.T) {
		t.Parallel()
		existing := stored()
		repo := repomocks.NewRepository(t)
		repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
		repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()
		publisher := cachemocks.NewEventPublisher(t)
		publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Maybe()
		updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil,
			appregistry.WithAuthLookup(authLookupStub{ready.ID: ready}))

		name := "renamed"
		_, err := updater.Update(context.Background(), appregistry.UpdateInput{
			ID: existing.ID, Name: &name, MCPTarget: &domain.MCPTarget{URL: "https://agentcore.example.com/mcp"},
		})
		if err != nil {
			t.Fatalf("Update() = %v, want nil", err)
		}
	})
}

func TestCreator_Create_AcceptsAnExchangeOnlyIdentity(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	identity := &authdomain.Auth{
		ID: ids.New[ids.AuthKind](), GatewayID: gwID, Type: authdomain.TypeOAuth2, Enabled: true,
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: "https://login.microsoftonline.com/tid/v2.0", ExchangeClientID: "gw-app", ExchangeClientSecret: "s3cret",
		}},
	}
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAuthLookup(authLookupStub{identity.ID: identity}))

	if _, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: gwID, Name: "agentcore", Type: domain.TypeMCP, MCPTarget: oboTarget(identity.ID.String()),
	}); err != nil {
		t.Fatalf("Create() = %v", err)
	}
}
