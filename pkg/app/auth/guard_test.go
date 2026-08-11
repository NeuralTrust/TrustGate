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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func enabledOAuth2(t *testing.T, gatewayID ids.GatewayID, issuer string, audiences ...string) *domain.Auth {
	t.Helper()
	a, err := domain.NewAuth(gatewayID, "idp", domain.TypeOAuth2, true, domain.Config{
		OAuth2: &domain.OAuth2Config{
			Issuer:    issuer,
			JWKSURL:   "https://idp.example.com/jwks",
			Audiences: audiences,
		},
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	return a
}

func createOAuth2(
	t *testing.T,
	repo *repomocks.Repository,
	publisher *cachemocks.EventPublisher,
	gatewayID ids.GatewayID,
	audiences ...string,
) error {
	t.Helper()
	creator := appauth.NewCreator(repo, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := creator.Create(context.Background(), appauth.CreateInput{
		GatewayID: gatewayID,
		Name:      "new-idp",
		Type:      domain.TypeOAuth2,
		Enabled:   true,
		Config: domain.Config{OAuth2: &domain.OAuth2Config{
			Issuer:    "https://idp.example.com",
			JWKSURL:   "https://idp.example.com/jwks",
			Audiences: audiences,
		}},
	})
	return err
}

func TestCreator_RejectsDuplicateIssuerAudience(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, gatewayID, "https://idp.example.com", "api://abc")}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	err := createOAuth2(t, repo, publisher, gatewayID, "api://abc")
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestCreator_RejectsAudienceEquivalence(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, gatewayID, "https://idp.example.com", "api://abc")}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	err := createOAuth2(t, repo, publisher, gatewayID, "abc")
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestCreator_AllowsSameIssuerAudienceOnAnotherGateway(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	other := enabledOAuth2(t, ids.New[ids.GatewayKind](), "https://idp.example.com", "api://abc")
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{other}, nil).Once()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	gatewayID := ids.New[ids.GatewayKind]()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}).
		Return(nil).
		Once()

	if err := createOAuth2(t, repo, publisher, gatewayID, "api://abc"); err != nil {
		t.Fatalf("expected same issuer+audience on a different gateway to be allowed, got %v", err)
	}
}

func TestCreator_RejectsWildcardAudienceOverlap(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	legacyNoAudiences := &domain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gatewayID,
		Name:      "idp",
		Type:      domain.TypeOAuth2,
		Enabled:   true,
		Config: domain.Config{OAuth2: &domain.OAuth2Config{
			Issuer:  "https://idp.example.com",
			JWKSURL: "https://idp.example.com/jwks",
		}},
	}
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{legacyNoAudiences}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	err := createOAuth2(t, repo, publisher, gatewayID, "api://abc")
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestCreator_AllowsSameIssuerDistinctAudience(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, gatewayID, "https://idp.example.com", "api://tenant-a")}, nil).Once()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}).
		Return(nil).
		Once()

	if err := createOAuth2(t, repo, publisher, gatewayID, "api://tenant-b"); err != nil {
		t.Fatalf("expected same issuer with distinct audience to be allowed, got %v", err)
	}
}

func TestUpdater_RejectsEnablingConflictingAuth(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	existing := enabledOAuth2(t, gatewayID, "https://idp.example.com", "api://abc")
	existing.Enabled = false
	other := enabledOAuth2(t, gatewayID, "https://idp.example.com", "abc")

	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{other}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(true),
	})
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_AllowsUpdatingSameEntry(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := enabledOAuth2(t, ids.New[ids.GatewayKind](), "https://idp.example.com", "api://abc")

	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{existing}, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:   existing.ID,
		Name: ptr("renamed"),
	}); err != nil {
		t.Fatalf("expected self-update to pass the guardrail, got %v", err)
	}
}
