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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// resolvingStore stands in for the materializer: it resolves every A2A auth
// value to value, or marks it unavailable when value is empty.
type resolvingStore struct{ value string }

func (s resolvingStore) Registries(_ context.Context, _ ids.GatewayID, byID map[ids.RegistryID]*domain.Registry) map[ids.RegistryID]*domain.Registry {
	out := map[ids.RegistryID]*domain.Registry{}
	for id, r := range byID {
		c := *r
		t := *r.A2ATarget
		a := *t.Auth
		a.Value = s.value
		t.Auth = &a
		c.A2ATarget = &t
		if s.value == "" {
			c.MarkCredentialUnavailable()
		}
		out[id] = &c
	}
	return out
}

// acceptRefs and refuseRefs stand in for the write-time validator.
type acceptRefs struct{}

func (acceptRefs) ValidateRegistry(context.Context, *domain.Registry, []appsecretref.Use) (func(), error) {
	return func() {}, nil
}

type refuseRefs struct{}

func (refuseRefs) ValidateRegistry(context.Context, *domain.Registry, []appsecretref.Use) (func(), error) {
	return nil, refdomain.ErrMissingScope
}

func referencedCardTarget(cardAuth domain.A2ACardAuth) *domain.A2ATarget {
	return &domain.A2ATarget{
		CardURL:  "https://travel.example.com",
		CardAuth: cardAuth,
		Auth:     &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "X-Key", Value: "secret://vault/agents/travel#key"},
	}
}

func previewWith(t *testing.T, fetcher appregistry.CardFetcher, creds appregistry.CardCredentials, opts ...appregistry.Option) appregistry.PreviewAgentCard {
	t.Helper()
	return appregistry.NewPreviewAgentCard(append([]appregistry.Option{appregistry.WithAgentCards(fetcher, creds)}, opts...)...)
}

func TestCardReadWithAReferenceAndNoStoresIsRefused(t *testing.T) {
	t.Parallel()
	preview := previewWith(t, appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t))
	_, err := preview.Preview(context.Background(), ids.New[ids.GatewayKind](), referencedCardTarget(domain.A2ACardAuthSame))
	require.ErrorIs(t, err, domain.ErrSecretUnavailable, "the reference must never be sent as the card credential")
}

func TestCardReadWithAnUnresolvedReferenceIsRefused(t *testing.T) {
	t.Parallel()
	preview := previewWith(t, appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t), appregistry.WithCardSecrets(resolvingStore{}, acceptRefs{}))
	_, err := preview.Preview(context.Background(), ids.New[ids.GatewayKind](), referencedCardTarget(domain.A2ACardAuthSame))
	require.ErrorIs(t, err, domain.ErrSecretUnavailable)
}

func TestCardReadUsesTheResolvedCredential(t *testing.T) {
	t.Parallel()
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Resolve(mock.Anything, "https://travel.example.com", mock.Anything).
		Return(&appregistry.FetchedCard{URL: pinnedCardURL, Card: []byte(`{"name":"Travel"}`)}, nil).Once()
	creds := appmocks.NewCardCredentials(t)
	creds.EXPECT().Authorizer(mock.Anything, mock.MatchedBy(func(tg *domain.A2ATarget) bool {
		return tg.Auth.Value == "resolved-key"
	})).Return(nil, nil).Once()
	preview := previewWith(t, fetcher, creds, appregistry.WithCardSecrets(resolvingStore{value: "resolved-key"}, acceptRefs{}))

	target := referencedCardTarget(domain.A2ACardAuthSame)
	_, err := preview.Preview(context.Background(), ids.New[ids.GatewayKind](), target)
	require.NoError(t, err)
	assert.Equal(t, "secret://vault/agents/travel#key", target.Auth.Value, "the saved target keeps the reference")
}

func TestAnonymousCardReadNeedsNoResolution(t *testing.T) {
	t.Parallel()
	fetcher := appmocks.NewCardFetcher(t)
	fetcher.EXPECT().Resolve(mock.Anything, mock.Anything, mock.Anything).
		Return(&appregistry.FetchedCard{URL: pinnedCardURL, Card: []byte(`{"name":"Travel"}`)}, nil).Once()
	preview := previewWith(t, fetcher, anonymousCards(t))
	_, err := preview.Preview(context.Background(), ids.New[ids.GatewayKind](), referencedCardTarget(""))
	require.NoError(t, err, "an anonymous card read never sends the auth, so its reference needs no store")
}

func TestCardReadWithAReferenceTheCallerMayNotUseIsRefused(t *testing.T) {
	t.Parallel()
	preview := previewWith(t, appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t),
		appregistry.WithCardSecrets(resolvingStore{value: "resolved-key"}, refuseRefs{}))
	target := referencedCardTarget(domain.A2ACardAuthSame)
	target.CardURL = "https://attacker.example"
	_, err := preview.Preview(context.Background(), ids.New[ids.GatewayKind](), target)
	require.ErrorIs(t, err, refdomain.ErrMissingScope, "the value must not be read, let alone sent to a caller-chosen host")
}

func TestCreateWithARefusedReferenceNeverReadsTheCard(t *testing.T) {
	t.Parallel()
	creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithAgentCards(appmocks.NewCardFetcher(t), appmocks.NewCardCredentials(t)),
		appregistry.WithCardSecrets(resolvingStore{value: "resolved-key"}, refuseRefs{}))
	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "t", Type: domain.TypeA2A, A2ATarget: referencedCardTarget(domain.A2ACardAuthSame),
	})
	require.ErrorIs(t, err, refdomain.ErrMissingScope)
}
