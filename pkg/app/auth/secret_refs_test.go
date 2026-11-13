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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// fixedValues resolves every use to "resolved", recording the sources.
type fixedValues struct{ sources []string }

func (f *fixedValues) Values(_ context.Context, _ ids.GatewayID, source string, uses []appsecretref.Use) []appsecretref.Resolved {
	f.sources = append(f.sources, source)
	out := make([]appsecretref.Resolved, len(uses))
	for i := range uses {
		out[i] = appsecretref.Resolved{Value: "resolved"}
	}
	return out
}

func TestCredentialFinderResolvesIdentityProviderSecrets(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	stored := &domain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: domain.TypeOAuth2, Config: domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer: "https://idp.example", ClientID: "c", ClientSecret: "secret://vault/idp#c",
	}}}
	repo := authmocks.NewRepository(t)
	repo.EXPECT().ListEnabledByGatewayAndType(mock.Anything, gw, domain.TypeOAuth2).Return([]*domain.Auth{stored}, nil).Once()
	values := &fixedValues{}
	finder := appauth.NewCredentialFinder(repo, newCacheManager(), newTestLogger(), nil, appauth.WithSecretValues(values))

	for range 2 {
		got, err := finder.OAuth2AuthsForGateway(context.Background(), gw)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "resolved", got[0].Config.OAuth2.ClientSecret)
	}
	assert.Equal(t, "secret://vault/idp#c", stored.Config.OAuth2.ClientSecret, "the stored auth is never modified")
	assert.Equal(t, []string{appsecretref.SourceAuthCredentials}, values.sources, "the resolved list is cached")
}
